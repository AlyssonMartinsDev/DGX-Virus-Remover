using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TJRemover
{
    public class MainForm : Form
    {
        readonly Engine engine = new Engine();
        readonly List<Finding> uiFindings = new List<Finding>();
        readonly System.Windows.Forms.Timer uiTimer = new System.Windows.Forms.Timer();
        CancellationTokenSource cts;
        Task task;
        readonly Stopwatch sw = new Stopwatch();
        bool busy, closeRequested, suppressCheck, cancelled;
        string mode = "";
        int shownPhaseVersion = -1, activeTab;
        List<Finding> lastSelection = new List<Finding>();
        string[] stepNames = new string[0];

        Label lblStatus, lblPhase, lblPercent, lblDone, lblRemain, lblTime, lblFiles, lblCurrent, lblEmpty;
        FlatBar bar;
        StatCard cProc, cMal, cInf, cReg, cSvc, cWarn;
        ListView lv;
        RichTextBox rtb;
        TextBox txtDetail;
        Panel pageFindings, pageLog;
        Button tabFind, tabLog;
        FlowLayoutPanel stepsList;
        readonly List<Label> stepLabels = new List<Label>();
        ComboBox cbMode;
        CheckBox chkPersist, chkUsb, chkOffline, chkDefender, chkVaccine;
        Button btnScan, btnClean, btnCancel, btnUndo, btnQuar, btnReport, btnAllow, btnProtect;
        string customFolder;
        int lastMode = 1;
        static readonly string[] ModeNames = { "Rápida (sistema, sem varrer arquivos)", "Completa (programas e usuários)", "Disco inteiro (mais lenta)", "Pasta escolhida…" };
        // vigia de pendrive
        readonly System.Windows.Forms.Timer usbTimer = new System.Windows.Forms.Timer();
        HashSet<string> knownDrives = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly Queue<string> pendingUsb = new Queue<string>();
        readonly Font fTitle, fBold, fBoldSmall, fSmall, fBig, fMono, fPhase;

        public bool IsBusy { get { return busy; } }

        public MainForm()
        {
            fTitle = new Font("Segoe UI Semibold", 16f);
            fBold = new Font("Segoe UI Semibold", 10f);
            fBoldSmall = new Font("Segoe UI Semibold", 9f);
            fSmall = new Font("Segoe UI", 9f);
            fBig = new Font("Segoe UI Semibold", 24f);
            fMono = new Font("Consolas", 9.5f);
            fPhase = new Font("Segoe UI Semibold", 12.5f);

            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = Program.AppName;
            Size = new Size(1220, 800);
            MinimumSize = new Size(1040, 680);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = C.Bg;
            ForeColor = C.Text;
            Font = new Font("Segoe UI", 9.5f);
            DoubleBuffered = true;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            Controls.Add(BuildBody());
            Controls.Add(BuildBottom());
            Controls.Add(BuildCards());
            Controls.Add(BuildProgress());
            Controls.Add(BuildHeader());
            ResumeLayout(false);
            PerformLayout();

            uiTimer.Interval = 80;
            uiTimer.Tick += UiTick;

            SetBusy(false);
            SetStatus("Pronto para escanear", C.Dim);
            ResetProgress();
            ShowPlan();
            UpdateEmpty();
            engine.Log(Program.AppName + " pronto. Clique em \"Escanear\" para começar — nada é alterado até você clicar em \"Remover selecionados\".", LogLevel.Title);
            DrainLogs();
        }

        // =====================================================================
        // construção da interface
        // =====================================================================
        Control BuildHeader()
        {
            var p = new Panel { Dock = DockStyle.Top, Height = 74, BackColor = C.Panel };
            var logo = new DgxLogo { Location = new Point(18, 11), Size = new Size(52, 52) };
            var t = new Label { Text = Program.AppName, Font = fTitle, ForeColor = C.Text, AutoSize = true, Location = new Point(80, 11) };
            var st = new Label { Text = Engine.V + " / Mofksys  ·  Synaptics  ·  Grenam  ·  Desinfecção  ·  Quarentena  ·  Vacina", Font = fSmall, ForeColor = C.Dim, AutoSize = true, Location = new Point(83, 44) };
            lblStatus = new Label { Dock = DockStyle.Right, Width = 420, TextAlign = ContentAlignment.MiddleRight, Font = new Font("Segoe UI Semibold", 12.5f), Padding = new Padding(0, 0, 24, 0) };
            var line = new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = C.Border };
            p.Controls.Add(lblStatus);
            p.Controls.Add(line);
            p.Controls.Add(logo);
            p.Controls.Add(t);
            p.Controls.Add(st);
            return p;
        }

        static Label MkLabel(Color c, Font f, ContentAlignment a)
        {
            return new Label { Dock = DockStyle.Fill, ForeColor = c, Font = f, TextAlign = a, AutoEllipsis = true, Margin = Padding.Empty };
        }

        Control BuildProgress()
        {
            var p = new Panel { Dock = DockStyle.Top, Height = 150, Padding = new Padding(22, 12, 22, 4), BackColor = C.Bg };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, BackColor = C.Bg, Margin = Padding.Empty };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            t.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
            t.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
            t.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
            t.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));

            var r0 = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty };
            lblPercent = new Label { Dock = DockStyle.Right, Width = 150, Font = fBig, ForeColor = C.Text, TextAlign = ContentAlignment.MiddleRight };
            lblPhase = new Label { Dock = DockStyle.Fill, Font = fPhase, ForeColor = C.Text, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
            r0.Controls.Add(lblPhase);
            r0.Controls.Add(lblPercent);

            bar = new FlatBar { Dock = DockStyle.Fill, Margin = new Padding(0, 3, 0, 3) };

            var r2 = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, Margin = Padding.Empty };
            r2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 17));
            r2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 15));
            r2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 36));
            r2.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
            r2.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            lblDone = MkLabel(C.Green, fBold, ContentAlignment.MiddleLeft);
            lblRemain = MkLabel(C.Orange, fBold, ContentAlignment.MiddleLeft);
            lblTime = MkLabel(C.Dim, fSmall, ContentAlignment.MiddleLeft);
            lblFiles = MkLabel(C.Dim, fSmall, ContentAlignment.MiddleRight);
            r2.Controls.Add(lblDone, 0, 0);
            r2.Controls.Add(lblRemain, 1, 0);
            r2.Controls.Add(lblTime, 2, 0);
            r2.Controls.Add(lblFiles, 3, 0);

            lblCurrent = MkLabel(C.Dim, fSmall, ContentAlignment.MiddleLeft);

            t.Controls.Add(r0, 0, 0);
            t.Controls.Add(bar, 0, 1);
            t.Controls.Add(r2, 0, 2);
            t.Controls.Add(lblCurrent, 0, 3);
            p.Controls.Add(t);
            return p;
        }

        Control BuildCards()
        {
            var p = new Panel { Dock = DockStyle.Top, Height = 98, Padding = new Padding(18, 2, 18, 10) };
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 6, RowCount = 1, Margin = Padding.Empty };
            for (int i = 0; i < 6; i++) t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 6));
            t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            cProc = new StatCard("Processos ativos", C.Red);
            cMal = new StatCard("Arquivos do vírus", C.Red);
            cInf = new StatCard("Executáveis infectados", C.Orange);
            cReg = new StatCard("Inicialização / registro", C.Yellow);
            cSvc = new StatCard("Serviços e tarefas", C.Yellow);
            cWarn = new StatCard("Avisos", C.Accent);
            var cards = new[] { cProc, cMal, cInf, cReg, cSvc, cWarn };
            for (int i = 0; i < cards.Length; i++)
            {
                cards[i].Dock = DockStyle.Fill;
                cards[i].Margin = new Padding(4);
                t.Controls.Add(cards[i], i, 0);
            }
            p.Controls.Add(t);
            return p;
        }

        Button MakeTab(string text, int idx, int width)
        {
            var b = new Button
            {
                Text = text, Dock = DockStyle.Left, Width = width, FlatStyle = FlatStyle.Flat, Font = fBold,
                ForeColor = C.Dim, BackColor = C.Panel, Cursor = Cursors.Hand, TabStop = false
            };
            b.FlatAppearance.BorderSize = 0;
            b.FlatAppearance.MouseOverBackColor = C.Card;
            b.FlatAppearance.MouseDownBackColor = C.Card;
            b.Click += (s, e) => SelectTab(idx);
            b.Paint += (s, e) =>
            {
                if (activeTab != idx) return;
                using (var br = new SolidBrush(C.Accent)) e.Graphics.FillRectangle(br, 12, b.Height - 3, b.Width - 24, 3);
            };
            return b;
        }

        Control BuildBody()
        {
            var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(22, 2, 22, 12) };

            // --- direita: abas
            var right = new Panel { Dock = DockStyle.Fill, BackColor = C.Panel };
            var pages = new Panel { Dock = DockStyle.Fill };

            pageFindings = new Panel { Dock = DockStyle.Fill, BackColor = C.Panel };
            lv = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details, CheckBoxes = true, FullRowSelect = true, BorderStyle = BorderStyle.None,
                BackColor = C.Panel, ForeColor = C.Text, HideSelection = false, HeaderStyle = ColumnHeaderStyle.Nonclickable,
                OwnerDraw = true, MultiSelect = false, Font = new Font("Segoe UI", 9.5f)
            };
            typeof(Control).GetProperty("DoubleBuffered", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(lv, true, null);
            lv.Columns.Add("Tipo", 240);
            lv.Columns.Add("Gravidade", 80);
            lv.Columns.Add("Item", 430);
            lv.Columns.Add("Status", 215);
            lv.Columns.Add("Detalhe", 200);
            lv.DrawColumnHeader += (s, e) =>
            {
                using (var b = new SolidBrush(C.Card)) e.Graphics.FillRectangle(b, e.Bounds);
                TextRenderer.DrawText(e.Graphics, e.Header.Text, fBoldSmall, Rectangle.Inflate(e.Bounds, -8, 0), C.Dim,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
                using (var pen = new Pen(C.Border)) e.Graphics.DrawLine(pen, e.Bounds.Right - 1, e.Bounds.Top + 5, e.Bounds.Right - 1, e.Bounds.Bottom - 5);
            };
            lv.DrawItem += (s, e) => e.DrawDefault = true;
            lv.DrawSubItem += (s, e) => e.DrawDefault = true;
            lv.Resize += (s, e) => FitColumns();
            lv.ItemCheck += (s, e) =>
            {
                if (suppressCheck) return;
                var f = lv.Items[e.Index].Tag as Finding;
                if (busy || (f != null && f.Done)) e.NewValue = e.CurrentValue;
            };
            lv.ItemChecked += (s, e) =>
            {
                if (suppressCheck) return;
                var f = e.Item.Tag as Finding;
                if (f != null) f.Selected = e.Item.Checked;
                UpdateCleanButton();
            };
            lv.SelectedIndexChanged += (s, e) => ShowDetail();
            lv.ContextMenuStrip = BuildContextMenu();

            lblEmpty = new Label
            {
                Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, ForeColor = C.Dim, BackColor = C.Panel,
                Font = new Font("Segoe UI", 11f),
                Text = "Nenhum item ainda.\r\nClique em \"Escanear\" para procurar o vírus, os arquivos infectados\r\ne tudo o que ele deixou no registro, serviços e tarefas."
            };
            txtDetail = new TextBox
            {
                Dock = DockStyle.Bottom, Height = 112, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
                BackColor = C.Card, ForeColor = C.Text, BorderStyle = BorderStyle.None, Font = fMono, TabStop = false,
                Text = "Selecione um item para ver os detalhes."
            };
            var detailPad = new Panel { Dock = DockStyle.Bottom, Height = 112, Padding = new Padding(10, 6, 10, 6), BackColor = C.Card };
            detailPad.Controls.Add(txtDetail);
            txtDetail.Dock = DockStyle.Fill;
            // o aviso "nenhum item" fica POR CIMA da lista; a lista nunca é ocultada
            // (ListView oculto perde o estado das caixinhas)
            lv.Controls.Add(lblEmpty);
            pageFindings.Controls.Add(lv);
            pageFindings.Controls.Add(detailPad);

            pageLog = new Panel { Dock = DockStyle.Fill, Visible = false, Padding = new Padding(12, 8, 6, 8), BackColor = C.Panel };
            rtb = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = C.Panel, ForeColor = C.Text,
                Font = fMono, DetectUrls = false, WordWrap = false
            };
            pageLog.Controls.Add(rtb);

            pages.Controls.Add(pageFindings);
            pages.Controls.Add(pageLog);

            var tabs = new Panel { Dock = DockStyle.Top, Height = 42, BackColor = C.Panel };
            tabLog = MakeTab("Registro de atividades", 1, 210);
            tabFind = MakeTab("Ameaças encontradas", 0, 230);
            tabs.Controls.Add(tabLog);
            tabs.Controls.Add(tabFind);
            tabs.Paint += (s, e) => { using (var pen = new Pen(C.Border)) e.Graphics.DrawLine(pen, 0, tabs.Height - 1, tabs.Width, tabs.Height - 1); };

            right.Controls.Add(pages);
            right.Controls.Add(tabs);

            // --- esquerda: etapas
            var steps = new Panel { Dock = DockStyle.Left, Width = 262, BackColor = C.Panel, Padding = new Padding(16, 12, 8, 10) };
            var stTitle = new Label { Text = "ETAPAS", Dock = DockStyle.Top, Height = 30, ForeColor = C.Dim, Font = fBoldSmall };
            stepsList = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = false };
            stepsList.Resize += (s, e) => FitSteps();
            steps.Controls.Add(stepsList);
            steps.Controls.Add(stTitle);
            var gap = new Panel { Dock = DockStyle.Left, Width = 14 };

            body.Controls.Add(right);
            body.Controls.Add(gap);
            body.Controls.Add(steps);
            return body;
        }

        ContextMenuStrip BuildContextMenu()
        {
            var m = new ContextMenuStrip { BackColor = C.Card, ForeColor = C.Text, ShowImageMargin = false };
            m.Items.Add("Abrir local do arquivo", null, (s, e) =>
            {
                var f = SelectedFinding();
                string p = f == null ? null : (f.FilePath ?? f.TaskFile);
                if (p != null && File.Exists(p)) Process.Start("explorer.exe", "/select,\"" + p + "\"");
            });
            m.Items.Add("Copiar detalhes", null, (s, e) =>
            {
                var f = SelectedFinding();
                if (f != null) Clipboard.SetText(f.KindText + " | " + f.SeverityText + " | " + f.Status + "\r\n" + f.Title + "\r\n" + f.Detail);
            });
            m.Items.Add(new ToolStripSeparator());
            m.Items.Add("Permitir este item (não é vírus — não acusar mais)", null, (s, e) => AllowSelected(false));
            m.Items.Add("Permitir a pasta inteira deste arquivo", null, (s, e) => AllowSelected(true));
            m.Items.Add(new ToolStripSeparator());
            m.Items.Add("Marcar todos", null, (s, e) => SetAllChecked(true));
            m.Items.Add("Desmarcar todos", null, (s, e) => SetAllChecked(false));
            return m;
        }

        void AllowSelected(bool folder)
        {
            if (busy) return;
            var list = lv.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag as Finding).Where(f => f != null && !f.Done).ToList();
            if (list.Count == 0) return;
            var sb = new StringBuilder(folder ? "Permitir as pastas abaixo (tudo dentro delas deixa de ser acusado)?\r\n\r\n" : "Marcar como \"não é vírus\" e não acusar mais?\r\n\r\n");
            foreach (var f in list.Take(8)) sb.AppendLine("  •  " + (folder && f.FilePath != null ? Path.GetDirectoryName(f.FilePath) : f.Title));
            if (list.Count > 8) sb.AppendLine("  … e mais " + (list.Count - 8));
            sb.AppendLine().Append("Só faça isso se tiver certeza. Dá para desfazer em \"Permitidos\".");
            if (MessageBox.Show(this, sb.ToString(), "Permitir", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            string note = "permitido em " + DateTime.Now.ToString("dd/MM/yyyy HH:mm");
            foreach (var f in list)
            {
                if (f.RegKey != null && f.FilePath == null)
                    Allowlist.Add(AllowType.Registry, Allowlist.RegKey(f.RegRoot, f.RegKey, f.RegValue), f.Title + " — " + note);
                else
                {
                    string p = f.FilePath ?? f.TaskFile;
                    if (p == null) continue;
                    if (folder) Allowlist.Add(AllowType.Folder, Path.GetDirectoryName(p), note);
                    else
                    {
                        Allowlist.Add(AllowType.File, p, note);
                        string h = File.Exists(p) ? Engine.Sha256(p) : null;
                        if (h != null && f.Kind != FindingKind.HiddenFolder && f.Kind != FindingKind.Hosts) Allowlist.Add(AllowType.Hash, h, Path.GetFileName(p) + " — " + note);
                    }
                }
                f.Selected = false; f.Done = true; f.Status = "Permitido (não será acusado)";
                UpdateItem(f);
            }
            UpdateCleanButton();
            UpdateCards();
        }

        // ---------------------------------------------------------------- vigia de pendrive
        void ApplyUsbWatch()
        {
            bool on = Settings.Get("vigiarPendrive", "1") == "1";
            knownDrives = new HashSet<string>(CurrentRemovable(), StringComparer.OrdinalIgnoreCase);
            usbTimer.Interval = 2000;
            usbTimer.Tick -= UsbTick;
            if (on) { usbTimer.Tick += UsbTick; usbTimer.Start(); }
            else usbTimer.Stop();
        }

        static List<string> CurrentRemovable()
        {
            var l = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
                try { if (d.DriveType == DriveType.Removable && d.IsReady) l.Add(d.RootDirectory.FullName); } catch { }
            return l;
        }

        void UsbTick(object sender, EventArgs e)
        {
            var now = CurrentRemovable();
            foreach (var d in now)
                if (!knownDrives.Contains(d) && !pendingUsb.Contains(d)) pendingUsb.Enqueue(d);
            knownDrives = new HashSet<string>(now, StringComparer.OrdinalIgnoreCase);
            if (busy || pendingUsb.Count == 0) return;
            string drive = pendingUsb.Dequeue();
            if (!Directory.Exists(drive)) return;
            engine.Log("Pendrive conectado: " + drive + " — verificando antes de você abrir qualquer arquivo.", LogLevel.Title);
            var o = new ScanOptions
            {
                CustomFolder = drive, SystemChecks = false, Persistence = false, Offline = false, DeepScan = true,
                Removable = true, Vaccine = false, ModeName = "Pendrive " + drive
            };
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
            StartScanWith(o);
        }

        CheckBox MkChk(string text, bool on)
        {
            return new CheckBox { Text = text, Checked = on, AutoSize = true, ForeColor = C.Text, Margin = new Padding(0, 6, 22, 0), Cursor = Cursors.Hand };
        }

        Button MkBtn(string text, Color back, int width, bool primary)
        {
            var b = new Button
            {
                Text = text, Width = width, Height = 40, FlatStyle = FlatStyle.Flat, BackColor = back,
                ForeColor = primary ? Color.White : C.Text, Font = fBold, Cursor = Cursors.Hand, Margin = new Padding(0, 4, 10, 0)
            };
            b.FlatAppearance.BorderSize = primary ? 0 : 1;
            b.FlatAppearance.BorderColor = C.Border;
            b.FlatAppearance.MouseOverBackColor = ControlPaint.Light(back, 0.15f);
            // botão desabilitado fica neutro, para não parecer clicável
            b.EnabledChanged += (s, e) => b.BackColor = b.Enabled ? back : C.Card;
            return b;
        }

        Control BuildBottom()
        {
            var p = new Panel { Dock = DockStyle.Bottom, Height = 108, BackColor = C.Panel, Padding = new Padding(22, 8, 22, 12) };
            var opts = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 34, WrapContents = false };
            var lblMode = new Label { Text = "Varredura:", AutoSize = true, ForeColor = C.Dim, Margin = new Padding(0, 7, 6, 0) };
            cbMode = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat, BackColor = C.Card, ForeColor = C.Text,
                Width = 250, Margin = new Padding(0, 3, 18, 0), Cursor = Cursors.Hand
            };
            cbMode.Items.AddRange(ModeNames);
            cbMode.DrawMode = DrawMode.OwnerDrawFixed;
            cbMode.DrawItem += (s, e) =>
            {
                if (e.Index < 0) return;
                bool sel = (e.State & DrawItemState.Selected) != 0 && (e.State & DrawItemState.ComboBoxEdit) == 0;
                using (var b = new SolidBrush(sel ? C.Accent : C.Card)) e.Graphics.FillRectangle(b, e.Bounds);
                TextRenderer.DrawText(e.Graphics, cbMode.Items[e.Index].ToString(), cbMode.Font, Rectangle.Inflate(e.Bounds, -4, 0),
                    sel ? Color.White : C.Text, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
            };
            int.TryParse(Settings.Get("modo", "1"), out lastMode);
            if (lastMode < 0 || lastMode > 2) lastMode = 1;
            cbMode.SelectedIndex = lastMode;
            cbMode.SelectedIndexChanged += (s, e) => OnModeChanged();
            chkPersist = MkChk("Inicialização e suspeitos", true);
            chkUsb = MkChk("Pendrives", true);
            chkOffline = MkChk("Perfis e Windows offline", true);
            chkDefender = MkChk("Confirmar com o Defender", false);
            chkVaccine = MkChk("Vacinar após limpar", true);
            chkDefender.Checked = Settings.Get("defender", "0") == "1";
            chkDefender.CheckedChanged += (s, e) => { Settings.Set("defender", chkDefender.Checked ? "1" : "0"); ShowPlan(); };
            chkPersist.CheckedChanged += (s, e) => ShowPlan();
            chkUsb.CheckedChanged += (s, e) => ShowPlan();
            var tip = new ToolTip();
            tip.SetToolTip(chkPersist, "Programas sem assinatura iniciando de AppData/Temp, scripts na pasta Inicializar,\nDefender desligado ou com exceções perigosas, hosts e proxy adulterados.");
            tip.SetToolTip(chkDefender, "Os arquivos suspeitos também são verificados pelo motor do Windows Defender (MpCmdRun).");
            tip.SetToolTip(chkUsb, "autorun.inf, vírus do atalho (atalhos falsos e pastas escondidas) e executáveis escondidos.");
            opts.Controls.AddRange(new Control[] { lblMode, cbMode, chkPersist, chkUsb, chkOffline, chkDefender, chkVaccine });

            var btns = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            btns.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 520));
            btns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            btns.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var left = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Margin = Padding.Empty };
            var rightF = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false, Margin = Padding.Empty };

            btnScan = MkBtn("Escanear", C.Accent, 150, true);
            btnClean = MkBtn("Remover selecionados", Color.FromArgb(214, 64, 69), 210, true);
            btnCancel = MkBtn("Cancelar", C.Card, 120, false);
            btnReport = MkBtn("Relatório", C.Card, 100, false);
            btnQuar = MkBtn("Quarentena", C.Card, 112, false);
            btnUndo = MkBtn("Desfazer limpeza", C.Card, 150, false);
            btnAllow = MkBtn("Permitidos", C.Card, 110, false);
            btnProtect = MkBtn("Proteção", C.Card, 100, false);
            btnReport.Margin = new Padding(0, 4, 0, 0);

            btnScan.Click += (s, e) => StartScanWith(GetOptions());
            btnClean.Click += (s, e) => StartClean();
            btnCancel.Click += (s, e) => { if (cts != null) { cts.Cancel(); btnCancel.Enabled = false; SetStatus("Cancelando…", C.Yellow); } };
            btnUndo.Click += (s, e) => StartUndo();
            btnQuar.Click += (s, e) => { using (var q = new QuarantineForm(engine.QuarantineBase)) q.ShowDialog(this); };
            btnAllow.Click += (s, e) => { using (var a = new AllowForm()) a.ShowDialog(this); };
            btnProtect.Click += (s, e) => { using (var pf = new ProtectForm()) pf.ShowDialog(this); ApplyUsbWatch(); };
            btnReport.Click += (s, e) => SaveReport();

            left.Controls.AddRange(new Control[] { btnScan, btnClean, btnCancel });
            rightF.Controls.AddRange(new Control[] { btnReport, btnQuar, btnUndo, btnAllow, btnProtect });
            btns.Controls.Add(left, 0, 0);
            btns.Controls.Add(rightF, 1, 0);

            p.Controls.Add(btns);
            p.Controls.Add(opts);
            return p;
        }

        // =====================================================================
        // estado da interface
        // =====================================================================
        ScanOptions GetOptions()
        {
            int m = cbMode.SelectedIndex;
            var o = new ScanOptions
            {
                DeepScan = m >= 1, WholeDisk = m == 2, Removable = chkUsb.Checked, Offline = chkOffline.Checked,
                Vaccine = chkVaccine.Checked, Persistence = chkPersist.Checked, DefenderConfirm = chkDefender.Checked,
                ModeName = m == 0 ? "Rápida" : m == 1 ? "Completa" : m == 2 ? "Disco inteiro" : "Pasta"
            };
            if (m == 3 && customFolder != null)
            {
                o.CustomFolder = customFolder;
                o.SystemChecks = false; o.Persistence = false; o.Offline = false;
                o.Removable = Engine.IsRemovableRoot(customFolder);
                o.ModeName = "Pasta " + customFolder;
            }
            return o;
        }

        void OnModeChanged()
        {
            int m = cbMode.SelectedIndex;
            if (m == 3)
            {
                using (var fb = new FolderBrowserDialog { Description = "Escolha a pasta (ou o pendrive) que será verificada:", ShowNewFolderButton = false, SelectedPath = customFolder ?? "" })
                {
                    if (fb.ShowDialog(this) != DialogResult.OK) { cbMode.SelectedIndex = lastMode; return; }
                    customFolder = fb.SelectedPath;
                }
                cbMode.Items[3] = "Pasta: " + customFolder;
            }
            else
            {
                lastMode = m;
                Settings.Set("modo", m.ToString());
            }
            bool sys = m != 3;
            chkPersist.Enabled = sys && !busy;
            chkOffline.Enabled = sys && !busy;
            ShowPlan();
        }

        void SetStatus(string text, Color c) { lblStatus.Text = text; lblStatus.ForeColor = c; }

        void SetBusy(bool b)
        {
            busy = b;
            btnScan.Enabled = !b;
            btnCancel.Enabled = b;
            btnUndo.Enabled = !b;
            btnReport.Enabled = !b;
            foreach (var c in new Control[] { cbMode, chkUsb, chkDefender, chkVaccine, btnQuar, btnAllow, btnProtect }) c.Enabled = !b;
            chkPersist.Enabled = !b && cbMode.SelectedIndex != 3;
            chkOffline.Enabled = !b && cbMode.SelectedIndex != 3;
            bar.Busy = b;
            UpdateCleanButton();
        }

        void UpdateCleanButton()
        {
            btnClean.Enabled = !busy && uiFindings.Any(f => f.Selected && !f.Done);
        }

        void SelectTab(int idx)
        {
            activeTab = idx;
            pageFindings.Visible = idx == 0;
            pageLog.Visible = idx == 1;
            tabFind.ForeColor = idx == 0 ? C.Text : C.Dim;
            tabLog.ForeColor = idx == 1 ? C.Text : C.Dim;
            tabFind.Invalidate();
            tabLog.Invalidate();
        }

        void FitColumns()
        {
            if (lv.Columns.Count < 5) return;
            // Tipo, Gravidade e Status fixos; Item e Detalhe dividem o resto (sem barra horizontal)
            int fixedW = lv.Columns[0].Width + lv.Columns[1].Width + lv.Columns[3].Width;
            int free = lv.ClientSize.Width - fixedW;
            if (free < 300) free = 300;
            int item = (int)(free * 0.62);
            if (lv.Columns[2].Width != item) lv.Columns[2].Width = item;
            // o último ocupa exatamente o espaço restante (conta a barra vertical quando ela aparece)
            int client = lv.ClientSize.Width;
            if (lv.IsHandleCreated && lv.Items.Count > 0)
            {
                bool vbar = (Native.GetWindowLong(lv.Handle, -16) & 0x00200000) != 0;   // WS_VSCROLL
                int rowH = lv.Items[0].Bounds.Height, header = lv.Items[0].Bounds.Top;
                bool needV = header + rowH * lv.Items.Count > lv.ClientSize.Height;
                if (needV && !vbar) client -= SystemInformation.VerticalScrollBarWidth;
            }
            int last = Math.Max(60, client - fixedW - item - 1);
            if (lv.Columns[4].Width != last) lv.Columns[4].Width = last;
            // as colunas cabem: some com a barra horizontal que o ListView às vezes deixa de um layout anterior
            if (lv.IsHandleCreated) Native.ShowScrollBar(lv.Handle, 0, false);
        }

        void FitSteps()
        {
            int w = stepsList.ClientSize.Width - 2;
            foreach (var l in stepLabels) if (l.Width != w) l.Width = w;
        }

        // O ListView perde o estado das caixinhas de itens adicionados enquanto estava oculto:
        // reaplica a partir do modelo para a tela sempre bater com o que será removido.
        void SyncChecks()
        {
            suppressCheck = true;
            foreach (ListViewItem it in lv.Items)
            {
                var f = it.Tag as Finding;
                if (f != null && it.Checked != f.Selected) it.Checked = f.Selected;
            }
            suppressCheck = false;
        }

        void UpdateEmpty()
        {
            bool empty = lv.Items.Count == 0;
            lblEmpty.Visible = empty;
            if (!empty) SyncChecks();
            tabFind.Text = uiFindings.Count > 0 ? "Ameaças encontradas (" + uiFindings.Count + ")" : "Ameaças encontradas";
        }

        void ResetProgress()
        {
            bar.Value = 0;
            lblPercent.Text = "0%";
            lblPhase.Text = "Aguardando início";
            lblDone.Text = "Concluído: 0%";
            lblRemain.Text = "Falta: 100%";
            lblTime.Text = "Tempo: 00:00   ·   Restante estimado: --:--";
            lblFiles.Text = "";
            lblCurrent.Text = "";
        }

        void ShowPlan()
        {
            if (busy) return;
            var names = Engine.ScanPlan(GetOptions()).Select(k => k.Key).ToArray();
            BuildSteps(names);
            for (int i = 0; i < stepLabels.Count; i++) SetStep(i, "○", C.Dim, false);
        }

        void BuildSteps(string[] names)
        {
            stepNames = names;
            stepsList.SuspendLayout();
            stepsList.Controls.Clear();
            stepLabels.Clear();
            foreach (var n in names)
            {
                var l = new Label
                {
                    AutoSize = false, Width = 220, Height = 26, TextAlign = ContentAlignment.MiddleLeft, Font = fSmall,
                    ForeColor = C.Dim, Margin = new Padding(0, 0, 0, 1), Padding = new Padding(6, 0, 0, 0), Text = n, AutoEllipsis = true
                };
                stepLabels.Add(l);
                stepsList.Controls.Add(l);
            }
            FitSteps();
            stepsList.ResumeLayout();
        }

        void SetStep(int i, string glyph, Color c, bool current)
        {
            var l = stepLabels[i];
            string t = glyph + "   " + stepNames[i];
            if (l.Text != t) l.Text = t;
            if (l.ForeColor != c) l.ForeColor = c;
            var back = current ? C.Card : C.Panel;
            if (l.BackColor != back) l.BackColor = back;
            var f = current ? fBoldSmall : fSmall;
            if (l.Font != f) l.Font = f;
        }

        void UpdateSteps()
        {
            var names = engine.PhaseNames;
            if (engine.PhaseVersion != shownPhaseVersion || names.Length != stepLabels.Count)
            {
                shownPhaseVersion = engine.PhaseVersion;
                BuildSteps(names);
            }
            int cur = engine.PhaseIndex;
            for (int i = 0; i < stepLabels.Count; i++)
            {
                if (i < cur) SetStep(i, "✓", C.Green, false);
                else if (i == cur && busy) SetStep(i, "●", C.Accent, true);
                else if (i == cur && cancelled) SetStep(i, "✕", C.Red, false);
                else SetStep(i, "○", C.Dim, false);
            }
        }

        static string Fmt(TimeSpan t)
        {
            return t.TotalHours >= 1 ? t.ToString(@"h\:mm\:ss") : t.ToString(@"mm\:ss");
        }

        void UpdateProgress()
        {
            double p = engine.Overall;
            bar.Value = p;
            bar.Animate();
            int pct = (int)Math.Floor(p * 100 + 1e-9);
            if (busy && pct >= 100) pct = 99;
            lblPercent.Text = pct + "%";
            lblDone.Text = "Concluído: " + pct + "%";
            lblRemain.Text = "Falta: " + (100 - pct) + "%";
            var el = sw.Elapsed;
            string eta = "--:--";
            if (busy && p > 0.03) eta = Fmt(TimeSpan.FromSeconds(el.TotalSeconds * (1 - p) / p));
            else if (!busy && pct == 100) eta = "00:00";
            lblTime.Text = "Tempo: " + Fmt(el) + "   ·   Restante estimado: " + eta;

            int i = engine.PhaseIndex, n = engine.PhaseNames.Length;
            if (i >= 0 && i < n) lblPhase.Text = string.Format("Etapa {0} de {1}  —  {2}", i + 1, n, engine.PhaseNames[i]);
            else if (n > 0 && i >= n) lblPhase.Text = mode == "scan" ? "Varredura concluída" : mode == "clean" ? "Limpeza concluída" : "Concluído";

            long fd = engine.FilesDone, ft = engine.FilesTotal;
            lblFiles.Text = ft > 0 ? string.Format("Executáveis analisados: {0:N0} de {1:N0}", fd, ft) : "";
            lblCurrent.Text = busy && engine.CurrentItem.Length > 0 ? "Analisando agora:  " + engine.CurrentItem : "";
        }

        // =====================================================================
        // itens da lista
        // =====================================================================
        static Color SevColor(Severity s)
        {
            switch (s)
            {
                case Severity.Critico: return C.Red;
                case Severity.Alto: return C.Orange;
                case Severity.Medio: return C.Yellow;
                default: return C.Accent;
            }
        }

        static Color StatusColor(Finding f)
        {
            if (f.Failed) return C.Red;
            if (f.Status.Contains("reinício")) return C.Yellow;
            if (f.Done) return C.Green;
            return C.Dim;
        }

        static string FirstLine(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            int i = s.IndexOf('\r');
            return i < 0 ? s : s.Substring(0, i);
        }

        ListViewItem MakeItem(Finding f)
        {
            var it = new ListViewItem(f.KindText) { Checked = f.Selected, Tag = f, UseItemStyleForSubItems = false, ForeColor = C.Text, BackColor = C.Panel };
            it.SubItems.Add(f.SeverityText, SevColor(f.Severity), C.Panel, fBoldSmall);
            it.SubItems.Add(f.Title, C.Text, C.Panel, lv.Font);
            it.SubItems.Add(f.Status, StatusColor(f), C.Panel, lv.Font);
            it.SubItems.Add(FirstLine(f.Detail), C.Dim, C.Panel, lv.Font);
            f.Tag = it;
            return it;
        }

        void UpdateItem(Finding f)
        {
            var it = f.Tag as ListViewItem;
            if (it == null) return;
            it.Text = f.KindText;
            it.SubItems[1].Text = f.SeverityText;
            it.SubItems[1].ForeColor = SevColor(f.Severity);
            it.SubItems[3].Text = f.Status;
            it.SubItems[3].ForeColor = StatusColor(f);
            suppressCheck = true;
            it.Checked = f.Selected;
            suppressCheck = false;
            if (it.Selected) ShowDetail();
        }

        Finding SelectedFinding()
        {
            return lv.SelectedItems.Count > 0 ? lv.SelectedItems[0].Tag as Finding : null;
        }

        void ShowDetail()
        {
            var f = SelectedFinding();
            if (f == null) return;
            txtDetail.Text = f.KindText + "  ·  Gravidade: " + f.SeverityText + "  ·  Status: " + f.Status + "\r\n" + f.Title + "\r\n\r\n" + f.Detail;
        }

        void SetAllChecked(bool on)
        {
            if (busy) return;
            suppressCheck = true;
            foreach (ListViewItem it in lv.Items)
            {
                var f = it.Tag as Finding;
                if (f == null || f.Done) continue;
                f.Selected = on;
                it.Checked = on;
            }
            suppressCheck = false;
            UpdateCleanButton();
        }

        void UpdateCards()
        {
            Func<FindingKind[], int> cnt = ks => uiFindings.Count(f => ks.Contains(f.Kind));
            cProc.SetValue(cnt(new[] { FindingKind.Process }));
            cMal.SetValue(cnt(new[] { FindingKind.MaliciousFile }));
            cInf.SetValue(cnt(new[] { FindingKind.InfectedFile }));
            cReg.SetValue(cnt(new[] { FindingKind.Registry, FindingKind.Autorun }));
            cSvc.SetValue(cnt(new[] { FindingKind.Service, FindingKind.Task }));
            cWarn.SetValue(cnt(new[] { FindingKind.Policy }));
        }

        void AppendLog(LogEntry e)
        {
            Color c;
            switch (e.Level)
            {
                case LogLevel.Ok: c = C.Green; break;
                case LogLevel.Warn: c = C.Yellow; break;
                case LogLevel.Error: c = C.Red; break;
                case LogLevel.Title: c = C.Accent; break;
                default: c = C.Text; break;
            }
            rtb.SelectionStart = rtb.TextLength;
            rtb.SelectionLength = 0;
            rtb.SelectionColor = C.Dim;
            rtb.SelectionFont = fMono;
            rtb.AppendText((e.Level == LogLevel.Title ? "\n" : "") + e.Time.ToString("HH:mm:ss") + "   ");
            rtb.SelectionColor = c;
            rtb.SelectionFont = e.Level == LogLevel.Title ? fBold : fMono;
            rtb.AppendText((e.Level == LogLevel.Title ? "■ " : "") + e.Text + "\n");
        }

        void DrainLogs()
        {
            LogEntry le;
            int n = 0;
            if (engine.LogQueue.IsEmpty) return;
            rtb.SuspendLayout();
            while (n < 400 && engine.LogQueue.TryDequeue(out le)) { AppendLog(le); n++; }
            rtb.ResumeLayout();
            rtb.SelectionStart = rtb.TextLength;
            rtb.ScrollToCaret();
        }

        // =====================================================================
        // ciclo da interface
        // =====================================================================
        void UiTick(object sender, EventArgs e)
        {
            DrainLogs();
            Finding f;
            bool added = false, changed = false;
            if (!engine.NewFindings.IsEmpty || !engine.ChangedFindings.IsEmpty)
            {
                lv.BeginUpdate();
                while (engine.NewFindings.TryDequeue(out f))
                {
                    uiFindings.Add(f);
                    suppressCheck = true;
                    lv.Items.Add(MakeItem(f));
                    suppressCheck = false;
                    added = true;
                }
                while (engine.ChangedFindings.TryDequeue(out f)) { UpdateItem(f); changed = true; }
                lv.EndUpdate();
            }
            if (added)
            {
                FitColumns();   // a barra vertical pode ter aparecido
                UpdateCards();
                UpdateEmpty();
                if (mode == "scan") SetStatus(uiFindings.Count + " item(ns) encontrado(s)…", C.Orange);
            }
            if (added || changed) UpdateCleanButton();
            UpdateSteps();
            UpdateProgress();

            if (task != null && task.IsCompleted && engine.LogQueue.IsEmpty && engine.NewFindings.IsEmpty && engine.ChangedFindings.IsEmpty)
                Finish();
        }

        void RunEngine(string m, Action<CancellationToken> work)
        {
            mode = m;
            cancelled = false;
            cts = new CancellationTokenSource();
            var tok = cts.Token;
            sw.Restart();
            SetBusy(true);
            task = Task.Factory.StartNew(() => work(tok), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            uiTimer.Start();
        }

        public void StartScanWith(ScanOptions o)
        {
            if (busy) return;
            uiFindings.Clear();
            lv.Items.Clear();
            txtDetail.Text = "Selecione um item para ver os detalhes.";
            UpdateCards();
            UpdateEmpty();
            SetStatus("Escaneando…", C.Accent);
            RunEngine("scan", ct => engine.Scan(o, ct));
        }

        void StartClean()
        {
            if (busy) return;
            var sel = uiFindings.Where(f => f.Selected && !f.Done).ToList();
            if (sel.Count == 0) return;
            int inf = sel.Count(f => f.Kind == FindingKind.InfectedFile && !f.Disinfect);
            int rec = sel.Count(f => f.Kind == FindingKind.InfectedFile && f.Disinfect);
            var sb = new StringBuilder();
            sb.AppendLine("Serão tratados " + sel.Count + " item(ns):");
            foreach (var g in sel.GroupBy(f => f.KindText)) sb.AppendLine("   •  " + g.Key + ": " + g.Count());
            sb.AppendLine();
            sb.AppendLine("Os processos do vírus serão congelados e encerrados, os arquivos vão para a quarentena");
            sb.AppendLine("e as alterações no registro ganham backup — tudo pode ser desfeito depois.");
            if (inf > 0)
            {
                sb.AppendLine();
                sb.AppendLine(inf + " programa(s) infectado(s) irão para a quarentena: reinstale-os depois da limpeza.");
            }
            if (rec > 0)
            {
                sb.AppendLine();
                sb.AppendLine(rec + " programa(s) infectado(s) serão DESINFETADOS: o original é recuperado e volta ao lugar");
                sb.AppendLine("(o arquivo infectado fica guardado na quarentena).");
            }
            if (chkVaccine.Checked) { sb.AppendLine(); sb.AppendLine("Ao final será aplicada a vacina contra reinfecção."); }
            sb.AppendLine();
            sb.Append("Continuar?");
            if (MessageBox.Show(this, sb.ToString(), "Confirmar remoção", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            lastSelection = sel;
            var o = GetOptions();
            SetStatus("Removendo ameaças…", C.Orange);
            RunEngine("clean", ct => engine.Clean(sel, o, ct));
        }

        void StartUndo()
        {
            if (busy) return;
            string qb = engine.QuarantineBase;
            var sessions = Directory.Exists(qb)
                ? Directory.GetDirectories(qb).Where(d => File.Exists(Path.Combine(d, "manifesto.txt"))).OrderByDescending(d => d).ToList()
                : new List<string>();
            if (sessions.Count == 0)
            {
                MessageBox.Show(this, "Não há nenhuma limpeza para desfazer.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string dir = sessions[0];
            if (sessions.Count > 1)
            {
                using (var fb = new FolderBrowserDialog { SelectedPath = dir, ShowNewFolderButton = false, Description = "Escolha a sessão de limpeza a desfazer (pasta com manifesto.txt):" })
                {
                    if (fb.ShowDialog(this) != DialogResult.OK) return;
                    dir = fb.SelectedPath;
                }
                if (!File.Exists(Path.Combine(dir, "manifesto.txt")))
                {
                    MessageBox.Show(this, "Essa pasta não tem manifesto.txt.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }
            if (MessageBox.Show(this,
                    "Desfazer a limpeza de " + Path.GetFileName(dir) + "?\r\n\r\nATENÇÃO: isso devolve os arquivos do vírus para os locais originais e restaura as entradas de registro e tarefas. " +
                    "Use só se algo legítimo foi removido por engano.",
                    "Desfazer limpeza", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            SetStatus("Desfazendo…", C.Yellow);
            RunEngine("undo", ct => engine.Undo(dir, ct));
        }

        void Finish()
        {
            uiTimer.Stop();
            cancelled = cts != null && cts.IsCancellationRequested;
            task = null;
            sw.Stop();
            SetBusy(false);
            UpdateSteps();
            UpdateProgress();
            SelectTab(activeTab);

            if (mode == "scan")
            {
                int threats = uiFindings.Count(x => x.Severity != Severity.Info);
                if (cancelled) SetStatus("Varredura cancelada", C.Yellow);
                else if (threats > 0) SetStatus("⚠  " + threats + " ameaça(s) encontrada(s)", C.Red);
                else if (uiFindings.Count > 0) SetStatus("Sem ameaças · " + uiFindings.Count + " aviso(s)", C.Yellow);
                else SetStatus("✓  Nenhuma ameaça encontrada", C.Green);
                if (!cancelled && threats > 0 && lv.Items.Count > 0) { lv.Items[0].Selected = true; lv.Focus(); }
            }
            else if (mode == "clean")
            {
                int ok = lastSelection.Count(x => x.Done && !x.Failed), fail = lastSelection.Count(x => x.Failed);
                if (cancelled) SetStatus("Limpeza interrompida", C.Yellow);
                else if (fail > 0) SetStatus("Limpeza com " + fail + " falha(s)", C.Orange);
                else SetStatus("✓  Limpeza concluída", C.Green);
                string msg = string.Format("{0} item(ns) tratados, {1} falha(s).\r\nQuarentena e backup: {2}", ok, fail, engine.LastSessionDir);
                if (engine.RestoredCount > 0)
                    msg += string.Format("\r\n\r\n{0} programa(s) desinfetado(s): o original foi recuperado e voltou ao lugar.", engine.RestoredCount);
                msg += "\r\n\r\nRecomendado: rode \"Escanear\" de novo para confirmar e faça uma varredura completa com o Windows Defender.";
                if (engine.NeedReboot)
                {
                    if (MessageBox.Show(this, msg + "\r\n\r\nÉ preciso REINICIAR para concluir a remoção. Reiniciar agora?", "Limpeza", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                        Process.Start(new ProcessStartInfo("shutdown.exe", "/r /t 5") { CreateNoWindow = true, UseShellExecute = false });
                }
                else if (!closeRequested) MessageBox.Show(this, msg, "Limpeza", MessageBoxButtons.OK, fail > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            }
            else if (mode == "undo")
            {
                SetStatus(cancelled ? "Restauração interrompida" : "Limpeza desfeita", C.Yellow);
            }
            if (closeRequested) Close();
        }

        void SaveReport()
        {
            using (var d = new SaveFileDialog
            {
                Filter = "Página HTML|*.html", FileName = "Relatorio_DGX_Virus_Remover_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".html",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
            })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                List<LogEntry> log;
                lock (engine.FullLog) log = engine.FullLog.ToList();
                File.WriteAllText(d.FileName, Report.Build(uiFindings, log, engine.LastSessionDir), new UTF8Encoding(true));
                try { Process.Start(d.FileName); } catch { }
            }
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            FitColumns();
            SelectTab(0);
            ApplyUsbWatch();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (busy)
            {
                e.Cancel = true;
                if (MessageBox.Show(this, "Uma operação está em andamento. Cancelar e sair?", Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                {
                    closeRequested = true;
                    if (cts != null) cts.Cancel();
                }
                return;
            }
            base.OnFormClosing(e);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            try { engine.UnloadHives(); } catch { }
            base.OnFormClosed(e);
        }
    }
}
