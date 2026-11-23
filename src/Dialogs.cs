using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace TJRemover
{
    /// <summary>Base escura comum às janelas auxiliares.</summary>
    public class DarkDialog : Form
    {
        protected readonly Font fBold = new Font("Segoe UI Semibold", 10f);
        protected readonly Font fTitle = new Font("Segoe UI Semibold", 13f);
        protected readonly FlowLayoutPanel buttons;
        protected readonly Panel body;

        public DarkDialog(string title, string subtitle, int w, int h)
        {
            Text = title + " — " + Program.AppName;
            Size = new Size(w, h);
            MinimumSize = new Size(Math.Min(w, 720), Math.Min(h, 420));
            StartPosition = FormStartPosition.CenterParent;
            BackColor = C.Bg; ForeColor = C.Text;
            Font = new Font("Segoe UI", 9.5f);
            AutoScaleMode = AutoScaleMode.Dpi;
            ShowInTaskbar = false; MinimizeBox = false;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            var head = new Panel { Dock = DockStyle.Top, Height = 64, BackColor = C.Panel, Padding = new Padding(20, 10, 20, 8) };
            head.Controls.Add(new Label { Text = subtitle, Dock = DockStyle.Top, Height = 20, ForeColor = C.Dim });
            head.Controls.Add(new Label { Text = title, Dock = DockStyle.Top, Height = 26, Font = fTitle });
            var foot = new Panel { Dock = DockStyle.Bottom, Height = 62, BackColor = C.Panel, Padding = new Padding(20, 10, 20, 10) };
            buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
            foot.Controls.Add(buttons);
            body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 14, 20, 14) };
            Controls.Add(body); Controls.Add(foot); Controls.Add(head);
        }

        protected Button Btn(string text, int width, bool primary, EventHandler click)
        {
            var back = primary ? C.Accent : C.Card;
            var b = new Button
            {
                Text = text, Width = width, Height = 38, FlatStyle = FlatStyle.Flat, BackColor = back, ForeColor = primary ? Color.White : C.Text,
                Font = fBold, Cursor = Cursors.Hand, Margin = new Padding(0, 0, 10, 0)
            };
            b.FlatAppearance.BorderSize = primary ? 0 : 1;
            b.FlatAppearance.BorderColor = C.Border;
            b.Click += click;
            buttons.Controls.Add(b);
            return b;
        }

        protected ListView MakeList(params KeyValuePair<string, int>[] cols)
        {
            var lv = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = true, HideSelection = false,
                BackColor = C.Panel, ForeColor = C.Text, BorderStyle = BorderStyle.None, CheckBoxes = false
            };
            foreach (var c in cols) lv.Columns.Add(c.Key, c.Value);
            lv.OwnerDraw = true;
            lv.DrawColumnHeader += (s, e) =>
            {
                using (var b = new SolidBrush(C.Card)) e.Graphics.FillRectangle(b, e.Bounds);
                TextRenderer.DrawText(e.Graphics, e.Header.Text, fBold, Rectangle.Inflate(e.Bounds, -6, 0), C.Dim,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
            };
            lv.DrawItem += (s, e) => e.DrawDefault = true;
            lv.DrawSubItem += (s, e) => e.DrawDefault = true;
            return lv;
        }

        protected static KeyValuePair<string, int> Col(string n, int w) { return new KeyValuePair<string, int>(n, w); }
    }

    // =========================================================================
    // QUARENTENA
    // =========================================================================
    public class QItem
    {
        public string Session, Manifest, Original, Vir, Hash;
        public bool Restored;   // desinfetado: o original limpo já voltou ao lugar
        public bool Encrypted;  // cópia cifrada (formato novo)
        public string Attrs;    // atributos originais (oculto/sistema)
        public long Size;
        public DateTime When;
    }

    public class QuarantineForm : DarkDialog
    {
        readonly string baseDir;
        readonly ListView lv;
        readonly Label info;

        public QuarantineForm(string quarantineBase)
            : base("Quarentena", "Arquivos removidos ficam guardados aqui (inofensivos, com extensão .vir). Restaure só o que tiver certeza de que não é vírus.", 1060, 600)
        {
            baseDir = quarantineBase;
            lv = MakeList(Col("Data", 130), Col("Arquivo original", 560), Col("Tamanho", 100), Col("Situação", 220));
            info = new Label { Dock = DockStyle.Bottom, Height = 26, ForeColor = C.Dim, TextAlign = ContentAlignment.MiddleLeft };
            body.Controls.Add(lv); body.Controls.Add(info);
            Btn("Restaurar", 120, false, (s, e) => Restore(false));
            Btn("Restaurar e permitir", 175, false, (s, e) => Restore(true));
            Btn("Excluir definitivamente", 195, false, (s, e) => Delete(lv.SelectedItems.Cast<ListViewItem>().Select(i => (QItem)i.Tag).ToList(), "selecionado(s)"));
            Btn("Esvaziar com mais de 30 dias", 225, false, (s, e) => Delete(Items().Where(q => q.When < DateTime.Now.AddDays(-30)).ToList(), "com mais de 30 dias"));
            Btn("Abrir pasta", 115, false, (s, e) => { Directory.CreateDirectory(baseDir); Process.Start("explorer.exe", "\"" + baseDir + "\""); });
            Btn("Fechar", 90, true, (s, e) => Close());
            Fill();
        }

        List<QItem> Items()
        {
            var res = new List<QItem>();
            if (!Directory.Exists(baseDir)) return res;
            foreach (var dir in Directory.GetDirectories(baseDir))
            {
                string mf = Path.Combine(dir, "manifesto.txt");
                if (!File.Exists(mf)) continue;
                DateTime when;
                if (!DateTime.TryParseExact(Path.GetFileName(dir), "yyyyMMdd_HHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None, out when))
                    when = Directory.GetCreationTime(dir);
                string[] lines;
                try { lines = File.ReadAllLines(mf); } catch { continue; }
                var rest = new HashSet<string>(lines.Where(l => l.StartsWith("REST\t") || l.StartsWith("REN\t"))
                    .Select(l => l.Split('\t')).Select(p => p[0] == "REN" ? p[2] : p[1]), StringComparer.OrdinalIgnoreCase);
                foreach (var l in lines.Where(x => x.StartsWith("FILE\t")))
                {
                    var p = l.Split('\t');
                    if (p.Length < 3 || !File.Exists(p[2])) continue;
                    long size = 0; try { size = new FileInfo(p[2]).Length; } catch { }
                    res.Add(new QItem { Session = dir, Manifest = mf, Original = p[1], Vir = p[2], Hash = p.Length > 3 ? p[3] : "", Restored = rest.Contains(p[1]), Size = size, When = when, Encrypted = p.Length > 4 && p[4] == "X", Attrs = p.Length > 5 ? p[5] : null });
                }
            }
            return res.OrderByDescending(q => q.When).ToList();
        }

        void Fill()
        {
            lv.BeginUpdate();
            lv.Items.Clear();
            var items = Items();
            foreach (var q in items)
            {
                var it = new ListViewItem(q.When.ToString("dd/MM/yyyy HH:mm")) { Tag = q };
                it.SubItems.Add(q.Original);
                it.SubItems.Add(string.Format("{0:N0} KB", (q.Size + 1023) / 1024));
                it.SubItems.Add(q.Restored ? "Desinfetado (original no lugar)" : "Removido");
                lv.Items.Add(it);
            }
            lv.EndUpdate();
            long total = items.Sum(q => q.Size);
            info.Text = string.Format("{0} arquivo(s) na quarentena · {1:N1} MB · pasta: {2}", items.Count, total / 1048576.0, baseDir);
        }

        static void Mark(QItem q, string tag)
        {
            try { File.AppendAllText(q.Manifest, tag + "\t" + q.Vir + "\r\n"); } catch { }
        }

        void Restore(bool allow)
        {
            var sel = lv.SelectedItems.Cast<ListViewItem>().Select(i => (QItem)i.Tag).ToList();
            if (sel.Count == 0) return;
            if (MessageBox.Show(this, "Devolver " + sel.Count + " arquivo(s) para o local original?" +
                    (allow ? "\r\nEles também entram na lista de Permitidos e não serão mais acusados." : "") +
                    "\r\n\r\nSó faça isso se tiver certeza de que NÃO são vírus.", "Restaurar", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            var sb = new StringBuilder();
            foreach (var q in sel)
            {
                try
                {
                    if (File.Exists(q.Original)) { sb.AppendLine("Já existe arquivo em " + q.Original + (q.Restored ? " (é o programa desinfetado — use \"Desfazer limpeza\" para trocar)" : "")); continue; }
                    Engine.RestoreFromQuarantine(q.Vir, q.Original, q.Encrypted, q.Attrs);
                    Mark(q, "RESTORED");
                    if (allow)
                    {
                        Allowlist.Add(AllowType.File, q.Original, "restaurado da quarentena em " + DateTime.Now.ToString("dd/MM/yyyy"));
                        string h = Engine.Sha256(q.Original);
                        if (h != null) Allowlist.Add(AllowType.Hash, h, Path.GetFileName(q.Original));
                    }
                }
                catch (Exception ex) { sb.AppendLine("Falha em " + q.Original + ": " + ex.Message); }
            }
            if (sb.Length > 0) MessageBox.Show(this, sb.ToString(), "Restaurar", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Fill();
        }

        void Delete(List<QItem> list, string what)
        {
            if (list.Count == 0) { MessageBox.Show(this, "Nenhum arquivo " + what + ".", "Quarentena", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            if (MessageBox.Show(this, "Excluir DEFINITIVAMENTE " + list.Count + " arquivo(s) " + what + " da quarentena?\r\n\r\n" +
                    "Eles não poderão mais ser restaurados (o \"Desfazer limpeza\" dessas sessões também não os trará de volta).",
                    "Excluir definitivamente", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            int ok = 0;
            foreach (var q in list)
                try { File.Delete(q.Vir); Mark(q, "DELETED"); ok++; } catch { }
            MessageBox.Show(this, ok + " arquivo(s) excluído(s) definitivamente.", "Quarentena", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Fill();
        }
    }

    // =========================================================================
    // PERMITIDOS
    // =========================================================================
    public class AllowForm : DarkDialog
    {
        readonly ListView lv;

        public AllowForm()
            : base("Permitidos", "Arquivos, pastas e entradas que você marcou como \"não é vírus\". Eles são ignorados em todas as varreduras.", 960, 540)
        {
            lv = MakeList(Col("Tipo", 150), Col("Valor", 520), Col("Observação", 240));
            body.Controls.Add(lv);
            Btn("Adicionar arquivo…", 160, false, (s, e) => AddFile());
            Btn("Adicionar pasta…", 150, false, (s, e) => AddFolder());
            Btn("Remover", 110, false, (s, e) => RemoveSel());
            Btn("Fechar", 90, true, (s, e) => Close());
            Fill();
        }

        void Fill()
        {
            lv.BeginUpdate();
            lv.Items.Clear();
            foreach (var a in Allowlist.All)
            {
                var it = new ListViewItem(a.TypeText) { Tag = a };
                it.SubItems.Add(a.Value);
                it.SubItems.Add(a.Note);
                lv.Items.Add(it);
            }
            lv.EndUpdate();
        }

        void AddFile()
        {
            using (var d = new OpenFileDialog { Title = "Arquivo que não é vírus", Filter = "Todos os arquivos|*.*", Multiselect = true })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                foreach (var f in d.FileNames)
                {
                    Allowlist.Add(AllowType.File, f, "adicionado em " + DateTime.Now.ToString("dd/MM/yyyy"));
                    string h = Engine.Sha256(f);
                    if (h != null) Allowlist.Add(AllowType.Hash, h, Path.GetFileName(f));
                }
            }
            Fill();
        }

        void AddFolder()
        {
            using (var d = new FolderBrowserDialog { Description = "Pasta cujo conteúdo não deve ser acusado (inclui subpastas):" })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                if (d.SelectedPath.Length <= 3 &&
                    MessageBox.Show(this, "Permitir um disco INTEIRO desliga a proteção nele. Tem certeza?", "Permitidos", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                Allowlist.Add(AllowType.Folder, d.SelectedPath, "adicionado em " + DateTime.Now.ToString("dd/MM/yyyy"));
            }
            Fill();
        }

        void RemoveSel()
        {
            var sel = lv.SelectedItems.Cast<ListViewItem>().Select(i => (AllowEntry)i.Tag).ToList();
            if (sel.Count == 0) return;
            if (MessageBox.Show(this, "Remover " + sel.Count + " item(ns) da lista? Eles voltam a ser verificados.", "Permitidos", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            foreach (var a in sel) Allowlist.Remove(a);
            Fill();
        }
    }

    // =========================================================================
    // PROTEÇÃO (máquina limpa)
    // =========================================================================
    public class ProtectForm : DarkDialog
    {
        readonly Label lblDefender;
        readonly CheckBox chkWatch, chkAutorun, chkExt, chkHidden;
        bool loading;

        const string PolExplorer = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
        const string AdvExplorer = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";

        public ProtectForm()
            : base("Proteção", "Ajustes que mantêm a máquina limpa no dia a dia da oficina.", 900, 660)
        {
            var flow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true };
            body.Controls.Add(flow);
            Func<string, Label> head = t => new Label { Text = t, AutoSize = true, Font = fBold, ForeColor = C.Text, Margin = new Padding(0, 10, 0, 4) };
            Func<string, Label> note = t => new Label { Text = t, AutoSize = true, MaximumSize = new Size(820, 0), ForeColor = C.Dim, Margin = new Padding(22, 0, 0, 6) };
            Func<string, CheckBox> chk = t => new CheckBox { Text = t, AutoSize = true, ForeColor = C.Text, Cursor = Cursors.Hand, Margin = new Padding(0, 4, 0, 0) };

            flow.Controls.Add(head("Windows Defender"));
            lblDefender = new Label { AutoSize = true, ForeColor = C.Dim, Text = "Consultando…", Margin = new Padding(0, 0, 0, 4) };
            flow.Controls.Add(lblDefender);
            var defBtns = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 2, 0, 4) };
            defBtns.Controls.Add(SmallBtn("Abrir Segurança do Windows", 220, (s, e) => { try { Process.Start("windowsdefender:"); } catch { } }));
            defBtns.Controls.Add(SmallBtn("Atualizar assinaturas", 180, (s, e) => UpdateSignatures()));
            flow.Controls.Add(defBtns);

            flow.Controls.Add(head("Pendrives"));
            chkWatch = chk("Verificar automaticamente todo pendrive conectado (enquanto o programa estiver aberto)");
            flow.Controls.Add(chkWatch);
            flow.Controls.Add(note("Ao conectar, o pendrive é varrido antes de você abrir qualquer arquivo: vírus do atalho, autorun, executáveis escondidos e as famílias conhecidas."));
            chkAutorun = chk("Bloquear AutoRun / Reprodução Automática em pendrives, CDs e discos de rede");
            flow.Controls.Add(chkAutorun);
            flow.Controls.Add(note("Impede que um pendrive infectado execute algo sozinho ao ser conectado (vale para todos os usuários)."));

            flow.Controls.Add(head("Explorador de Arquivos"));
            chkExt = chk("Mostrar extensões de arquivo");
            flow.Controls.Add(chkExt);
            flow.Controls.Add(note("Assim \"Laudo.pdf.exe\" aparece com o .exe e você percebe que é programa, não documento."));
            chkHidden = chk("Mostrar arquivos e pastas ocultos");
            flow.Controls.Add(chkHidden);
            flow.Controls.Add(note("Revela arquivos que vírus escondem (as pastas do sistema continuam protegidas)."));

            flow.Controls.Add(head("Rotina da máquina limpa"));
            flow.Controls.Add(note(
                "1. Defender ligado e atualizado; varredura rápida aqui toda semana e completa todo mês.\r\n" +
                "2. Pendrive de cliente: sempre verificar antes de abrir; nunca executar .exe que veio dentro dele.\r\n" +
                "3. Ferramentas, cracks e keygens: testar primeiro em \"Pasta escolhida\" (ou numa máquina virtual), nunca direto no PC de trabalho.\r\n" +
                "4. Não desligar o Defender para rodar programa: se ele acusar, permita só aquele arquivo, depois de verificado.\r\n" +
                "5. Revisar a Quarentena e esvaziar o que tiver mais de 30 dias.\r\n" +
                "6. Lista de Permitidos curta: só arquivos que você conhece e verificou.\r\n" +
                "7. Backup dos arquivos de trabalho (calibrações, laudos) fora do PC — contra ransomware."));

            loading = true;
            chkWatch.Checked = Settings.Get("vigiarPendrive", "1") == "1";
            chkAutorun.Checked = ReadDword(Registry.LocalMachine, PolExplorer, "NoDriveTypeAutoRun", 0) == 0xFF;
            chkExt.Checked = ReadDword(Registry.CurrentUser, AdvExplorer, "HideFileExt", 1) == 0;
            chkHidden.Checked = ReadDword(Registry.CurrentUser, AdvExplorer, "Hidden", 2) == 1;
            loading = false;

            chkWatch.CheckedChanged += (s, e) => { if (!loading) Settings.Set("vigiarPendrive", chkWatch.Checked ? "1" : "0"); };
            chkAutorun.CheckedChanged += (s, e) => { if (!loading) SetAutorun(chkAutorun.Checked); };
            chkExt.CheckedChanged += (s, e) => { if (!loading) SetDword(Registry.CurrentUser, AdvExplorer, "HideFileExt", chkExt.Checked ? 0 : 1, true); };
            chkHidden.CheckedChanged += (s, e) => { if (!loading) SetDword(Registry.CurrentUser, AdvExplorer, "Hidden", chkHidden.Checked ? 1 : 2, true); };

            Btn("Fechar", 90, true, (s, e) => Close());
            Task.Factory.StartNew(() => DefenderStatus()).ContinueWith(t => { try { lblDefender.Text = t.Result; lblDefender.ForeColor = t.Result.StartsWith("✓") ? C.Green : C.Orange; } catch { } },
                TaskScheduler.FromCurrentSynchronizationContext());
        }

        Button SmallBtn(string text, int w, EventHandler click)
        {
            var b = new Button { Text = text, Width = w, Height = 32, FlatStyle = FlatStyle.Flat, BackColor = C.Card, ForeColor = C.Text, Cursor = Cursors.Hand, Margin = new Padding(0, 0, 8, 0) };
            b.FlatAppearance.BorderColor = C.Border;
            b.Click += click;
            return b;
        }

        static int ReadDword(RegistryKey hive, string key, string name, int def)
        {
            try { using (var k = hive.OpenSubKey(key)) return k == null ? def : Convert.ToInt32(k.GetValue(name, def)); } catch { return def; }
        }

        void SetDword(RegistryKey hive, string key, string name, int value, bool refresh)
        {
            try
            {
                using (var k = hive.CreateSubKey(key)) k.SetValue(name, value, RegistryValueKind.DWord);
                if (refresh) Native.SHChangeNotify(0x08000000, 0, IntPtr.Zero, IntPtr.Zero);   // SHCNE_ASSOCCHANGED: Explorer relê as opções
            }
            catch (Exception ex) { MessageBox.Show(this, "Não foi possível alterar: " + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        void SetAutorun(bool block)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
                try
                {
                    using (var k = hive.CreateSubKey(PolExplorer))
                    {
                        if (block) k.SetValue("NoDriveTypeAutoRun", 0xFF, RegistryValueKind.DWord);
                        else k.DeleteValue("NoDriveTypeAutoRun", false);
                    }
                }
                catch (Exception ex) { MessageBox.Show(this, "Não foi possível alterar o AutoRun: " + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
        }

        static string DefenderStatus()
        {
            try
            {
                using (var s = new System.Management.ManagementObjectSearcher(@"root\Microsoft\Windows\Defender",
                    "SELECT AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus"))
                    foreach (System.Management.ManagementObject o in s.Get())
                    {
                        bool av = Convert.ToBoolean(o["AntivirusEnabled"]), rt = Convert.ToBoolean(o["RealTimeProtectionEnabled"]);
                        string upd = "";
                        try { upd = System.Management.ManagementDateTimeConverter.ToDateTime(Convert.ToString(o["AntivirusSignatureLastUpdated"])).ToString("dd/MM/yyyy"); } catch { }
                        if (av && rt) return "✓ Proteção em tempo real LIGADA · assinaturas de " + upd;
                        return "⚠ Proteção em tempo real DESLIGADA" + (upd.Length > 0 ? " · assinaturas de " + upd : "") + " — religue em Segurança do Windows.";
                    }
            }
            catch { }
            return "⚠ Não foi possível consultar o Windows Defender (outro antivírus instalado?).";
        }

        void UpdateSignatures()
        {
            string mp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe");
            if (!File.Exists(mp)) { MessageBox.Show(this, "MpCmdRun.exe não encontrado.", Text); return; }
            lblDefender.Text = "Atualizando assinaturas do Defender…";
            lblDefender.ForeColor = C.Accent;
            Task.Factory.StartNew(() =>
            {
                try
                {
                    using (var p = Process.Start(new ProcessStartInfo(mp, "-SignatureUpdate") { CreateNoWindow = true, UseShellExecute = false }))
                        p.WaitForExit(300000);
                }
                catch { }
                return DefenderStatus();
            }).ContinueWith(t => { try { lblDefender.Text = t.Result; lblDefender.ForeColor = t.Result.StartsWith("✓") ? C.Green : C.Orange; } catch { } },
                TaskScheduler.FromCurrentSynchronizationContext());
        }
    }
}
