using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace TJRemover
{
    class RegSource
    {
        public string Root;     // HKLM / HKU
        public string Prefix;   // caminho até a raiz "SOFTWARE" daquela fonte
        public bool Machine;
        public bool Wow;
        public bool Online;
        public string Label;
    }

    public class FileScanResult
    {
        public bool IsPE;
        public bool Signature;
        public bool SignatureInTail;
        public long EmbeddedPe = -1;
        public bool Infected { get { return IsPE && (EmbeddedPe > 0 || SignatureInTail); } }
        public VirusFamily Family;        // Synaptics / Mofksys / Grenam (assinaturas do Synaptics Killer)
        public DisinfectPlan Plan;        // como recuperar o programa original
    }

    public partial class Engine
    {
        // Nome do vírus montado em tempo de execução, para que ESTE executável
        // não contenha a assinatura e não seja detectado por ele mesmo.
        public static readonly string V = new string("niaMjorpJT".Reverse().ToArray());

        // ---- configuração para testes
        public static string TestRoot;
        public static string QuarantineBaseOverride;

        public static readonly string[] KnownDropperRel =
        {
            @"Windows\Resources\svchost.exe", @"Windows\Resources\spoolsv.exe",
            @"Windows\Resources\Themes\explorer.exe", @"Windows\Resources\Themes\icsys.icn.exe",
            @"Windows\System\svchost.exe", @"Windows\System\spoolsv.exe",
            @"Windows\System\explorer.exe", @"Windows\System\icsys.icn.exe"
        };

        static readonly string[] ExecExt = { ".exe", ".scr", ".com", ".pif" };

        // Executável dentro de \Windows\Resources\... ou direto em \Windows\System\ (NÃO System32)
        static readonly Regex RxDropperFile = new Regex(
            @"^[A-Za-z]:\\Windows\\(?:Resources\\(?:[^\\]+\\)*[^\\]+|System\\[^\\]+)\.(?:exe|scr|com|pif)$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Referência a esses caminhos dentro de linhas de comando / registro / tarefas
        static readonly Regex RxRef = new Regex(
            @"\\Windows\\(?:Resources\\(?:[^\\""]+\\)*[^\\""]+|System\\[^\\""]+)\.(?:exe|scr|com|pif)\b|icsys\.icn\.exe|\\(?:ProgramData|Application Data)\\Synaptics\\Synaptics\.exe",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Pastas onde o Synaptics falso se instala (o driver verdadeiro do touchpad fica em Program Files)
        static readonly string[] SynapticsDirsRel = { @"ProgramData\Synaptics", @"Documents and Settings\All Users\Application Data\Synaptics" };

        static readonly byte[] SigA = Encoding.ASCII.GetBytes(V);
        static readonly byte[] SigW = Encoding.Unicode.GetBytes(V);
        const int Chunk = 1 << 20;            // 1 MB do fim de cada executável
        const int HeadChunk = 2 << 20;        // 2 MB do início (o Synaptics tem ~750 KB antes do original)
        const long FullReadMax = 256L << 20;  // arquivos de famílias conhecidas são lidos inteiros até 256 MB

        static readonly string[] RunKeys =
        {
            @"Microsoft\Windows\CurrentVersion\Run",
            @"Microsoft\Windows\CurrentVersion\RunOnce",
            @"Microsoft\Windows\CurrentVersion\RunServices",
            @"Microsoft\Windows\CurrentVersion\RunServicesOnce",
            @"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        };

        // ---- estado lido pela interface
        public readonly List<Finding> Findings = new List<Finding>();
        readonly HashSet<string> findingKeys = new HashSet<string>();
        public readonly ConcurrentQueue<LogEntry> LogQueue = new ConcurrentQueue<LogEntry>();
        public readonly ConcurrentQueue<Finding> NewFindings = new ConcurrentQueue<Finding>();
        public readonly ConcurrentQueue<Finding> ChangedFindings = new ConcurrentQueue<Finding>();
        public readonly List<LogEntry> FullLog = new List<LogEntry>();

        public string[] PhaseNames = new string[0];
        public int PhaseVersion;
        volatile int phaseIndex = -1;
        public int PhaseIndex { get { return phaseIndex; } }
        string currentItem = "";
        public string CurrentItem { get { return Volatile.Read(ref currentItem); } set { Volatile.Write(ref currentItem, value ?? ""); } }
        long filesDone, filesTotal;
        public long FilesDone { get { return Interlocked.Read(ref filesDone); } }
        public long FilesTotal { get { return Interlocked.Read(ref filesTotal); } }
        double overall;
        public double Overall { get { return Volatile.Read(ref overall); } }
        double[] weights = new double[0];
        double phaseFrac;

        public bool NeedReboot;
        public string LastSessionDir;

        readonly List<string> windowsRoots = new List<string>();
        readonly List<RegSource> regSources = new List<RegSource>();
        readonly List<string> loadedHives = new List<string>();
        readonly List<string> excludes = new List<string>();
        readonly HashSet<string> flagged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> reportedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly string selfPath;

        public Engine()
        {
            try { selfPath = Process.GetCurrentProcess().MainModule.FileName; } catch { selfPath = ""; }
        }

        public string QuarantineBase
        {
            get
            {
                return QuarantineBaseOverride ??
                       Path.Combine(Path.GetPathRoot(Environment.SystemDirectory), "Quarentena_" + V);
            }
        }

        // =====================================================================
        // utilidades
        // =====================================================================
        public void Log(string text, LogLevel lvl = LogLevel.Info)
        {
            var e = new LogEntry { Time = DateTime.Now, Text = text, Level = lvl };
            lock (FullLog) FullLog.Add(e);
            LogQueue.Enqueue(e);
        }

        static KeyValuePair<string, double> P(string n, double w) { return new KeyValuePair<string, double>(n, w); }

        void SetupPhases(List<KeyValuePair<string, double>> list)
        {
            weights = list.Select(k => k.Value).ToArray();
            PhaseNames = list.Select(k => k.Key).ToArray();
            phaseIndex = -1; phaseFrac = 0;
            Volatile.Write(ref overall, 0.0);
            Interlocked.Exchange(ref filesDone, 0);
            Interlocked.Exchange(ref filesTotal, 0);
            PhaseVersion++;
        }

        void Begin(int i)
        {
            phaseIndex = i; phaseFrac = 0; Recalc();
            Log(PhaseNames[i], LogLevel.Title);
        }

        void Frac(double f)
        {
            if (f < 0) f = 0; if (f > 1) f = 1;
            phaseFrac = f; Recalc();
        }

        void Recalc()
        {
            double total = weights.Sum(), done = 0;
            int pi = phaseIndex;
            for (int k = 0; k < pi && k < weights.Length; k++) done += weights[k];
            if (pi >= 0 && pi < weights.Length) done += weights[pi] * phaseFrac;
            Volatile.Write(ref overall, total > 0 ? done / total : 0);
        }

        void Complete() { phaseIndex = PhaseNames.Length; Volatile.Write(ref overall, 1.0); }

        static bool Eq(string a, string b) { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }
        static bool IsExec(string p) { string e = Path.GetExtension(p); return ExecExt.Any(x => Eq(x, e)); }
        static bool IsIcsys(string p) { return Eq(Path.GetFileName(p), "icsys.icn.exe"); }
        static string San(string s) { return Regex.Replace(s ?? "", @"[^A-Za-z0-9_\-\.]", "_"); }
        static string SysRoot() { return Path.GetPathRoot(Environment.SystemDirectory); }
        static string WithSlash(string p) { return p.EndsWith("\\") ? p : p + "\\"; }
        static string Trunc(string s, int n) { s = s ?? ""; return s.Length <= n ? s : s.Substring(0, n) + "…"; }

        static int RunTool(string exe, string args, out string output)
        {
            output = "";
            try
            {
                var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, exe), args)
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage),
                    StandardErrorEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage)
                };
                using (var p = Process.Start(psi))
                {
                    var err = p.StandardError.ReadToEndAsync();
                    string o = p.StandardOutput.ReadToEnd();
                    if (!p.WaitForExit(60000)) { try { p.Kill(); } catch { } output = "tempo esgotado"; return -1; }
                    output = (o + " " + err.Result).Trim();
                    return p.ExitCode;
                }
            }
            catch (Exception ex) { output = ex.Message; return -1; }
        }

        static RegistryKey OpenKey(string root, string path, bool writable)
        {
            try
            {
                using (var b = RegistryKey.OpenBaseKey(root == "HKLM" ? RegistryHive.LocalMachine : RegistryHive.Users, RegistryView.Registry64))
                    return b.OpenSubKey(path, writable);
            }
            catch { return null; }
        }

        static List<string> SafeDirs(string dir)
        {
            try { return Directory.GetDirectories(dir).ToList(); } catch { return new List<string>(); }
        }

        bool IsExcluded(string dir)
        {
            foreach (var x in excludes)
                if (dir.StartsWith(x, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        List<string> SafeFiles(string dir, bool recursive, CancellationToken ct)
        {
            var result = new List<string>();
            if (!Directory.Exists(dir)) return result;
            var stack = new Stack<string>();
            stack.Push(dir);
            while (stack.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                string d = stack.Pop();
                try { result.AddRange(Directory.GetFiles(d)); } catch { }
                if (!recursive) continue;
                try
                {
                    foreach (var sub in Directory.GetDirectories(d))
                    {
                        try { if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
                        if (!IsExcluded(sub)) stack.Push(sub);
                    }
                }
                catch { }
            }
            return result;
        }

        public static string Sha256(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (fs.Length > 512L * 1024 * 1024) return null;
                    using (var sha = SHA256.Create())
                        return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "");
                }
            }
            catch { return null; }
        }

        static bool IsSynapticsDropper(string p)
        {
            if (!Eq(Path.GetFileName(p), "Synaptics.exe")) return false;
            string dir = (Path.GetDirectoryName(p) ?? "").TrimEnd('\\');
            foreach (var rel in SynapticsDirsRel) if (dir.EndsWith("\\" + rel, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public bool IsDropperPath(string p)
        {
            if (string.IsNullOrEmpty(p)) return false;
            if (IsIcsys(p)) return true;
            if (!IsExec(p)) return false;
            if (RxDropperFile.IsMatch(p)) return true;
            if (IsSynapticsDropper(p)) return true;
            foreach (var r in windowsRoots)
            {
                if (p.StartsWith(r + @"Windows\Resources\", StringComparison.OrdinalIgnoreCase)) return true;
                if (Eq(Path.GetDirectoryName(p), r + @"Windows\System")) return true;
            }
            return false;
        }

        bool IsFlagged(string p) { lock (flagged) return flagged.Contains(p); }

        bool IsSuspiciousRef(string data)
        {
            if (string.IsNullOrEmpty(data)) return false;
            string ex = Environment.ExpandEnvironmentVariables(data);
            if (RxRef.IsMatch(data) || RxRef.IsMatch(ex)) return true;
            lock (flagged)
                foreach (var f in flagged)
                    if (ex.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        int ignored;

        bool IsAllowed(Finding f)
        {
            if (f.RegKey != null && Allowlist.IsRegAllowed(f.RegRoot, f.RegKey, f.RegValue)) return true;
            string p = f.FilePath ?? f.TaskFile;
            if (p == null) return false;
            if (Allowlist.IsPathAllowed(p)) return true;
            if (Allowlist.HasHashes && File.Exists(p) && Allowlist.IsHashAllowed(Sha256(p))) return true;
            return false;
        }

        bool AddFinding(Finding f)
        {
            if (f.Kind != FindingKind.Process && IsAllowed(f))
            {
                Interlocked.Increment(ref ignored);
                Log("Permitido (ignorado): " + f.Title, LogLevel.Info);
                return false;
            }
            lock (Findings)
            {
                if (!findingKeys.Add(f.Key)) return false;
                Findings.Add(f);
            }
            NewFindings.Enqueue(f);
            Log(string.Format("ENCONTRADO [{0}] {1}", f.KindText, f.Title),
                f.Severity == Severity.Info ? LogLevel.Warn : LogLevel.Error);
            return true;
        }

        void Changed(Finding f, string status, bool done)
        {
            f.Status = status; f.Done = done;
            if (done) f.Selected = false;
            ChangedFindings.Enqueue(f);
        }

        // =====================================================================
        // análise de arquivo
        // =====================================================================
        static int IndexOf(byte[] buf, int len, byte[] pat)
        {
            int last = len - pat.Length;
            int i = 0;
            while (i <= last)
            {
                i = Array.IndexOf(buf, pat[0], i, last - i + 1);
                if (i < 0) return -1;
                int j = 1;
                while (j < pat.Length && buf[i + j] == pat[j]) j++;
                if (j == pat.Length) return i;
                i++;
            }
            return -1;
        }

        static long FindEmbeddedPe(byte[] b, int len)
        {
            int i = 2;
            while (i < len - 0x40)
            {
                i = Array.IndexOf(b, (byte)'M', i, len - 0x40 - i);
                if (i < 0) return -1;
                if (b[i + 1] == (byte)'Z')
                {
                    int lf = BitConverter.ToInt32(b, i + 0x3C);
                    long pe = (long)i + lf;
                    if (lf >= 0x40 && lf <= 0x400 && pe + 4 <= len &&
                        b[pe] == 'P' && b[pe + 1] == 'E' && b[pe + 2] == 0 && b[pe + 3] == 0)
                        return i;
                }
                i++;
            }
            return -1;
        }

        static void ReadFull(Stream s, byte[] buf, int count)
        {
            int off = 0;
            while (off < count) { int n = s.Read(buf, off, count - off); if (n <= 0) break; off += n; }
        }

        public static FileScanResult ScanFile(string path)
        {
            var r = new FileScanResult();
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan))
                {
                    long len = fs.Length;
                    if (len < 64) return r;
                    int hl = (int)Math.Min(len, HeadChunk);
                    var head = new byte[hl];
                    ReadFull(fs, head, hl);
                    r.IsPE = head[0] == 'M' && head[1] == 'Z';
                    r.Signature = IndexOf(head, hl, SigA) >= 0 || IndexOf(head, hl, SigW) >= 0;
                    if (r.Signature && r.IsPE) r.EmbeddedPe = FindEmbeddedPe(head, hl);
                    byte[] tail = null;
                    if (len > HeadChunk)
                    {
                        long start = Math.Max(HeadChunk, len - Chunk);
                        fs.Seek(start, SeekOrigin.Begin);
                        int tl = (int)(len - start);
                        tail = new byte[tl];
                        ReadFull(fs, tail, tl);
                        if (!r.Signature && (IndexOf(tail, tl, SigA) >= 0 || IndexOf(tail, tl, SigW) >= 0))
                        {
                            r.Signature = true;
                            r.SignatureInTail = true;
                        }
                    }
                    if (r.IsPE)
                    {
                        r.Family = Families.Classify(head, hl);
                        if (r.Family == VirusFamily.None && tail != null) r.Family = Families.Classify(tail, tail.Length);
                        bool tjHost = r.Signature && r.Infected;
                        if ((r.Family != VirusFamily.None || tjHost) && len <= FullReadMax)
                        {
                            var all = new byte[len];
                            fs.Seek(0, SeekOrigin.Begin);
                            ReadFull(fs, all, (int)len);
                            r.Plan = r.Family != VirusFamily.None ? Families.Plan(path, all) : Families.PlanTJ(all);
                        }
                    }
                }
            }
            catch { }
            return r;
        }

        string BuildFileDetail(string path, string reason, FileScanResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine(reason);
            try
            {
                var fi = new FileInfo(path);
                sb.AppendFormat("Tamanho: {0:N0} bytes   ·   Modificado em {1:dd/MM/yyyy HH:mm}\r\n", fi.Length, fi.LastWriteTime);
                var a = fi.Attributes;
                bool h = (a & FileAttributes.Hidden) != 0, s = (a & FileAttributes.System) != 0;
                if (h || s) sb.AppendLine("Atributos: " + (h ? "oculto " : "") + (s ? "sistema " : "") + "(camuflagem típica do vírus)");
            }
            catch { }
            if (r != null && r.Signature) sb.AppendLine("Assinatura \"" + V + "\" encontrada no binário.");
            if (r != null && r.EmbeddedPe > 0) sb.AppendFormat("Há outro executável embutido no deslocamento 0x{0:X} (provavelmente o programa original).\r\n", r.EmbeddedPe);
            if (r != null && r.SignatureInTail) sb.AppendLine("O código do vírus está anexado ao final do programa.");
            if (r != null && r.Family != VirusFamily.None) sb.AppendLine("Família: " + Families.Name(r.Family) + " (assinatura reconhecida).");
            if (r != null && r.Plan != null && r.Plan.Note.Length > 0) sb.AppendLine(r.Plan.Note);
            if (r != null && r.Plan != null && r.Plan.CanRestore) sb.AppendLine("Na limpeza: o arquivo infectado vai para a quarentena e o programa ORIGINAL é restaurado no lugar (dá para desfazer).");
            string hash = Sha256(path);
            if (hash != null) sb.AppendLine("SHA256: " + hash);
            return sb.ToString().TrimEnd();
        }

        void ReportFile(string path, FindingKind kind, Severity sev, string reason, FileScanResult r)
        {
            if (Eq(path, selfPath)) return;
            if (Allowlist.IsPathAllowed(path) || (Allowlist.HasHashes && Allowlist.IsHashAllowed(Sha256(path))))
            {
                lock (reportedFiles) if (!reportedFiles.Add(path)) return;
                Interlocked.Increment(ref ignored);
                Log("Permitido (ignorado): " + path, LogLevel.Info);
                return;
            }
            lock (reportedFiles) if (!reportedFiles.Add(path)) return;
            if (r == null) r = ScanFile(path);
            lock (flagged) flagged.Add(path);
            var fam = r.Family != VirusFamily.None ? r.Family : (r.Signature ? VirusFamily.TJ : VirusFamily.None);
            if (fam == VirusFamily.None && IsDropperPath(path)) fam = IsSynapticsDropper(path) ? VirusFamily.SynapticsV1 : VirusFamily.TJ;
            AddFinding(new Finding
            {
                Kind = kind, Severity = sev, Title = path, FilePath = path, Family = fam,
                Disinfect = kind == FindingKind.InfectedFile && r.Plan != null && r.Plan.CanRestore,
                Detail = BuildFileDetail(path, reason, r)
            });
        }

        void ReportDropper(string path, string reason)
        {
            ReportFile(path, FindingKind.MaliciousFile, Severity.Critico, reason, null);
        }

        // =====================================================================
        // VARREDURA
        // =====================================================================
        public static List<KeyValuePair<string, double>> ScanPlan(ScanOptions o)
        {
            var ph = new List<KeyValuePair<string, double>> { P("Preparando o ambiente", 3) };
            if (o.SystemChecks)
            {
                ph.Add(P("Locais conhecidos do vírus", 6));
                ph.Add(P("Processos em execução", 4));
                ph.Add(P("Registro do Windows", 8));
                ph.Add(P("Serviços e tarefas agendadas", 5));
                if (o.Persistence)
                {
                    ph.Add(P("Inicialização e programas suspeitos", 8));
                    ph.Add(P("Segurança do Windows (Defender, hosts, proxy)", 3));
                }
            }
            if (o.Removable) ph.Add(P("Pendrives (autorun e vírus do atalho)", 3));
            if (o.DeepScan)
            {
                ph.Add(P(o.CustomFolder != null ? "Localizando executáveis na pasta" : "Localizando executáveis", 6));
                ph.Add(P("Varredura profunda (infectados)", 64));
            }
            if (o.DefenderConfirm) ph.Add(P("Confirmando com o Windows Defender", 8));
            if (o.SystemChecks) ph.Add(P("Verificação final", 2));
            return ph;
        }

        public void Scan(ScanOptions o, CancellationToken ct)
        {
            lock (Findings) { Findings.Clear(); findingKeys.Clear(); }
            lock (flagged) flagged.Clear();
            lock (reportedFiles) reportedFiles.Clear();
            NeedReboot = false;
            SetupPhases(ScanPlan(o));
            var sw = Stopwatch.StartNew();
            ignored = 0;
            Allowlist.Reload();
            Log("Nova varredura (" + o.ModeName + ") em " + Environment.MachineName + " (" + DateTime.Now.ToString("dd/MM/yyyy HH:mm") + ")", LogLevel.Title);
            int i = 0;
            try
            {
                Begin(i++); Safe(() => Prepare(o, ct));
                if (o.SystemChecks)
                {
                    Begin(i++); Safe(() => ScanKnownLocations(ct));
                    Begin(i++); Safe(() => ScanProcesses(ct, false));
                    Begin(i++); Safe(() => ScanRegistry(ct));
                    Begin(i++); Safe(() => ScanServicesAndTasks(ct));
                    if (o.Persistence)
                    {
                        Begin(i++); Safe(() => ScanPersistence(ct));
                        Begin(i++); Safe(() => ScanWindowsSecurity(ct));
                    }
                }
                if (o.Removable) { Begin(i++); Safe(() => ScanRemovable(o, ct)); }
                if (o.DeepScan)
                {
                    List<string> files = new List<string>();
                    Begin(i++); Safe(() => { files = EnumerateTargets(o, ct); });
                    Begin(i++); Safe(() => DeepScan(files, ct));
                }
                if (o.DefenderConfirm) { Begin(i++); Safe(() => DefenderConfirm(ct)); }
                if (o.SystemChecks) { Begin(i++); Safe(() => ScanProcesses(ct, true)); }
                if (ignored > 0) Log(ignored + " item(ns) ignorado(s) por estarem na lista de Permitidos.", LogLevel.Info);
                Complete();
                int threats, warns;
                lock (Findings)
                {
                    threats = Findings.Count(f => f.Severity != Severity.Info);
                    warns = Findings.Count - threats;
                }
                CurrentItem = "";
                Log(string.Format("Varredura concluída em {0:mm\\:ss}: {1} ameaça(s), {2} aviso(s).", sw.Elapsed, threats, warns),
                    threats > 0 ? LogLevel.Error : LogLevel.Ok);
            }
            catch (OperationCanceledException) { Log("Varredura cancelada pelo usuário.", LogLevel.Warn); }
            catch (Exception ex) { Log("Erro inesperado na varredura: " + ex, LogLevel.Error); }
        }

        // Um erro numa etapa não pode derrubar a varredura inteira
        void Safe(Action a)
        {
            try { a(); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                var ae = ex as AggregateException;
                if (ae != null && ae.InnerExceptions.All(x => x is OperationCanceledException)) throw new OperationCanceledException();
                Log("Erro nesta etapa (as demais continuam): " + ex.GetType().Name + " — " + ex.Message, LogLevel.Error);
            }
        }

        void Prepare(ScanOptions o, CancellationToken ct)
        {
            UnloadHives();
            windowsRoots.Clear();
            excludes.Clear();
            excludes.Add(QuarantineBase);
            if (TestRoot != null)
                windowsRoots.Add(WithSlash(TestRoot));
            else
            {
                foreach (var d in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (!d.IsReady || (d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable)) continue;
                        string r = d.RootDirectory.FullName;
                        excludes.Add(r + "System Volume Information");
                        excludes.Add(r + @"Windows\WinSxS");
                        excludes.Add(r + @"Windows\servicing");
                        if (Directory.Exists(r + "Windows")) windowsRoots.Add(r);
                    }
                    catch { }
                }
            }
            Log("Unidades com Windows: " + string.Join("  ", windowsRoots));
            Frac(0.3);
            if (o.Offline && TestRoot == null) LoadOfflineHives(ct);
            Frac(0.85);
            BuildRegSources();
            Log(string.Format("{0} áreas de registro serão analisadas.", regSources.Count));
        }

        // ---------------------------------------------------------------- hives
        bool LoadHive(string key, string file)
        {
            string outp;
            int rc = RunTool("reg.exe", "load \"" + key + "\" \"" + file + "\"", out outp);
            if (rc == 0) { loadedHives.Add(key); Log("Registro offline carregado: " + file, LogLevel.Ok); return true; }
            Log("Não foi possível carregar " + file + ": " + outp, LogLevel.Warn);
            return false;
        }

        public void UnloadHives()
        {
            if (loadedHives.Count == 0) return;
            for (int i = loadedHives.Count - 1; i >= 0; i--)
            {
                string outp; int rc = -1;
                for (int t = 0; t < 3 && rc != 0; t++)
                {
                    GC.Collect(); GC.WaitForPendingFinalizers();
                    rc = RunTool("reg.exe", "unload \"" + loadedHives[i] + "\"", out outp);
                    if (rc != 0) Thread.Sleep(400);
                }
                if (rc != 0) Log("Aviso: não consegui descarregar " + loadedHives[i] + " (será liberado no reinício).", LogLevel.Warn);
            }
            loadedHives.Clear();
        }

        void LoadOfflineHives(CancellationToken ct)
        {
            // perfis deste Windows que não estão logados
            try
            {
                using (var pl = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
                {
                    if (pl != null)
                        foreach (var sid in pl.GetSubKeyNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            if (!sid.StartsWith("S-1-5-21-")) continue;
                            string dir;
                            using (var k = pl.OpenSubKey(sid))
                                dir = k == null ? null : Environment.ExpandEnvironmentVariables(Convert.ToString(k.GetValue("ProfileImagePath")));
                            if (string.IsNullOrEmpty(dir)) continue;
                            bool loaded;
                            using (var u = Registry.Users.OpenSubKey(sid)) loaded = u != null;
                            if (loaded) continue;
                            string nt = Path.Combine(dir, "NTUSER.DAT");
                            if (File.Exists(nt)) LoadHive(@"HKU\TJU_" + San(Path.GetFileName(dir)), nt);
                        }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log("Perfis offline: " + ex.Message, LogLevel.Warn); }

            // Windows instalados em outros discos (ex.: HD de outro PC ligado nesta máquina)
            foreach (var root in windowsRoots)
            {
                if (Eq(root, SysRoot())) continue;
                string L = root.Substring(0, 1).ToUpperInvariant();
                string soft = Path.Combine(root, @"Windows\System32\config\SOFTWARE");
                if (File.Exists(soft)) LoadHive(@"HKLM\TJM_" + L, soft);
                foreach (var ud in SafeDirs(Path.Combine(root, "Users")))
                {
                    string nt = Path.Combine(ud, "NTUSER.DAT");
                    if (File.Exists(nt)) LoadHive(@"HKU\TJU_" + L + "_" + San(Path.GetFileName(ud)), nt);
                }
            }
        }

        static string UserLabel(string sub)
        {
            if (sub.StartsWith("TJU_")) return "Perfil offline " + sub.Substring(4);
            if (sub == ".DEFAULT") return "Usuário padrão";
            if (sub == "S-1-5-18") return "SYSTEM";
            if (sub == "S-1-5-19") return "Serviço local";
            if (sub == "S-1-5-20") return "Serviço de rede";
            try { return new SecurityIdentifier(sub).Translate(typeof(NTAccount)).Value; } catch { return sub; }
        }

        void BuildRegSources()
        {
            regSources.Clear();
            regSources.Add(new RegSource { Root = "HKLM", Prefix = "SOFTWARE", Machine = true, Online = true, Label = "Máquina" });
            regSources.Add(new RegSource { Root = "HKLM", Prefix = @"SOFTWARE\WOW6432Node", Machine = true, Online = true, Wow = true, Label = "Máquina (32 bits)" });
            foreach (var key in loadedHives.Where(k => k.StartsWith(@"HKLM\TJM_")))
            {
                string name = key.Substring(5);
                string lbl = "Windows offline " + name.Substring(4) + ":";
                regSources.Add(new RegSource { Root = "HKLM", Prefix = name, Machine = true, Label = lbl });
                regSources.Add(new RegSource { Root = "HKLM", Prefix = name + @"\WOW6432Node", Machine = true, Wow = true, Label = lbl + " (32 bits)" });
            }
            try
            {
                using (var hku = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64))
                    foreach (var sub in hku.GetSubKeyNames())
                    {
                        if (sub.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
                        regSources.Add(new RegSource { Root = "HKU", Prefix = sub + @"\Software", Online = !sub.StartsWith("TJU_"), Label = UserLabel(sub) });
                    }
            }
            catch { }
        }

        // ---------------------------------------------------------------- 1. locais conhecidos
        void ScanKnownLocations(CancellationToken ct)
        {
            int before = Findings.Count;
            var dirs = new List<KeyValuePair<string, bool>>();
            var temps = new List<string>();
            foreach (var r in windowsRoots)
            {
                dirs.Add(new KeyValuePair<string, bool>(r + @"Windows\Resources", true));
                dirs.Add(new KeyValuePair<string, bool>(r + @"Windows\System", false));
                temps.Add(r + @"Windows\Temp");
                foreach (var ud in SafeDirs(r + "Users")) temps.Add(Path.Combine(ud, @"AppData\Local\Temp"));
            }
            var synDirs = new List<string>();
            foreach (var r in windowsRoots) foreach (var rel in SynapticsDirsRel) synDirs.Add(r + rel);
            int total = dirs.Count + temps.Count + synDirs.Count, n = 0;
            foreach (var sd in synDirs)
            {
                CurrentItem = sd;
                foreach (var f in SafeFiles(sd, true, ct))
                {
                    if (!IsExec(f)) continue;
                    var fr = ScanFile(f);
                    if (IsSynapticsDropper(f) || fr.Family == VirusFamily.SynapticsV1 || fr.Family == VirusFamily.SynapticsV2)
                        ReportFile(f, FindingKind.MaliciousFile, Severity.Critico,
                            "Synaptics falso: o vírus se instala nesta pasta fingindo ser o driver do touchpad (o driver verdadeiro fica em Program Files).", fr);
                }
                Frac(++n / (double)total);
            }
            foreach (var d in dirs)
            {
                CurrentItem = d.Key;
                foreach (var f in SafeFiles(d.Key, d.Value, ct))
                    if (IsExec(f) || IsIcsys(f))
                        ReportDropper(f, "Executável escondido numa pasta onde o Windows não guarda programas.");
                Frac(++n / (double)total);
            }
            foreach (var t in temps)
            {
                CurrentItem = t;
                foreach (var f in SafeFiles(t, true, ct))
                    if (IsIcsys(f)) ReportDropper(f, "Cópia do icsys.icn.exe (componente do " + V + ") em pasta temporária.");
                Frac(++n / (double)total);
            }
            if (Findings.Count == before) Log("Nenhum arquivo do vírus nos locais conhecidos.", LogLevel.Ok);
        }

        // ---------------------------------------------------------------- 2. processos
        void ScanProcesses(CancellationToken ct, bool final)
        {
            var procs = Process.GetProcesses();
            int n = 0, hits = 0;
            foreach (var p in procs)
            {
                ct.ThrowIfCancellationRequested();
                int pid = p.Id;
                p.Dispose();
                Frac(++n / (double)procs.Length);
                string path = Native.GetProcessPath(pid);
                if (path == null) continue;
                CurrentItem = path;
                bool dropper = IsDropperPath(path);
                if (!dropper && !IsFlagged(path)) continue;
                if (dropper) ReportDropper(path, "Executável de um processo malicioso em execução.");
                bool infectedHost;
                lock (Findings) infectedHost = Findings.Any(f => f.Kind == FindingKind.InfectedFile && Eq(f.FilePath, path));
                if (AddFinding(new Finding
                {
                    Kind = FindingKind.Process, Severity = Severity.Critico, Pid = pid, FilePath = path,
                    Title = string.Format("{0} (PID {1})", Path.GetFileName(path), pid),
                    Detail = (infectedHost ? "Programa infectado em execução — o vírus está ativo dentro dele." :
                              IsSynapticsDropper(path) ? "Synaptics falso em execução." : "Componente do vírus em execução.") +
                             "\r\nExecutável: " + path +
                             "\r\nSerá congelado e encerrado antes da remoção (os componentes se relançam entre si)."
                })) hits++;
            }
            if (!final && hits == 0) Log("Nenhum processo do vírus em execução.", LogLevel.Ok);
        }

        // ---------------------------------------------------------------- 3. registro
        Finding RegFinding(RegSource s, string keyPath, string name, string data, RegAction act, string newVal, string what, Severity sev)
        {
            string full = s.Root + "\\" + keyPath;
            return new Finding
            {
                Kind = FindingKind.Registry, Severity = sev, RegRoot = s.Root, RegKey = keyPath, RegValue = name,
                RegAct = act, RegNewValue = newVal,
                Title = string.Format("{0}: {1} → \"{2}\"", s.Label, what, name),
                Detail = string.Format("{0}\r\nChave: {1}\r\nValor: {2} = {3}\r\nAção: {4}", what, full, name, data,
                    act == RegAction.DeleteValue ? "remover o valor" : "restaurar para \"" + newVal + "\"")
            };
        }

        static string ReadStr(RegistryKey k, string name)
        {
            try { return Convert.ToString(k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)); }
            catch { return null; }
        }

        void ScanRegistry(CancellationToken ct)
        {
            int before = Findings.Count, n = 0;
            foreach (var s in regSources)
            {
                ct.ThrowIfCancellationRequested();
                CurrentItem = s.Root + "\\" + s.Prefix;
                Frac(n++ / (double)regSources.Count);
                try { ScanRegSource(s); }
                catch (Exception ex) { Log("Sem acesso a parte do registro de " + s.Label + ": " + ex.Message, LogLevel.Warn); }
            }
            if (Findings.Count == before) Log("Registro limpo: nenhuma entrada do vírus.", LogLevel.Ok);
        }

        void ScanRegSource(RegSource s)
        {
                foreach (var rk in RunKeys)
                {
                    string kp = s.Prefix + "\\" + rk;
                    using (var k = OpenKey(s.Root, kp, false))
                    {
                        if (k == null) continue;
                        foreach (var name in k.GetValueNames())
                        {
                            if (name.Length == 0) continue;
                            string data = ReadStr(k, name);
                            if (IsSuspiciousRef(data))
                                AddFinding(RegFinding(s, kp, name, data, RegAction.DeleteValue, null,
                                    "Inicialização automática (" + rk.Substring(rk.LastIndexOf('\\') + 1) + ")", Severity.Alto));
                        }
                    }
                }
                if (s.Wow) return;

                // Winlogon: Shell / Userinit
                string wl = s.Prefix + @"\Microsoft\Windows NT\CurrentVersion\Winlogon";
                using (var k = OpenKey(s.Root, wl, false))
                    if (k != null)
                        foreach (var name in new[] { "Shell", "Userinit" })
                        {
                            string data = ReadStr(k, name);
                            if (!IsSuspiciousRef(data)) continue;
                            if (s.Machine)
                            {
                                string def = name == "Shell" ? "explorer.exe"
                                    : (s.Online ? Environment.SystemDirectory : @"C:\Windows\system32") + @"\userinit.exe,";
                                AddFinding(RegFinding(s, wl, name, data, RegAction.SetValue, def, "Winlogon sequestrado", Severity.Critico));
                            }
                            else AddFinding(RegFinding(s, wl, name, data, RegAction.DeleteValue, null, "Winlogon do usuário sequestrado", Severity.Critico));
                        }

                // Windows\Load / Run (inicialização antiga)
                string wk = s.Prefix + @"\Microsoft\Windows NT\CurrentVersion\Windows";
                using (var k = OpenKey(s.Root, wk, false))
                    if (k != null)
                        foreach (var name in new[] { "Load", "Run" })
                        {
                            string data = ReadStr(k, name);
                            if (IsSuspiciousRef(data))
                                AddFinding(RegFinding(s, wk, name, data, RegAction.DeleteValue, null, "Inicialização antiga (Windows\\" + name + ")", Severity.Alto));
                        }

                // Image File Execution Options (Debugger)
                if (s.Machine)
                {
                    string ifeo = s.Prefix + @"\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
                    using (var k = OpenKey(s.Root, ifeo, false))
                        if (k != null)
                            foreach (var sub in k.GetSubKeyNames())
                            {
                                RegistryKey sk = null;
                                try { sk = k.OpenSubKey(sub); } catch { }
                                if (sk == null) continue;
                                using (sk)
                                {
                                    string data = ReadStr(sk, "Debugger");
                                    if (IsSuspiciousRef(data))
                                        AddFinding(RegFinding(s, ifeo + "\\" + sub, "Debugger", data, RegAction.DeleteValue, null,
                                            "Sequestro de programa (IFEO " + sub + ")", Severity.Critico));
                                }
                            }
                }

                CheckPolicies(s);
        }

        void CheckPolicies(RegSource s)
        {
            var list = new[]
            {
                new[] { @"Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", "bloqueia o Gerenciador de Tarefas" },
                new[] { @"Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", "bloqueia o Editor do Registro" },
                new[] { @"Policies\Microsoft\Windows\System", "DisableCMD", "bloqueia o Prompt de Comando" },
                new[] { @"Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoFolderOptions", "esconde as Opções de Pasta" }
            };
            foreach (var p in list)
            {
                string kp = s.Prefix + "\\" + p[0];
                using (var k = OpenKey(s.Root, kp, false))
                {
                    if (k == null) continue;
                    object v = k.GetValue(p[1]);
                    long num = 0;
                    try { num = Convert.ToInt64(v); } catch { }
                    if (v == null || num == 0) continue;
                    var f = RegFinding(s, kp, p[1], Convert.ToString(v), RegAction.DeleteValue, null, "Política que " + p[2], Severity.Info);
                    f.Kind = FindingKind.Policy;
                    f.Selected = false;
                    f.Detail += "\r\nVírus costumam ativar isso. Em PC de empresa pode ser intencional — por isso vem desmarcado.";
                    AddFinding(f);
                }
            }
        }

        // ---------------------------------------------------------------- 4. serviços e tarefas
        static string ExtractCommand(string xml)
        {
            var m1 = Regex.Match(xml, @"<Command>(.*?)</Command>", RegexOptions.Singleline);
            var m2 = Regex.Match(xml, @"<Arguments>(.*?)</Arguments>", RegexOptions.Singleline);
            return (m1.Success ? m1.Groups[1].Value : "?") + (m2.Success ? " " + m2.Groups[1].Value : "");
        }

        void ScanServicesAndTasks(CancellationToken ct)
        {
            int before = Findings.Count;
            if (TestRoot == null)
                using (var svc = OpenKey("HKLM", @"SYSTEM\CurrentControlSet\Services", false))
                    if (svc != null)
                    {
                        var names = svc.GetSubKeyNames();
                        for (int i = 0; i < names.Length; i++)
                        {
                            ct.ThrowIfCancellationRequested();
                            if ((i & 31) == 0) Frac(0.4 * i / names.Length);
                            RegistryKey sk = null;
                            try { sk = svc.OpenSubKey(names[i]); } catch { }
                            if (sk == null) continue;
                            using (var k = sk)
                            {
                                string ip = ReadStr(k, "ImagePath");
                                if (!IsSuspiciousRef(ip)) continue;
                                CurrentItem = names[i];
                                AddFinding(new Finding
                                {
                                    Kind = FindingKind.Service, Severity = Severity.Critico, ServiceName = names[i],
                                    Title = "Serviço \"" + names[i] + "\"",
                                    Detail = "Serviço do Windows que inicia um componente do vírus.\r\nExecutável: " + ip +
                                             "\r\nAção: parar e excluir o serviço (com backup .reg)."
                                });
                            }
                        }
                    }
            Frac(0.4);

            int rn = 0;
            foreach (var r in windowsRoots)
            {
                bool online = TestRoot == null && Eq(r, SysRoot());
                string tdir = r + @"Windows\System32\Tasks";
                foreach (var f in SafeFiles(tdir, true, ct))
                {
                    CurrentItem = f;
                    string txt;
                    try { txt = File.ReadAllText(f); } catch { continue; }
                    if (!IsSuspiciousRef(txt)) continue;
                    string tn = "\\" + f.Substring(tdir.Length).TrimStart('\\');
                    AddFinding(new Finding
                    {
                        Kind = FindingKind.Task, Severity = Severity.Critico, TaskFile = f, TaskName = online ? tn : null,
                        Title = (online ? "Tarefa " : "Tarefa (Windows offline) ") + tn,
                        Detail = "Tarefa agendada que executa um componente do vírus.\r\nArquivo: " + f + "\r\nComando: " + ExtractCommand(txt)
                    });
                }
                // jobs antigos criados com o comando AT (técnica usada pelo vírus)
                foreach (var f in SafeFiles(r + @"Windows\Tasks", false, ct))
                {
                    if (!Eq(Path.GetExtension(f), ".job")) continue;
                    string txt;
                    try { txt = Encoding.Unicode.GetString(File.ReadAllBytes(f)); } catch { continue; }
                    if (!IsSuspiciousRef(txt)) continue;
                    AddFinding(new Finding
                    {
                        Kind = FindingKind.Task, Severity = Severity.Critico, TaskFile = f,
                        Title = "Job do comando AT: " + Path.GetFileName(f),
                        Detail = "Job agendado (comando AT) que executa o vírus em horários fixos.\r\nArquivo: " + f
                    });
                }
                Frac(0.4 + 0.6 * ++rn / Math.Max(1, windowsRoots.Count));
            }
            if (Findings.Count == before) Log("Nenhum serviço ou tarefa do vírus.", LogLevel.Ok);
        }

        // ---------------------------------------------------------------- 5. pendrives
        public static bool IsRemovableRoot(string p)
        {
            if (string.IsNullOrEmpty(p)) return false;
            if (TestRemovableRoots != null) return TestRemovableRoots.Any(x => Eq(WithSlash(x), WithSlash(p)));
            try
            {
                string root = Path.GetPathRoot(p);
                return Eq(WithSlash(p), root) && new DriveInfo(root).DriveType == DriveType.Removable;
            }
            catch { return false; }
        }

        List<string> RemovableRoots(ScanOptions o)
        {
            if (o.CustomFolder != null) return IsRemovableRoot(o.CustomFolder) ? new List<string> { WithSlash(o.CustomFolder) } : new List<string>();
            if (TestRemovableRoots != null) return TestRemovableRoots.Select(WithSlash).ToList();
            var l = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
                try { if (d.IsReady && d.DriveType == DriveType.Removable) l.Add(d.RootDirectory.FullName); } catch { }
            return l;
        }

        void ScanRemovable(ScanOptions o, CancellationToken ct)
        {
            int before = Findings.Count;
            var roots = RemovableRoots(o);
            int n = 0;
            foreach (var root in roots)
            {
                ct.ThrowIfCancellationRequested();
                Safe(() => ScanUsbWorm(root, ct));
                Frac(++n / (double)Math.Max(1, roots.Count) * 0.8);
                string inf = Path.Combine(root, "autorun.inf");
                CurrentItem = inf;
                if (!File.Exists(inf)) continue;
                string txt = "";
                try { txt = File.ReadAllText(inf); } catch { }
                if (!Regex.IsMatch(txt, @"(?im)^\s*(open|shellexecute|shell\\)")) continue;
                AddFinding(new Finding
                {
                    Kind = FindingKind.Autorun, Severity = Severity.Alto, FilePath = inf, Title = inf,
                    Detail = "autorun.inf que executa um programa ao conectar o pendrive (técnica de propagação).\r\nConteúdo:\r\n" + Trunc(txt, 600)
                });
            }
            Frac(1);
            if (roots.Count == 0) Log("Nenhum pendrive conectado.", LogLevel.Info);
            else if (Findings.Count == before) Log("Pendrive(s) limpo(s): sem autorun.inf perigoso nem vírus do atalho.", LogLevel.Ok);
        }

        // ---------------------------------------------------------------- 6. varredura profunda
        List<string> EnumerateTargets(ScanOptions o, CancellationToken ct)
        {
            var roots = new List<string>();
            if (o.CustomFolder != null) roots.Add(o.CustomFolder);
            else if (TestRoot != null) roots.Add(TestRoot);
            else
                foreach (var d in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (!d.IsReady) continue;
                        string r = d.RootDirectory.FullName;
                        if (d.DriveType == DriveType.Fixed)
                        {
                            if (o.WholeDisk) roots.Add(r);
                            else
                                foreach (var sub in new[] { "Program Files", "Program Files (x86)", "ProgramData", "Users", @"Windows\Temp" })
                                    if (Directory.Exists(r + sub)) roots.Add(r + sub);
                        }
                        else if (d.DriveType == DriveType.Removable && o.Removable) roots.Add(r);
                    }
                    catch { }
                }
            Log("Áreas analisadas: " + string.Join("  |  ", roots));

            var list = new List<string>();
            long dirs = 0;
            var stack = new Stack<string>();
            foreach (var root in roots) stack.Push(root);
            while (stack.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                string d = stack.Pop();
                dirs++;
                if ((dirs & 63) == 0) { CurrentItem = d; Frac(dirs / (dirs + 4000.0)); }
                try
                {
                    foreach (var f in Directory.EnumerateFiles(d))
                        if (IsExec(f))
                        {
                            list.Add(f);
                            Interlocked.Increment(ref filesTotal);
                        }
                }
                catch { }
                try
                {
                    foreach (var sub in Directory.EnumerateDirectories(d))
                    {
                        try { if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
                        if (!IsExcluded(sub)) stack.Push(sub);
                    }
                }
                catch { }
            }
            Frac(1);
            Log(string.Format("{0:N0} executáveis encontrados em {1:N0} pastas.", list.Count, dirs));
            return list;
        }

        void DeepScan(List<string> files, CancellationToken ct)
        {
            long total = files.Count;
            Interlocked.Exchange(ref filesTotal, total);
            Interlocked.Exchange(ref filesDone, 0);
            if (total == 0) { Frac(1); return; }
            int before = Findings.Count;
            var po = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(2, Math.Min(4, Environment.ProcessorCount)), CancellationToken = ct };
            Parallel.ForEach(files, po, f =>
            {
                try
                {
                    bool skip;
                    lock (reportedFiles) skip = reportedFiles.Contains(f);
                    if (!skip && !Eq(f, selfPath))
                    {
                        CurrentItem = f;
                        var r = ScanFile(f);
                        if (IsIcsys(f) || IsDropperPath(f))
                            ReportFile(f, FindingKind.MaliciousFile, Severity.Critico, "Componente do vírus (nome/local conhecido).", r);
                        else if (r.Family != VirusFamily.None)
                        {
                            string fam = Families.Name(r.Family);
                            if (r.Plan != null && r.Plan.CanRestore)
                                ReportFile(f, FindingKind.InfectedFile, Severity.Alto,
                                    "Programa infectado pelo " + fam + ". O programa original foi localizado dentro dele e será recuperado.", r);
                            else if (r.Plan == null)
                                ReportFile(f, FindingKind.InfectedFile, Severity.Alto,
                                    "Programa infectado pelo " + fam + " (grande demais para recuperar o original automaticamente: vai para a quarentena).", r);
                            else
                                ReportFile(f, FindingKind.MaliciousFile, Severity.Critico, "Cópia do " + fam + " (o próprio vírus).", r);
                        }
                        else if (r.Signature && r.Infected && r.Plan != null && r.Plan.CanRestore)
                            ReportFile(f, FindingKind.InfectedFile, Severity.Alto,
                                "Programa infectado pelo " + V + ". O programa original foi localizado dentro dele e será recuperado.", r);
                        else if (r.Signature && r.Infected)
                            ReportFile(f, FindingKind.InfectedFile, Severity.Alto,
                                "Programa infectado: o código do " + V + " foi inserido neste executável. Depois da limpeza, reinstale este programa.", r);
                        else if (r.Signature)
                            ReportFile(f, FindingKind.MaliciousFile, Severity.Critico,
                                "Cópia do vírus com outro nome (assinatura encontrada e nenhum programa original embutido).", r);
                    }
                }
                catch { }
                long d = Interlocked.Increment(ref filesDone);
                if ((d & 7) == 0 || d == total) Frac(d / (double)total);
            });
            if (Findings.Count == before) Log("Nenhum executável infectado.", LogLevel.Ok);
        }
    }
}
