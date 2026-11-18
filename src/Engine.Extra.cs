using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace TJRemover
{
    /// <summary>
    /// Detecções genéricas (não dependem de assinatura de uma família):
    /// persistência suspeita, configurações de segurança do Windows adulteradas, vírus do atalho em
    /// pendrive, sinais de ransomware e confirmação pelo Windows Defender.
    /// </summary>
    public partial class Engine
    {
        public static string[] TestRemovableRoots;   // testes: pastas tratadas como pendrive

        static readonly string[] ScriptExt = { ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1" };
        static readonly string[] Lolbins = { "wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe" };

        static bool IsScript(string p) { string e = Path.GetExtension(p); return ScriptExt.Any(x => Eq(x, e)); }

        // locais graváveis pelo usuário, onde programas legítimos raramente ficam sem assinatura digital
        static readonly Regex RxUserLoc = new Regex(
            @"\\AppData\\|\\Local Settings\\|\\Temp\\|\\Users\\Public\\|\\\$Recycle\.Bin\\|\\RECYCLER\\|\\ProgramData\\[^\\]+(?:\\[^\\]+)?$|\\Windows\\Temp\\|\\Downloads\\[^\\]+$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        static readonly Regex RxEncodedPs = new Regex(@"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|-w(indowstyle)?\s+hid|downloadstring|iex\s*\(|invoke-expression|frombase64string",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>Executável/script referenciado por uma linha de comando (aceita aspas, variáveis e lolbins).</summary>
        static List<string> CommandTargets(string cmd)
        {
            var res = new List<string>();
            if (string.IsNullOrWhiteSpace(cmd)) return res;
            string c = Environment.ExpandEnvironmentVariables(cmd.Trim());
            string first;
            if (c.StartsWith("\"")) { int q = c.IndexOf('"', 1); first = q > 0 ? c.Substring(1, q - 1) : c.Trim('"'); }
            else
            {
                var m = Regex.Match(c, @"^.+?\.(exe|com|scr|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|lnk)\b", RegexOptions.IgnoreCase);
                first = m.Success ? m.Value : c.Split(' ')[0];
            }
            res.Add(first);
            string fn = Path.GetFileName(first);
            if (Lolbins.Any(x => Eq(x, fn)) || !first.Contains("\\"))
                foreach (Match m in Regex.Matches(c, @"[A-Za-z]:\\[^""<>|*?\r\n]+?\.(vbs|vbe|js|jse|wsf|hta|ps1|bat|cmd|dll|exe|scr)\b", RegexOptions.IgnoreCase))
                    if (!Eq(m.Value, first)) res.Add(m.Value);
            return res;
        }

        /// <summary>Motivo para considerar o arquivo suspeito, ou null.</summary>
        string Suspicion(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path) || Eq(path, selfPath)) return null;
                if (Allowlist.IsPathAllowed(path) || (Allowlist.HasHashes && Allowlist.IsHashAllowed(Sha256(path)))) return null;
                if (IsScript(path)) return RxUserLoc.IsMatch(path) || path.IndexOf(@"\Start Menu\", StringComparison.OrdinalIgnoreCase) >= 0
                    ? "Script iniciado automaticamente a partir de uma pasta de usuário (técnica comum de vírus)." : null;
                if (!IsExec(path) && !Eq(Path.GetExtension(path), ".dll")) return null;
                if (!RxUserLoc.IsMatch(path)) return null;
                if (Native.IsSigned(path)) return null;
                return "Executável SEM assinatura digital iniciando de uma pasta de usuário (AppData/Temp/ProgramData). " +
                       "É onde ladrões de senha, mineradores e acesso remoto costumam se instalar.";
            }
            catch { return null; }
        }

        void ReportSuspicious(string path, string reason, string origin)
        {
            if (Eq(path, selfPath) || Allowlist.IsPathAllowed(path)) return;
            lock (reportedFiles) if (reportedFiles.Contains(path)) return;
            var r = ScanFile(path);
            if (r.Family != VirusFamily.None || r.Signature) { ReportFile(path, FindingKind.MaliciousFile, Severity.Critico, "Componente de vírus conhecido (" + origin + ").", r); return; }
            lock (reportedFiles) if (!reportedFiles.Add(path)) return;
            AddFinding(new Finding
            {
                Kind = FindingKind.Suspicious, Severity = Severity.Medio, Selected = false, FilePath = path, Title = path,
                Detail = BuildFileDetail(path, reason + "\r\nOrigem: " + origin +
                    "\r\nVem DESMARCADO: confira antes de remover. Se for um programa seu, use \"Permitir\" (botão direito).", r)
            });
        }

        // =====================================================================
        // inicialização e programas suspeitos
        // =====================================================================
        void ScanPersistence(CancellationToken ct)
        {
            int before = Findings.Count, n = 0;
            // 1. Run / RunOnce de todas as fontes de registro
            foreach (var s in regSources)
            {
                ct.ThrowIfCancellationRequested();
                Frac(0.35 * n++ / Math.Max(1, regSources.Count));
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
                            if (string.IsNullOrEmpty(data) || IsSuspiciousRef(data)) continue;   // conhecidos já foram tratados
                            CurrentItem = s.Root + "\\" + kp + " → " + name;
                            bool enc = RxEncodedPs.IsMatch(data);
                            string why = null, target = null;
                            foreach (var t in CommandTargets(data)) { why = Suspicion(t); if (why != null) { target = t; break; } }
                            if (why == null && !enc) continue;
                            var f = RegFinding(s, kp, name, data, RegAction.DeleteValue, null,
                                enc ? "Inicialização com PowerShell oculto/codificado" : "Inicialização de programa suspeito", enc ? Severity.Alto : Severity.Medio);
                            f.Selected = enc;
                            f.Detail += "\r\n" + (enc ? "Comando PowerShell escondido ou codificado na inicialização (técnica de vírus)." : why);
                            AddFinding(f);
                            if (target != null) ReportSuspicious(target, why, "inicialização " + s.Label + " → " + name);
                        }
                    }
                }
            }

            // 2. pastas Inicializar (de todos os usuários e do sistema)
            var startups = new List<string>();
            foreach (var r in windowsRoots)
            {
                startups.Add(r + @"ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp");
                foreach (var ud in SafeDirs(r + "Users")) startups.Add(Path.Combine(ud, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
            }
            foreach (var sd in startups)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var f in SafeFiles(sd, false, ct))
                {
                    CurrentItem = f;
                    string ext = Path.GetExtension(f).ToLowerInvariant();
                    if (ext == ".ini") continue;
                    if (ext == ".lnk")
                    {
                        string target, args;
                        if (!ResolveLnk(f, out target, out args)) continue;
                        foreach (var t in CommandTargets("\"" + target + "\" " + args))
                        {
                            string why = Suspicion(t);
                            if (why != null || RxEncodedPs.IsMatch(args ?? ""))
                            {
                                ReportSuspicious(f, (why ?? "Atalho com PowerShell oculto/codificado.") + "\r\nO atalho na pasta Inicializar aponta para: " + target + " " + args, "pasta Inicializar");
                                if (why != null) ReportSuspicious(t, why, "atalho " + Path.GetFileName(f));
                                break;
                            }
                        }
                    }
                    else if (IsScript(f) || ext == ".bat" || ext == ".cmd" || IsExec(f))
                    {
                        string why = IsExec(f) && Native.IsSigned(f) ? null : "Arquivo executável/script direto na pasta Inicializar: roda a cada login.";
                        if (why != null) ReportSuspicious(f, why, "pasta Inicializar");
                    }
                }
            }
            Frac(0.55);

            // 3. tarefas agendadas que rodam programa suspeito
            foreach (var r in windowsRoots)
            {
                string tdir = r + @"Windows\System32\Tasks";
                foreach (var f in SafeFiles(tdir, true, ct))
                {
                    string txt;
                    try { txt = File.ReadAllText(f); } catch { continue; }
                    if (IsSuspiciousRef(txt)) continue;
                    string cmd = ExtractCommand(txt);
                    CurrentItem = f;
                    bool enc = RxEncodedPs.IsMatch(cmd);
                    string why = null, target = null;
                    foreach (var t in CommandTargets(System.Net.WebUtility.HtmlDecode(cmd))) { why = Suspicion(t); if (why != null) { target = t; break; } }
                    if (why == null && !enc) continue;
                    bool online = TestRoot == null && Eq(r, SysRoot());
                    string tn = "\\" + f.Substring(tdir.Length).TrimStart('\\');
                    AddFinding(new Finding
                    {
                        Kind = FindingKind.Task, Severity = enc ? Severity.Alto : Severity.Medio, Selected = enc, TaskFile = f, TaskName = online ? tn : null,
                        Title = "Tarefa " + tn,
                        Detail = (enc ? "Tarefa com PowerShell oculto/codificado." : "Tarefa agendada que executa um programa suspeito.\r\n" + why) +
                                 "\r\nArquivo: " + f + "\r\nComando: " + cmd + (enc ? "" : "\r\nVem DESMARCADO: confira antes de remover.")
                    });
                    if (target != null) ReportSuspicious(target, why, "tarefa " + tn);
                }
            }
            Frac(0.8);

            // 4. processos rodando de pastas temporárias / lixeira sem assinatura
            if (TestRoot == null)
                foreach (var p in Process.GetProcesses())
                {
                    int pid = p.Id; p.Dispose();
                    string path = Native.GetProcessPath(pid);
                    if (path == null || !Regex.IsMatch(path, @"\\Temp\\|\\\$Recycle\.Bin\\|\\RECYCLER\\|\\Users\\Public\\", RegexOptions.IgnoreCase)) continue;
                    string why = Suspicion(path);
                    if (why != null) ReportSuspicious(path, "Processo em execução a partir de pasta temporária/lixeira, sem assinatura digital.", "processo PID " + pid);
                }
            Frac(1);
            if (Findings.Count == before) Log("Nenhuma inicialização ou programa suspeito.", LogLevel.Ok);
        }

        static bool ResolveLnk(string lnk, out string target, out string args)
        {
            target = null; args = null;
            try
            {
                var t = Type.GetTypeFromProgID("WScript.Shell");
                object sh = Activator.CreateInstance(t);
                object sc = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, sh, new object[] { lnk });
                target = Convert.ToString(sc.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, sc, null));
                args = Convert.ToString(sc.GetType().InvokeMember("Arguments", BindingFlags.GetProperty, null, sc, null));
                System.Runtime.InteropServices.Marshal.FinalReleaseComObject(sc);
                System.Runtime.InteropServices.Marshal.FinalReleaseComObject(sh);
                return !string.IsNullOrEmpty(target);
            }
            catch { return false; }
        }

        // =====================================================================
        // configurações de segurança do Windows
        // =====================================================================
        static readonly Regex RxSecurityHost = new Regex(
            @"microsoft|windowsupdate|msftncsi|defender|virustotal|kaspersky|avast|avg\.|eset|mcafee|norton|symantec|malwarebytes|bitdefender|sophos|trendmicro|avira|f-secure|drweb|clamav|hitmanpro|emsisoft",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        void ScanWindowsSecurity(CancellationToken ct)
        {
            int before = Findings.Count;
            foreach (var s in regSources)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (s.Machine && !s.Wow)
                    {
                        // Defender desligado por política (vírus faz isso; o usuário normalmente desliga pela tela, não por política)
                        string pol = s.Prefix + @"\Policies\Microsoft\Windows Defender";
                        CheckDword(s, pol, "DisableAntiSpyware", "Windows Defender desligado por política", Severity.Alto, true);
                        CheckDword(s, pol, "DisableAntiVirus", "Antivírus do Defender desligado por política", Severity.Alto, true);
                        foreach (var v in new[] { "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableOnAccessProtection", "DisableIOAVProtection", "DisableScanOnRealtimeEnable" })
                            CheckDword(s, pol + @"\Real-Time Protection", v, "Proteção em tempo real do Defender bloqueada por política (" + v + ")", Severity.Alto, true);

                        // exclusões do Defender perigosas (vírus se coloca como exceção)
                        foreach (var basek in new[] { s.Prefix + @"\Microsoft\Windows Defender\Exclusions", pol + @"\Exclusions" })
                            foreach (var sub in new[] { "Paths", "Processes", "Extensions" })
                            {
                                string kp = basek + "\\" + sub;
                                using (var k = OpenKey(s.Root, kp, false))
                                {
                                    if (k == null) continue;
                                    foreach (var name in k.GetValueNames())
                                    {
                                        string why = BadExclusion(sub, name);
                                        if (why == null) continue;
                                        var f = RegFinding(s, kp, name, "", RegAction.DeleteValue, null, "Exceção perigosa no Windows Defender", Severity.Alto);
                                        f.Kind = FindingKind.Policy;
                                        f.Selected = false;
                                        f.Title = "Defender ignora: " + name;
                                        f.Detail = "O Windows Defender está configurado para NÃO verificar: " + name + "\r\n" + why +
                                                   "\r\nVírus modernos se adicionam como exceção. Vem desmarcado porque você pode ter criado esta exceção (ex.: para uma ferramenta)." +
                                                   "\r\nChave: " + s.Root + "\\" + kp +
                                                   "\r\nObs.: com a Proteção contra Adulteração ligada, o Windows pode bloquear a remoção — aí remova em Segurança do Windows.";
                                        AddFinding(f);
                                    }
                                }
                            }

                        // AppInit_DLLs: DLL carregada em todo programa
                        string wk = s.Prefix + @"\Microsoft\Windows NT\CurrentVersion\Windows";
                        using (var k = OpenKey(s.Root, wk, false))
                            if (k != null)
                            {
                                string dlls = ReadStr(k, "AppInit_DLLs");
                                long load = 0; try { load = Convert.ToInt64(k.GetValue("LoadAppInit_DLLs", 0)); } catch { }
                                if (!string.IsNullOrWhiteSpace(dlls) && load != 0)
                                    AddFinding(RegFinding(s, wk, "AppInit_DLLs", dlls, RegAction.SetValue, "", "DLL injetada em todos os programas (AppInit_DLLs)", Severity.Alto));
                            }
                    }
                    if (!s.Machine)
                    {
                        // proxy sequestrado (desvia a navegação / bloqueia atualizações)
                        string ik = s.Prefix + @"\Microsoft\Windows\CurrentVersion\Internet Settings";
                        using (var k = OpenKey(s.Root, ik, false))
                            if (k != null)
                            {
                                string pac = ReadStr(k, "AutoConfigURL");
                                if (!string.IsNullOrWhiteSpace(pac))
                                {
                                    var f = RegFinding(s, ik, "AutoConfigURL", pac, RegAction.DeleteValue, null, "Configuração automática de proxy (PAC)", Severity.Medio);
                                    f.Selected = false;
                                    f.Detail += "\r\nVírus usam isso para desviar a navegação. Em empresa pode ser legítimo — vem desmarcado.";
                                    AddFinding(f);
                                }
                                long en = 0; try { en = Convert.ToInt64(k.GetValue("ProxyEnable", 0)); } catch { }
                                string srv = ReadStr(k, "ProxyServer");
                                if (en != 0 && !string.IsNullOrWhiteSpace(srv))
                                {
                                    var f = RegFinding(s, ik, "ProxyEnable", "1 (servidor " + srv + ")", RegAction.SetDword, "0", "Proxy de internet ligado", Severity.Medio);
                                    f.Selected = false;
                                    f.Detail += "\r\nTodo o tráfego passa por " + srv + ". Se você não configurou isso, é sinal de vírus/adware.";
                                    AddFinding(f);
                                }
                            }
                    }
                }
                catch (Exception ex) { Log("Sem acesso a parte das configurações de " + s.Label + ": " + ex.Message, LogLevel.Warn); }
            }
            Frac(0.5);

            // arquivo hosts bloqueando antivírus / Windows Update
            foreach (var r in windowsRoots)
            {
                string hosts = r + @"Windows\System32\drivers\etc\hosts";
                if (!File.Exists(hosts)) continue;
                string[] lines;
                try { lines = File.ReadAllLines(hosts); } catch { continue; }
                var bad = lines.Where(l =>
                {
                    string t = l.Trim();
                    if (t.Length == 0 || t.StartsWith("#")) return false;
                    var parts = Regex.Split(t, @"\s+");
                    return parts.Length >= 2 && parts.Skip(1).Any(h => !h.StartsWith("#") && RxSecurityHost.IsMatch(h) && !Eq(h, "localhost"));
                }).ToList();
                if (bad.Count == 0) continue;
                AddFinding(new Finding
                {
                    Kind = FindingKind.Hosts, Severity = Severity.Alto, FilePath = hosts, Title = hosts + " (" + bad.Count + " bloqueio(s))",
                    Extra = string.Join("\n", bad),
                    Detail = "O arquivo hosts está bloqueando sites de antivírus / Windows Update — técnica para o vírus não ser removido.\r\n" +
                             "Linhas que serão desativadas (o resto do arquivo não muda; há backup):\r\n  " + string.Join("\r\n  ", bad.Take(30))
                });
            }
            Frac(0.75);

            // sinais do ransomware STOP/Djvu (bilhete de resgate)
            foreach (var r in windowsRoots)
                foreach (var ud in SafeDirs(r + "Users"))
                    foreach (var sub in new[] { "Desktop", "Documents", "Downloads" })
                    {
                        string note = Path.Combine(ud, sub, "_readme.txt");
                        if (!File.Exists(note)) continue;
                        string txt = "";
                        try { txt = File.ReadAllText(note); } catch { }
                        if (txt.IndexOf("personal ID", StringComparison.OrdinalIgnoreCase) < 0 && txt.IndexOf("ATTENTION!", StringComparison.Ordinal) < 0) continue;
                        AddFinding(new Finding
                        {
                            Kind = FindingKind.Warning, Severity = Severity.Info, Selected = false, FilePath = note, Title = "Bilhete de resgate: " + note,
                            Detail = "Encontrado o bilhete do ransomware STOP/Djvu (comum em quem baixa crack/keygen).\r\n" +
                                     "Os arquivos podem estar criptografados (extensões estranhas de 4 letras). NÃO pague.\r\n" +
                                     "A varredura de inicialização acima costuma achar o executável dele em AppData\\Local (pasta com nome aleatório).\r\n" +
                                     "Guarde o _readme.txt e um arquivo criptografado: se ele usou a chave offline, há ferramentas oficiais que recuperam."
                        });
                    }
            Frac(1);
            if (Findings.Count == before) Log("Configurações de segurança do Windows OK (Defender, hosts, proxy).", LogLevel.Ok);
        }

        void CheckDword(RegSource s, string key, string value, string what, Severity sev, bool sel)
        {
            using (var k = OpenKey(s.Root, key, false))
            {
                if (k == null) return;
                object v = k.GetValue(value);
                long num = 0;
                try { num = Convert.ToInt64(v); } catch { }
                if (v == null || num == 0) return;
                var f = RegFinding(s, key, value, Convert.ToString(v), RegAction.DeleteValue, null, what, sev);
                f.Kind = FindingKind.Policy;
                f.Selected = sel;
                AddFinding(f);
            }
        }

        static string BadExclusion(string type, string name)
        {
            string n = Environment.ExpandEnvironmentVariables(name ?? "").Trim();
            if (type == "Extensions")
            {
                string e = n.TrimStart('*', '.').ToLowerInvariant();
                return new[] { "exe", "dll", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "ps1", "hta", "wsf", "msi", "lnk", "tmp" }.Contains(e)
                    ? "Extensão de programa inteira ignorada: qualquer vírus com essa extensão passa." : null;
            }
            if (Regex.IsMatch(n, @"^[A-Za-z]:\\?$")) return "Um disco inteiro está fora da proteção.";
            if (Regex.IsMatch(n, @"^[A-Za-z]:\\(Users|Windows|ProgramData|Program Files( \(x86\))?)\\?$", RegexOptions.IgnoreCase)) return "Uma pasta de sistema inteira está fora da proteção.";
            if (RxUserLoc.IsMatch(n + (n.EndsWith("\\") ? "x" : "")) || Regex.IsMatch(n, @"\\(AppData|Temp)\\?$", RegexOptions.IgnoreCase))
                return "Pasta de usuário/temporária fora da proteção (é onde os vírus se instalam).";
            return null;
        }

        // =====================================================================
        // vírus do atalho (pendrive)
        // =====================================================================
        void ScanUsbWorm(string root, CancellationToken ct)
        {
            root = WithSlash(root);
            var lnkHits = new List<string>();
            var hidden = new List<string>();
            foreach (var d in SafeDirs(root))
            {
                string name = Path.GetFileName(d);
                if (Eq(name, "System Volume Information") || name.StartsWith("$", StringComparison.Ordinal)) continue;
                try
                {
                    var a = File.GetAttributes(d);
                    if ((a & FileAttributes.Hidden) != 0) hidden.Add(d);
                }
                catch { }
            }
            string[] files;
            try { files = Directory.GetFiles(root); } catch { files = new string[0]; }
            foreach (var f in files)
            {
                ct.ThrowIfCancellationRequested();
                CurrentItem = f;
                string ext = Path.GetExtension(f).ToLowerInvariant();
                FileAttributes fa = 0;
                try { fa = File.GetAttributes(f); } catch { }
                bool isHidden = (fa & FileAttributes.Hidden) != 0;
                if (ext == ".lnk")
                {
                    string target, args;
                    if (!ResolveLnk(f, out target, out args)) continue;
                    string tn = Path.GetFileName(target ?? "");
                    string bare = Path.GetFileNameWithoutExtension(f);
                    bool lol = Lolbins.Any(x => Eq(x, tn));
                    bool onDrive = (target ?? "").StartsWith(root, StringComparison.OrdinalIgnoreCase) && (IsScript(target) || IsExec(target));
                    bool twin = hidden.Any(h => Eq(Path.GetFileName(h), bare));
                    if (lol || onDrive || twin)
                    {
                        lnkHits.Add(f);
                        lock (reportedFiles) if (!reportedFiles.Add(f)) continue;
                        AddFinding(new Finding
                        {
                            Kind = FindingKind.Autorun, Severity = Severity.Alto, FilePath = f, Title = f,
                            Detail = "Atalho falso do \"vírus do atalho\": parece uma pasta/arquivo, mas executa o vírus.\r\n" +
                                     "Aponta para: " + target + " " + args + (twin ? "\r\nA pasta verdadeira com esse nome foi escondida pelo vírus." : "")
                        });
                    }
                }
                else if (IsScript(f) || ((ext == ".exe" || ext == ".scr" || ext == ".pif" || ext == ".com") && isHidden))
                {
                    var r = ScanFile(f);
                    ReportFile(f, FindingKind.MaliciousFile, Severity.Alto,
                        IsScript(f) ? "Script na raiz do pendrive (o vírus do atalho usa scripts .vbs/.js para se espalhar)."
                                    : "Executável escondido na raiz do pendrive.", r);
                }
            }
            if (lnkHits.Count == 0) return;
            // há evidência do worm: scripts dentro de pastas escondidas e as pastas a desocultar
            foreach (var h in hidden)
            {
                foreach (var f in SafeFiles(h, false, ct))
                    if (IsScript(f)) ReportFile(f, FindingKind.MaliciousFile, Severity.Alto, "Script do vírus do atalho dentro de pasta escondida.", null);
                lock (reportedFiles) if (!reportedFiles.Add(h)) continue;
                AddFinding(new Finding
                {
                    Kind = FindingKind.HiddenFolder, Severity = Severity.Medio, FilePath = h, Title = h,
                    Detail = "Pasta escondida pelo vírus do atalho (seus arquivos continuam dentro dela).\r\nNa limpeza ela volta a ficar visível (atributos oculto/sistema removidos)."
                });
            }
        }

        // =====================================================================
        // confirmação pelo Windows Defender
        // =====================================================================
        static string MpCmdRun()
        {
            try
            {
                string plat = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform");
                if (Directory.Exists(plat))
                {
                    var best = Directory.GetDirectories(plat).OrderByDescending(d => d).Select(d => Path.Combine(d, "MpCmdRun.exe")).FirstOrDefault(File.Exists);
                    if (best != null) return best;
                }
                string pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe");
                return File.Exists(pf) ? pf : null;
            }
            catch { return null; }
        }

        void DefenderConfirm(CancellationToken ct)
        {
            string mp = MpCmdRun();
            List<Finding> list;
            lock (Findings) list = Findings.Where(f => (f.Kind == FindingKind.Suspicious || f.Kind == FindingKind.MaliciousFile) && f.FilePath != null && File.Exists(f.FilePath)).ToList();
            if (mp == null) { Log("Windows Defender (MpCmdRun) não encontrado — confirmação pulada.", LogLevel.Warn); Frac(1); return; }
            if (list.Count == 0) { Log("Nenhum arquivo para confirmar com o Defender.", LogLevel.Ok); Frac(1); return; }
            int n = 0, hits = 0;
            foreach (var f in list)
            {
                ct.ThrowIfCancellationRequested();
                CurrentItem = f.FilePath;
                string outp;
                int rc = RunTool(mp, "-Scan -ScanType 3 -File \"" + f.FilePath + "\" -DisableRemediation", out outp);
                if (rc == 2)
                {
                    var m = Regex.Match(outp, @"Threat\s*:\s*([^\r\n]+)");
                    string name = m.Success ? m.Groups[1].Value.Trim() : "ameaça";
                    hits++;
                    f.Severity = f.Kind == FindingKind.Suspicious ? Severity.Alto : f.Severity;
                    f.Selected = true;
                    f.Detail += "\r\n\r\n✔ Confirmado pelo Windows Defender: " + name;
                    Changed(f, "Defender: " + name, false);
                    Log("Defender confirmou: " + f.FilePath + " → " + name, LogLevel.Error);
                }
                else if (rc == 0) Changed(f, f.Kind == FindingKind.Suspicious ? "Defender: nada encontrado" : f.Status, false);
                else if (n == 0 && rc != 0) Log("Defender respondeu código " + rc + " (pode estar desativado): " + Trunc(outp, 200), LogLevel.Warn);
                Frac(++n / (double)list.Count);
            }
            Log(string.Format("Defender verificou {0} arquivo(s): {1} confirmado(s) como ameaça.", list.Count, hits), hits > 0 ? LogLevel.Error : LogLevel.Ok);
        }

        // =====================================================================
        // ações de limpeza dos novos tipos
        // =====================================================================
        string ApplyHosts(Finding f)
        {
            try
            {
                string hosts = f.FilePath;
                var bad = new HashSet<string>((f.Extra ?? "").Split('\n').Where(x => x.Length > 0));
                string backup = Path.Combine(session, "hosts_backup.txt");
                File.Copy(hosts, backup, true);
                var attrs = File.GetAttributes(hosts);
                File.SetAttributes(hosts, FileAttributes.Normal);
                var lines = File.ReadAllLines(hosts).Select(l => bad.Contains(l) ? "# desativado pelo DGX Virus Remover: " + l : l).ToArray();
                File.WriteAllLines(hosts, lines);
                File.SetAttributes(hosts, attrs & ~FileAttributes.ReadOnly);
                manifest.WriteLine("HOSTS\t" + backup + "\t" + hosts);
                Log("hosts corrigido: " + bad.Count + " bloqueio(s) desativado(s).", LogLevel.Ok);
                return "Corrigido (backup salvo)";
            }
            catch (Exception ex) { return "Falha: " + ex.Message; }
        }

        string ApplyUnhide(Finding f)
        {
            try
            {
                var a = File.GetAttributes(f.FilePath);
                File.SetAttributes(f.FilePath, a & ~(FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly));
                manifest.WriteLine("ATTR\t" + f.FilePath + "\t" + (int)a);
                Log("Pasta visível de novo: " + f.FilePath, LogLevel.Ok);
                return "Pasta visível de novo";
            }
            catch (Exception ex) { return "Falha: " + ex.Message; }
        }
    }
}
