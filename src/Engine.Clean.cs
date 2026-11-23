using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace TJRemover
{
    class ProcHandle
    {
        public int Pid;
        public string Path;
        public IntPtr Handle;
        public bool Suspended;
    }

    public partial class Engine
    {
        string session;
        StreamWriter manifest;
        readonly HashSet<string> exportedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> pendingReboot = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> failedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> quarantined = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> restored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int quarCounter;
        public int RestoredCount { get { lock (restored) return restored.Count; } }

        // =====================================================================
        // processos: abrir todos, congelar todos, encerrar todos
        // =====================================================================
        List<ProcHandle> OpenTargets(HashSet<string> paths, IEnumerable<Finding> procFindings)
        {
            var targets = new Dictionary<int, string>();
            int me = Process.GetCurrentProcess().Id;
            foreach (var p in Process.GetProcesses())
            {
                int pid = p.Id;
                p.Dispose();
                if (pid == me || pid <= 4) continue;
                string path = Native.GetProcessPath(pid);
                if (path == null) continue;
                bool hit = IsDropperPath(path) || (paths != null && paths.Contains(path));
                if (!hit && procFindings != null)
                    foreach (var f in procFindings)
                        if (f.Pid == pid && Eq(f.FilePath, path)) { hit = true; break; }
                if (hit) targets[pid] = path;
            }
            var list = new List<ProcHandle>();
            foreach (var kv in targets)
            {
                IntPtr h = Native.OpenProcess(Native.PROCESS_TERMINATE | Native.PROCESS_SUSPEND_RESUME |
                                              Native.PROCESS_QUERY_LIMITED_INFORMATION | Native.SYNCHRONIZE, false, kv.Key);
                if (h == IntPtr.Zero)
                {
                    Log(string.Format("Sem permissão para acessar {0} (PID {1}).", System.IO.Path.GetFileName(kv.Value), kv.Key), LogLevel.Error);
                    continue;
                }
                list.Add(new ProcHandle { Pid = kv.Key, Path = kv.Value, Handle = h });
            }
            return list;
        }

        void SuspendAll(List<ProcHandle> list)
        {
            // primeiro congela todos (rápido, sem log no meio) para nenhum relançar o outro
            foreach (var x in list) x.Suspended = Native.NtSuspendProcess(x.Handle) == 0;
            foreach (var x in list)
                Log((x.Suspended ? "Congelado: " : "Não foi possível congelar: ") + System.IO.Path.GetFileName(x.Path) + " (PID " + x.Pid + ")",
                    x.Suspended ? LogLevel.Ok : LogLevel.Warn);
        }

        void TerminateAll(List<ProcHandle> list, List<Finding> procFindings)
        {
            foreach (var x in list)
            {
                bool ok = Native.TerminateProcess(x.Handle, 1);
                Native.WaitForSingleObject(x.Handle, 3000);
                Native.CloseHandle(x.Handle);
                Log((ok ? "Encerrado: " : "Falha ao encerrar: ") + x.Path + " (PID " + x.Pid + ")", ok ? LogLevel.Ok : LogLevel.Error);
                if (procFindings != null)
                    foreach (var f in procFindings.Where(f => f.Pid == x.Pid))
                        Changed(f, ok ? "Encerrado" : "Falha ao encerrar", true);
            }
            if (procFindings != null)
                foreach (var f in procFindings.Where(f => !f.Done))
                    Changed(f, "Já não estava em execução", true);
        }

        int KillNow(HashSet<string> paths)
        {
            var l = OpenTargets(paths, null);
            if (l.Count == 0) return 0;
            SuspendAll(l);
            TerminateAll(l, null);
            return l.Count;
        }

        // =====================================================================
        // quarentena
        // =====================================================================
        // ---- quarentena cifrada: o antivírus não apaga a cópia (senão o "Desfazer" quebraria)
        static readonly byte[] QKey = System.Text.Encoding.ASCII.GetBytes("DGX-Quarentena-v1");

        /// <summary>Copia aplicando XOR (a mesma função cifra e decifra).</summary>
        public static void XorCopy(string src, string dst)
        {
            var buf = new byte[1 << 16];
            long pos = 0;
            using (var i = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var o = new FileStream(dst, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                int n;
                while ((n = i.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int k = 0; k < n; k++) buf[k] ^= (byte)(QKey[(pos + k) % QKey.Length] + (byte)((pos + k) >> 8));
                    o.Write(buf, 0, n);
                    pos += n;
                }
            }
        }

        /// <summary>Devolve um arquivo da quarentena (cifrado "X" ou antigo, só renomeado).</summary>
        public static void RestoreFromQuarantine(string vir, string original, bool encrypted, string attrs = null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(original));
            if (encrypted) { XorCopy(vir, original); File.Delete(vir); }
            else File.Move(vir, original);
            int a;
            if (attrs != null && int.TryParse(attrs, out a) && a != 0)
                try { File.SetAttributes(original, (FileAttributes)a); } catch { }   // volta oculto/sistema como estava
        }

        /// <summary>Converte arquivos de quarentenas antigas (só renomeados) para o formato cifrado.</summary>
        public static int MigrateQuarantine(string baseDir)
        {
            int n = 0;
            try
            {
                if (!Directory.Exists(baseDir)) return 0;
                foreach (var dir in Directory.GetDirectories(baseDir))
                {
                    string mf = Path.Combine(dir, "manifesto.txt");
                    if (!File.Exists(mf)) continue;
                    var lines = File.ReadAllLines(mf);
                    bool changed = false;
                    for (int i = 0; i < lines.Length; i++)
                    {
                        var p = lines[i].Split('\t');
                        if (p[0] != "FILE" || p.Length < 3 || (p.Length > 4 && p[4] == "X") || !File.Exists(p[2])) continue;
                        try
                        {
                            string tmp = p[2] + ".x";
                            if (File.Exists(tmp)) File.Delete(tmp);
                            XorCopy(p[2], tmp);
                            File.Delete(p[2]);
                            File.Move(tmp, p[2]);
                            lines[i] = "FILE\t" + p[1] + "\t" + p[2] + "\t" + (p.Length > 3 ? p[3] : "") + "\tX";
                            changed = true; n++;
                        }
                        catch { }
                    }
                    if (changed) File.WriteAllLines(mf, lines, new UTF8Encoding(false));
                }
            }
            catch { }
            return n;
        }

        string NewQuarantinePath(string path)
        {
            // nome curto (nº + nome do arquivo); o caminho original fica no manifesto
            return Path.Combine(session, "arquivos",
                (Interlocked.Increment(ref quarCounter)).ToString("0000") + "_" + San(Path.GetFileName(path)) + ".vir");
        }

        string QuarantineFile(string path, HashSet<string> killPaths)
        {
            if (!File.Exists(path)) return "Já não existe";
            Exception last = null;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                string dest = null;
                try
                {
                    var origAttrs = File.GetAttributes(path);
                    File.SetAttributes(path, FileAttributes.Normal);
                    string hash = Sha256(path) ?? "";
                    dest = NewQuarantinePath(path);
                    XorCopy(path, dest);
                    try { File.Delete(path); }
                    catch { File.Delete(dest); throw; }
                    if (File.Exists(path)) { File.Delete(dest); throw new IOException("o arquivo continua no lugar"); }
                    lock (quarantined) quarantined.Add(path);
                    manifest.WriteLine("FILE\t" + path + "\t" + dest + "\t" + hash + "\tX\t" + (int)origAttrs);
                    Log("Quarentena: " + path, LogLevel.Ok);
                    return "Em quarentena";
                }
                catch (Exception ex)
                {
                    last = ex;
                    KillNow(killPaths);   // algo relançou o vírus ou está segurando o arquivo
                    if (attempt >= 1) KillLockers(path);   // pergunta ao Windows quem está com o arquivo aberto
                    Thread.Sleep(300);
                }
            }
            if (Native.MoveFileEx(path, null, Native.MOVEFILE_DELAY_UNTIL_REBOOT))
            {
                NeedReboot = true;
                lock (pendingReboot) pendingReboot.Add(path);
                Log("Arquivo travado, será apagado no próximo reinício: " + path, LogLevel.Warn);
                return "Será apagado no reinício";
            }
            lock (failedFiles) failedFiles.Add(path);
            Log("Falha ao remover " + path + ": " + (last != null ? last.Message : "?"), LogLevel.Error);
            return "Falha: " + (last != null ? last.Message : "?");
        }

        /// <summary>
        /// Encerra quem está com o arquivo aberto, usando o Restart Manager do Windows
        /// (substitui o handle.exe que o Synaptics Killer precisa ter na pasta).
        /// </summary>
        void KillLockers(string path)
        {
            int me = Process.GetCurrentProcess().Id;
            foreach (var l in Native.GetLockingProcesses(path))
            {
                if (l.Pid <= 4 || l.Pid == me || l.Critical) continue;
                IntPtr h = Native.OpenProcess(Native.PROCESS_TERMINATE | Native.SYNCHRONIZE, false, l.Pid);
                if (h == IntPtr.Zero) continue;
                bool ok = Native.TerminateProcess(h, 1);
                Native.WaitForSingleObject(h, 3000);
                Native.CloseHandle(h);
                Log((ok ? "Encerrado (segurava o arquivo): " : "Não consegui encerrar: ") + l.Name + " (PID " + l.Pid + ")", ok ? LogLevel.Ok : LogLevel.Warn);
            }
        }

        // =====================================================================
        // desinfecção (Synaptics, Mofksys/TJprojMain, Grenam)
        // =====================================================================
        string DisinfectFile(Finding f, HashSet<string> killPaths)
        {
            string path = f.FilePath;
            if (!File.Exists(path)) return "Já não existe";
            DisinfectPlan plan;
            try
            {
                File.SetAttributes(path, FileAttributes.Normal);
                var data = File.ReadAllBytes(path);
                plan = f.Family == VirusFamily.TJ ? Families.PlanTJ(data) : Families.Plan(path, data);
            }
            catch (Exception ex)
            {
                Log("Não consegui ler " + path + " para desinfetar (" + ex.Message + "); vai para a quarentena.", LogLevel.Warn);
                return QuarantineFile(path, killPaths);
            }
            if (!plan.CanRestore)
            {
                Log("Original não encontrado em " + path + " — só quarentena.", LogLevel.Warn);
                return QuarantineFile(path, killPaths);
            }

            string q = QuarantineFile(path, killPaths);       // o infectado sempre vai para a quarentena (dá para desfazer)
            if (q != "Em quarentena") return q + " (original não restaurado)";
            try
            {
                if (plan.RestoreFrom != null)
                {
                    // Grenam: o original estava escondido como g<nome>.exe
                    File.SetAttributes(plan.RestoreFrom, FileAttributes.Normal);
                    File.Move(plan.RestoreFrom, path);
                    manifest.WriteLine("REN\t" + plan.RestoreFrom + "\t" + path);
                }
                else
                {
                    File.WriteAllBytes(path, plan.Original);
                    manifest.WriteLine("REST\t" + path + "\t" + (Sha256(path) ?? ""));
                }
                lock (restored) restored.Add(path);
                killPaths.Remove(path);   // o arquivo agora é o programa limpo: não é mais alvo
                Log("Desinfetado (" + Families.Name(plan.Family) + "): original restaurado em " + path, LogLevel.Ok);
                return "Desinfetado — original restaurado";
            }
            catch (Exception ex)
            {
                Log("Falha ao restaurar o original de " + path + ": " + ex.Message + " (o infectado está na quarentena)", LogLevel.Error);
                return "Em quarentena (falha ao restaurar o original: " + ex.Message + ")";
            }
        }

        // =====================================================================
        // registro / serviços / tarefas
        // =====================================================================
        void BackupKey(string full)
        {
            if (exportedKeys.Contains(full)) return;
            string dir = Path.Combine(session, "registro");
            Directory.CreateDirectory(dir);
            string file = Path.Combine(dir, (exportedKeys.Count + 1).ToString("000") + ".reg");
            string outp;
            if (RunTool("reg.exe", "export \"" + full + "\" \"" + file + "\" /y", out outp) == 0)
            {
                manifest.WriteLine("REG\t" + file + "\t" + full);
                exportedKeys.Add(full);
            }
            else Log("Aviso: backup de " + full + " falhou (" + outp + ")", LogLevel.Warn);
        }

        void ApplyRegistry(Finding f)
        {
            string full = (f.RegRoot == "HKLM" ? "HKLM\\" : "HKU\\") + f.RegKey;
            try
            {
                BackupKey(full);
                using (var k = OpenKey(f.RegRoot, f.RegKey, true))
                {
                    if (k == null) { Changed(f, "Chave não encontrada", true); return; }
                    if (f.RegAct == RegAction.DeleteValue) k.DeleteValue(f.RegValue, false);
                    else if (f.RegAct == RegAction.SetDword) k.SetValue(f.RegValue, int.Parse(f.RegNewValue), RegistryValueKind.DWord);
                    else k.SetValue(f.RegValue, f.RegNewValue, RegistryValueKind.String);
                }
                Changed(f, f.RegAct == RegAction.DeleteValue ? "Removido" : "Restaurado", true);
                Log((f.RegAct == RegAction.DeleteValue ? "Removido: " : "Restaurado: ") + full + " → " + f.RegValue, LogLevel.Ok);
            }
            catch (Exception ex)
            {
                string msg = ex is UnauthorizedAccessException || ex is System.Security.SecurityException
                    ? "Falha: protegido pelo Windows (remova em Segurança do Windows)" : "Falha: " + ex.Message;
                Changed(f, msg, true);
                Log("Falha no registro " + full + ": " + ex.Message, LogLevel.Error);
            }
        }

        void ApplyService(Finding f)
        {
            string outp;
            BackupKey(@"HKLM\SYSTEM\CurrentControlSet\Services\" + f.ServiceName);
            RunTool("sc.exe", "stop \"" + f.ServiceName + "\"", out outp);
            int rc = RunTool("sc.exe", "delete \"" + f.ServiceName + "\"", out outp);
            if (rc == 0) { Changed(f, "Removido", true); Log("Serviço removido: " + f.ServiceName, LogLevel.Ok); }
            else if (rc == 1072) { NeedReboot = true; Changed(f, "Será removido no reinício", true); Log("Serviço marcado para exclusão: " + f.ServiceName, LogLevel.Warn); }
            else { Changed(f, "Falha: sc " + rc, true); Log("Falha ao remover serviço " + f.ServiceName + ": " + outp, LogLevel.Error); }
        }

        void ApplyTask(Finding f, HashSet<string> killPaths)
        {
            if (f.TaskName == null)
            {
                Changed(f, QuarantineFile(f.TaskFile, killPaths), true);
                return;
            }
            try
            {
                string dir = Path.Combine(session, "tarefas");
                Directory.CreateDirectory(dir);
                string copy = Path.Combine(dir, San(f.TaskName.Trim('\\').Replace('\\', '_')) + ".xml");
                File.Copy(f.TaskFile, copy, true);
                string outp;
                int rc = RunTool("schtasks.exe", "/delete /tn \"" + f.TaskName + "\" /f", out outp);
                if (rc == 0)
                {
                    manifest.WriteLine("TASK\t" + f.TaskName + "\t" + copy);
                    Changed(f, "Removida", true);
                    Log("Tarefa removida: " + f.TaskName, LogLevel.Ok);
                }
                else { Changed(f, "Falha: " + outp, true); Log("Falha ao remover tarefa " + f.TaskName + ": " + outp, LogLevel.Error); }
            }
            catch (Exception ex) { Changed(f, "Falha: " + ex.Message, true); }
        }

        // =====================================================================
        // reinfecção e vacina
        // =====================================================================
        List<string> DropperFilesPresent(HashSet<string> extra)
        {
            var res = new List<string>();
            foreach (var r in windowsRoots)
            {
                foreach (var f in SafeFiles(r + @"Windows\Resources", true, CancellationToken.None))
                    if (IsExec(f) || IsIcsys(f)) res.Add(f);
                foreach (var f in SafeFiles(r + @"Windows\System", false, CancellationToken.None))
                    if (IsExec(f) || IsIcsys(f)) res.Add(f);
            }
            foreach (var r in windowsRoots)
                foreach (var rel in SynapticsDirsRel)
                    foreach (var f in SafeFiles(r + rel, true, CancellationToken.None))
                        if (IsSynapticsDropper(f)) res.Add(f);
            foreach (var p in extra) if (File.Exists(p) && !res.Contains(p, StringComparer.OrdinalIgnoreCase)) res.Add(p);
            // programas desinfetados (original restaurado no mesmo caminho) não são "reinfecção"
            lock (restored) res.RemoveAll(p => restored.Contains(p));
            // arquivos que já falharam (ou aguardam reinício) não são "reinfecção"
            lock (pendingReboot) res.RemoveAll(p => pendingReboot.Contains(p));
            lock (failedFiles) res.RemoveAll(p => failedFiles.Contains(p));
            return res;
        }

        void Reinfection(HashSet<string> paths, CancellationToken ct)
        {
            for (int round = 1; round <= 5; round++)
            {
                ct.ThrowIfCancellationRequested();
                CurrentItem = "Observando o sistema — rodada " + round + " de 5";
                Thread.Sleep(1500); // tempo para um componente escondido tentar relançar o vírus
                var live = OpenTargets(paths, null);
                var back = DropperFilesPresent(paths);
                if (live.Count == 0 && back.Count == 0)
                {
                    Log(round == 1 ? "Nenhum sinal de reinfecção." : "Reinfecção contida.", LogLevel.Ok);
                    Frac(1);
                    return;
                }
                Log(string.Format("Rodada {0}: {1} processo(s) e {2} arquivo(s) voltaram — removendo de novo.", round, live.Count, back.Count), LogLevel.Warn);
                SuspendAll(live);
                TerminateAll(live, null);
                foreach (var f in back) QuarantineFile(f, paths);
                Frac(round / 5.0);
            }
            NeedReboot = true;
            Log("O vírus continua voltando. Reinicie em Modo de Segurança e rode o programa novamente.", LogLevel.Error);
        }

        void ApplyVaccine()
        {
            var world = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            var rels = KnownDropperRel.Concat(new[] { @"ProgramData\Synaptics\Synaptics.exe" }).ToArray();
            int n = 0, ok = 0, total = windowsRoots.Count * rels.Length;
            foreach (var r in windowsRoots)
                foreach (var rel in rels)
                {
                    string p = r + rel;
                    CurrentItem = p;
                    Frac(++n / (double)total);
                    if (File.Exists(p)) { Log("Vacina não aplicada (o arquivo ainda está lá — reinicie e rode de novo): " + p, LogLevel.Warn); continue; }
                    if (Directory.Exists(p)) { ok++; continue; }
                    string parent = Path.GetDirectoryName(p);
                    if (rel.StartsWith(@"ProgramData\Synaptics") && Directory.Exists(Path.GetDirectoryName(parent)) && !Directory.Exists(parent))
                    {
                        try
                        {
                            Directory.CreateDirectory(parent);
                            new DirectoryInfo(parent).Attributes = FileAttributes.Directory | FileAttributes.Hidden;
                            manifest.WriteLine("VDIR\t" + parent);
                        }
                        catch { }
                    }
                    if (!Directory.Exists(parent)) continue;
                    try
                    {
                        Directory.CreateDirectory(p);
                        new DirectoryInfo(p).Attributes = FileAttributes.Directory | FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System;
                        var ds = Directory.GetAccessControl(p);
                        ds.AddAccessRule(new FileSystemAccessRule(world,
                            FileSystemRights.Delete | FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories,
                            AccessControlType.Deny));
                        Directory.SetAccessControl(p, ds);
                        manifest.WriteLine("VACC\t" + p);
                        ok++;
                        Log("Vacina aplicada: " + p, LogLevel.Ok);
                    }
                    catch (Exception ex) { Log("Vacina não aplicada em " + p + ": " + ex.Message, LogLevel.Warn); }
                }
            Log(string.Format("Vacina ativa em {0} de {1} caminhos usados pelo vírus.", ok, total), ok > 0 ? LogLevel.Ok : LogLevel.Warn);
        }

        // =====================================================================
        // LIMPEZA
        // =====================================================================
        public void Clean(List<Finding> sel, ScanOptions o, CancellationToken ct)
        {
            NeedReboot = false;
            exportedKeys.Clear();
            lock (pendingReboot) pendingReboot.Clear();
            lock (failedFiles) failedFiles.Clear();
            lock (quarantined) quarantined.Clear();
            lock (restored) restored.Clear();
            quarCounter = 0;
            session =Path.Combine(QuarantineBase, DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            Directory.CreateDirectory(Path.Combine(session, "arquivos"));
            LastSessionDir = session;

            var ph = new List<KeyValuePair<string, double>>
            {
                P("Congelando processos do vírus", 5),
                P("Encerrando processos", 5),
                P("Quarentena dos arquivos", 30),
                P("Limpando o registro", 15),
                P("Serviços, tarefas e autorun", 10),
                P("Vigiando contra reinfecção", 25)
            };
            if (o.Vaccine) ph.Add(P("Aplicando vacina", 10));
            SetupPhases(ph);
            Log("Limpeza iniciada — sessão de quarentena: " + session, LogLevel.Title);

            var sw = Stopwatch.StartNew();
            manifest = new StreamWriter(Path.Combine(session, "manifesto.txt"), true, new UTF8Encoding(false)) { AutoFlush = true };
            try
            {
                var procs = sel.Where(f => f.Kind == FindingKind.Process).ToList();
                var files = sel.Where(f => f.Kind == FindingKind.MaliciousFile || f.Kind == FindingKind.InfectedFile || f.Kind == FindingKind.Suspicious).ToList();
                var paths = new HashSet<string>(files.Select(f => f.FilePath), StringComparer.OrdinalIgnoreCase);

                Begin(0);
                var handles = OpenTargets(paths, procs);
                SuspendAll(handles);
                Frac(1);

                Begin(1);
                TerminateAll(handles, procs);
                Frac(1);

                Begin(2);
                int n = 0;
                foreach (var f in files)
                {
                    ct.ThrowIfCancellationRequested();
                    CurrentItem = f.FilePath;
                    string st;
                    if (f.Kind == FindingKind.InfectedFile && f.DefenderClean) st = DefenderDisinfect(f, paths);
                    else if (f.Kind == FindingKind.InfectedFile && f.Disinfect) st = DisinfectFile(f, paths);
                    else st = QuarantineFile(f.FilePath, paths);
                    Changed(f, st, true);
                    Frac(++n / (double)Math.Max(1, files.Count));
                }

                Begin(3);
                var regs = sel.Where(f => f.Kind == FindingKind.Registry || f.Kind == FindingKind.Policy).ToList();
                n = 0;
                foreach (var f in regs)
                {
                    ct.ThrowIfCancellationRequested();
                    CurrentItem = f.RegRoot + "\\" + f.RegKey;
                    ApplyRegistry(f);
                    Frac(++n / (double)Math.Max(1, regs.Count));
                }

                Begin(4);
                var others = sel.Where(f => f.Kind == FindingKind.Service || f.Kind == FindingKind.Task || f.Kind == FindingKind.Autorun ||
                                            f.Kind == FindingKind.Hosts || f.Kind == FindingKind.HiddenFolder || f.Kind == FindingKind.Warning ||
                                            f.Kind == FindingKind.SystemIni).ToList();
                n = 0;
                foreach (var f in others)
                {
                    ct.ThrowIfCancellationRequested();
                    CurrentItem = f.Title;
                    if (f.Kind == FindingKind.Service) ApplyService(f);
                    else if (f.Kind == FindingKind.Task) ApplyTask(f, paths);
                    else if (f.Kind == FindingKind.Hosts) Changed(f, ApplyHosts(f), true);
                    else if (f.Kind == FindingKind.HiddenFolder) Changed(f, ApplyUnhide(f), true);
                    else if (f.Kind == FindingKind.SystemIni) Changed(f, ApplySystemIni(f), true);
                    else if (f.Kind == FindingKind.Warning) Changed(f, "Somente aviso (nada a remover)", true);
                    else Changed(f, QuarantineFile(f.FilePath, paths), true);
                    Frac(++n / (double)Math.Max(1, others.Count));
                }

                Begin(5);
                Reinfection(paths, ct);

                if (o.Vaccine) { Begin(6); ApplyVaccine(); }

                Complete();
                CurrentItem = "";
                int ok = sel.Count(f => f.Done && !f.Failed), fail = sel.Count(f => f.Failed);
                Log(string.Format("Limpeza concluída em {0:mm\\:ss}: {1} item(ns) tratados, {2} falha(s).{3}", sw.Elapsed, ok, fail,
                    NeedReboot ? " REINICIE o computador para concluir." : ""), fail > 0 ? LogLevel.Warn : LogLevel.Ok);
            }
            catch (OperationCanceledException) { Log("Limpeza interrompida pelo usuário.", LogLevel.Warn); }
            catch (Exception ex) { Log("Erro inesperado na limpeza: " + ex, LogLevel.Error); }
            finally
            {
                manifest.Dispose();
                manifest = null;
                SaveLog(Path.Combine(session, "log.txt"));
                UnloadHives();
            }
        }

        public void SaveLog(string file)
        {
            try
            {
                var sb = new StringBuilder();
                lock (FullLog)
                    foreach (var e in FullLog) sb.AppendLine(e.Time.ToString("dd/MM HH:mm:ss") + "  " + e.Text);
                File.WriteAllText(file, sb.ToString(), Encoding.UTF8);
            }
            catch { }
        }

        // =====================================================================
        // DESFAZER
        // =====================================================================
        public void Undo(string dir, CancellationToken ct)
        {
            SetupPhases(new List<KeyValuePair<string, double>>
            {
                P("Lendo o manifesto", 5), P("Removendo a vacina", 10), P("Restaurando arquivos", 40),
                P("Restaurando o registro", 30), P("Restaurando tarefas", 15)
            });
            try
            {
                Begin(0);
                string mf = Path.Combine(dir, "manifesto.txt");
                var lines = File.ReadAllLines(mf).Select(l => l.Split('\t')).ToList();
                Log("Desfazendo a limpeza de " + dir, LogLevel.Title);
                Frac(1);

                var world = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                Begin(1);
                var vacc = lines.Where(l => l[0] == "VACC").ToList();
                int n = 0;
                foreach (var l in vacc)
                {
                    string p = l[1];
                    try
                    {
                        if (Directory.Exists(p))
                        {
                            var ds = Directory.GetAccessControl(p);
                            ds.PurgeAccessRules(world);
                            Directory.SetAccessControl(p, ds);
                            new DirectoryInfo(p).Attributes = FileAttributes.Directory;
                            Directory.Delete(p);
                        }
                        Log("Vacina removida: " + p, LogLevel.Ok);
                    }
                    catch (Exception ex) { Log("Falha ao remover vacina " + p + ": " + ex.Message, LogLevel.Error); }
                    Frac(++n / (double)Math.Max(1, vacc.Count));
                }

                Begin(2);
                // primeiro desfaz as desinfecções (tira o original restaurado do caminho), na ordem inversa
                var revert = lines.Where(l => l[0] == "REST" || l[0] == "REN").Reverse().ToList();
                string undoDir = Path.Combine(dir, "desfeitos");
                foreach (var l in revert)
                {
                    try
                    {
                        if (l[0] == "REN")
                        {
                            // Grenam: o original volta a ser g<nome>.exe (oculto), como estava
                            string hidden = l[1], path = l[2];
                            if (File.Exists(path) && !File.Exists(hidden))
                            {
                                File.Move(path, hidden);
                                File.SetAttributes(hidden, FileAttributes.Hidden);
                                Log("Original devolvido a " + hidden, LogLevel.Ok);
                            }
                        }
                        else if (File.Exists(l[1]))
                        {
                            Directory.CreateDirectory(undoDir);
                            string dest = Path.Combine(undoDir, DateTime.Now.ToString("HHmmssfff") + "_" + San(Path.GetFileName(l[1])));
                            File.Move(l[1], dest);
                            Log("Original recuperado guardado em " + dest + " (o infectado volta ao lugar).", LogLevel.Ok);
                        }
                    }
                    catch (Exception ex) { Log("Falha ao reverter a desinfecção de " + l[1] + ": " + ex.Message, LogLevel.Error); }
                }
                foreach (var l in lines.Where(l => l[0] == "HOSTS"))
                    try
                    {
                        File.SetAttributes(l[2], FileAttributes.Normal);
                        File.Copy(l[1], l[2], true);
                        Log("hosts restaurado: " + l[2], LogLevel.Ok);
                    }
                    catch (Exception ex) { Log("Falha ao restaurar o hosts: " + ex.Message, LogLevel.Error); }
                foreach (var l in lines.Where(l => l[0] == "ATTR"))
                    try
                    {
                        File.SetAttributes(l[1], (FileAttributes)int.Parse(l[2]));
                        Log("Atributos restaurados: " + l[1], LogLevel.Ok);
                    }
                    catch (Exception ex) { Log("Falha ao restaurar atributos de " + l[1] + ": " + ex.Message, LogLevel.Error); }
                var vdirs = lines.Where(l => l[0] == "VDIR").ToList();
                foreach (var l in vdirs)
                    try { if (Directory.Exists(l[1]) && !Directory.EnumerateFileSystemEntries(l[1]).Any()) Directory.Delete(l[1]); } catch { }

                var files = lines.Where(l => l[0] == "FILE").ToList();
                n = 0;
                foreach (var l in files)
                {
                    ct.ThrowIfCancellationRequested();
                    string orig = l[1], q = l[2];
                    CurrentItem = orig;
                    try
                    {
                        if (!File.Exists(q)) Log("Arquivo da quarentena não encontrado: " + q, LogLevel.Warn);
                        else if (File.Exists(orig)) Log("Já existe um arquivo em " + orig + " — mantido na quarentena.", LogLevel.Warn);
                        else
                        {
                            RestoreFromQuarantine(q, orig, l.Length > 4 && l[4] == "X", l.Length > 5 ? l[5] : null);
                            Log("Restaurado: " + orig, LogLevel.Ok);
                        }
                    }
                    catch (Exception ex) { Log("Falha ao restaurar " + orig + ": " + ex.Message, LogLevel.Error); }
                    Frac(++n / (double)Math.Max(1, files.Count));
                }

                Begin(3);
                var regs = lines.Where(l => l[0] == "REG").ToList();
                n = 0;
                foreach (var l in regs)
                {
                    string outp;
                    CurrentItem = l.Length > 2 ? l[2] : l[1];
                    if (CurrentItem.Contains(@"\TJU_") || CurrentItem.Contains(@"\TJM_"))
                        Log("Registro offline não restaurado automaticamente (importe manualmente): " + l[1], LogLevel.Warn);
                    else if (RunTool("reg.exe", "import \"" + l[1] + "\"", out outp) == 0)
                        Log("Registro restaurado: " + CurrentItem, LogLevel.Ok);
                    else Log("Falha ao importar " + l[1] + ": " + outp, LogLevel.Error);
                    Frac(++n / (double)Math.Max(1, regs.Count));
                }

                Begin(4);
                var tasks = lines.Where(l => l[0] == "TASK").ToList();
                n = 0;
                foreach (var l in tasks)
                {
                    string outp;
                    if (RunTool("schtasks.exe", "/create /tn \"" + l[1] + "\" /xml \"" + l[2] + "\" /f", out outp) == 0)
                        Log("Tarefa restaurada: " + l[1], LogLevel.Ok);
                    else Log("Falha ao restaurar tarefa " + l[1] + ": " + outp, LogLevel.Error);
                    Frac(++n / (double)Math.Max(1, tasks.Count));
                }

                File.Move(mf, Path.Combine(dir, "manifesto_desfeito_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt"));
                Complete();
                CurrentItem = "";
                Log("Limpeza desfeita.", LogLevel.Ok);
            }
            catch (OperationCanceledException) { Log("Restauração interrompida.", LogLevel.Warn); }
            catch (Exception ex) { Log("Erro ao desfazer: " + ex.Message, LogLevel.Error); }
        }
    }
}
