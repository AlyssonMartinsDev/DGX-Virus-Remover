using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace TJRemover
{
    public enum AllowType { File, Folder, Hash, Registry }

    public class AllowEntry
    {
        public AllowType Type;
        public string Value;      // caminho, pasta, SHA256 ou "HKLM\chave|valor"
        public string Note = "";  // de onde veio (nome do arquivo, data)
        public string TypeText
        {
            get
            {
                switch (Type)
                {
                    case AllowType.File: return "Arquivo";
                    case AllowType.Folder: return "Pasta (e subpastas)";
                    case AllowType.Hash: return "Conteúdo (SHA256)";
                    default: return "Registro";
                }
            }
        }
    }

    /// <summary>
    /// Arquivos, pastas, conteúdos (SHA256) e entradas de registro que o usuário marcou como
    /// "não é vírus". Ficam em %ProgramData%\DGX Virus Remover\permitidos.txt.
    /// </summary>
    public static class Allowlist
    {
        public static string FileOverride;   // testes
        static readonly object sync = new object();
        static List<AllowEntry> entries;

        public static string DataDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DGX Virus Remover"); }
        }

        static string FilePath { get { return FileOverride ?? Path.Combine(DataDir, "permitidos.txt"); } }

        public static List<AllowEntry> All
        {
            get { lock (sync) { Load(); return entries.ToList(); } }
        }

        static void Load()
        {
            if (entries != null) return;
            entries = new List<AllowEntry>();
            try
            {
                if (!File.Exists(FilePath)) return;
                foreach (var line in File.ReadAllLines(FilePath, Encoding.UTF8))
                {
                    var p = line.Split('\t');
                    if (p.Length < 2 || line.StartsWith("#")) continue;
                    AllowType t;
                    if (!Enum.TryParse(p[0], out t)) continue;
                    entries.Add(new AllowEntry { Type = t, Value = p[1], Note = p.Length > 2 ? p[2] : "" });
                }
            }
            catch { }
        }

        static void Save()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath));
                var sb = new StringBuilder("# DGX Virus Remover — itens permitidos (tipo<TAB>valor<TAB>observação)\r\n");
                foreach (var e in entries) sb.AppendLine(e.Type + "\t" + e.Value + "\t" + (e.Note ?? "").Replace("\t", " "));
                File.WriteAllText(FilePath, sb.ToString(), new UTF8Encoding(false));
            }
            catch { }
        }

        public static void Reload() { lock (sync) { entries = null; Load(); } }

        public static void Add(AllowType t, string value, string note)
        {
            if (string.IsNullOrEmpty(value)) return;
            if (t == AllowType.Folder && !value.EndsWith("\\")) value += "\\";
            lock (sync)
            {
                Load();
                if (entries.Any(e => e.Type == t && string.Equals(e.Value, value, StringComparison.OrdinalIgnoreCase))) return;
                entries.Add(new AllowEntry { Type = t, Value = value, Note = note ?? "" });
                Save();
            }
        }

        public static void Remove(AllowEntry x)
        {
            lock (sync)
            {
                Load();
                entries.RemoveAll(e => e.Type == x.Type && string.Equals(e.Value, x.Value, StringComparison.OrdinalIgnoreCase));
                Save();
            }
        }

        public static bool HasHashes { get { lock (sync) { Load(); return entries.Any(e => e.Type == AllowType.Hash); } } }

        /// <summary>Caminho permitido (arquivo exato ou dentro de uma pasta permitida).</summary>
        public static bool IsPathAllowed(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            lock (sync)
            {
                Load();
                foreach (var e in entries)
                {
                    if (e.Type == AllowType.File && string.Equals(e.Value, path, StringComparison.OrdinalIgnoreCase)) return true;
                    if (e.Type == AllowType.Folder && path.StartsWith(e.Value, StringComparison.OrdinalIgnoreCase)) return true;
                }
            }
            return false;
        }

        public static bool IsHashAllowed(string sha)
        {
            if (string.IsNullOrEmpty(sha)) return false;
            lock (sync)
            {
                Load();
                return entries.Any(e => e.Type == AllowType.Hash && string.Equals(e.Value, sha, StringComparison.OrdinalIgnoreCase));
            }
        }

        public static string RegKey(string root, string key, string value) { return root + "\\" + key + "|" + (value ?? ""); }

        public static bool IsRegAllowed(string root, string key, string value)
        {
            string k = RegKey(root, key, value);
            lock (sync)
            {
                Load();
                return entries.Any(e => e.Type == AllowType.Registry && string.Equals(e.Value, k, StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    /// <summary>Preferências simples (chave=valor) em %ProgramData%\DGX Virus Remover\config.ini.</summary>
    public static class Settings
    {
        static string FilePath { get { return Path.Combine(Allowlist.DataDir, "config.ini"); } }

        public static string Get(string key, string def)
        {
            try
            {
                if (File.Exists(FilePath))
                    foreach (var l in File.ReadAllLines(FilePath))
                    {
                        int i = l.IndexOf('=');
                        if (i > 0 && l.Substring(0, i).Trim() == key) return l.Substring(i + 1).Trim();
                    }
            }
            catch { }
            return def;
        }

        public static void Set(string key, string value)
        {
            try
            {
                Directory.CreateDirectory(Allowlist.DataDir);
                var lines = File.Exists(FilePath) ? File.ReadAllLines(FilePath).ToList() : new List<string>();
                lines.RemoveAll(l => l.StartsWith(key + "="));
                lines.Add(key + "=" + value);
                File.WriteAllLines(FilePath, lines);
            }
            catch { }
        }
    }
}
