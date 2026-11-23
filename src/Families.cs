using System;
using System.IO;
using System.Text;

namespace TJRemover
{
    public enum VirusFamily { None, TJ, SynapticsV1, SynapticsV2, Mofksys, Grenam, Sality, FileInfector }

    /// <summary>O que fazer com um executável de uma família conhecida.</summary>
    public class DisinfectPlan
    {
        public VirusFamily Family;
        public byte[] Original;        // programa original recuperado (Synaptics / Mofksys)
        public long OriginalOffset = -1;
        public string RestoreFrom;     // Grenam: original escondido "g<nome>.exe"
        public bool WormOnly;          // é o próprio vírus (sem programa original) → quarentena
        public string Note = "";
        public bool CanRestore { get { return Original != null || RestoreFrom != null; } }
    }

    /// <summary>
    /// Detecção e desinfecção das famílias tratadas pelo "Synaptics Killer" (Car-Tech), reimplementadas e
    /// endurecidas: o original recuperado é validado como executável PE e o tamanho é calculado pelo
    /// cabeçalho dele, em vez de confiar só em "último MZ".
    /// As assinaturas ficam cifradas (XOR) para que ESTE programa não seja detectado por ele mesmo.
    /// </summary>
    public static class Families
    {
        static byte[] D(string hex)
        {
            var b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = (byte)(Convert.ToByte(hex.Substring(i * 2, 2), 16) ^ 0x5A);
            return b;
        }

        static readonly byte[] DriveWatcher = D("5A1E28332C3F7A0D3B2E39323F287A092E352A7A77647A5A"); // "\0Drive Watcher Stop -> \0"
        static readonly byte[] SynV2 = D("4DC160D917000A5A585A5A5A5E5A555AA5A55A5AE25A5A5A");        // 17 9B 3A 83 + cabeçalho Delphi MZP
        static readonly byte[] MofCode = D("4B1A5A87C772A7A5A59D1FA67E5A5A5A");                        // trecho de código do Mofksys
        static readonly byte[] MofVbp = D("5E425A5A52EA1B5ABC7F1A5A5AEA1B5A705A065A1B5A1C5A605A065A085A1C5A1E5A065A225A145A3F5A2D5A195A355A3E5A3F5A065A225A145A3F5A2D5A0A5A285A355A065A225A0E5A065A2E5A285A305A1C5A145A065A0A5A285A355A305A3F5A395A2E5A6B5A745A2C5A385A2A5A"); // projeto VB6 do Mofksys
        static readonly byte[] CodeGear = D("7857507A7A7A7A343B373F677819353E3F1D3F3B287A081B1E7A092E2F3E3335");      // manifesto Delphi
        static readonly byte[] GrenamCode = D("B2BDA7A5A5D1823065305B305AE35B5A5A5AE05B5A5A5AD199B294A7A5A5D1823065305B305AE35B5A5A5A6988D199B2"); // código do Grenam
        static readonly byte[] MofMarker = D("92CD94FA0C0480E8");                                       // marcador antes do original no Mofksys
        static readonly byte[] ResOriginal = D("1F5A025A1F5A085A1F5A095A025A");   // nome de recurso UTF-16 onde o Synaptics guarda o original
        static readonly byte[] ResVersion = D("1F5A025A1F5A0C5A095A145A025A");    // nome de recurso UTF-16 da versão do Synaptics
        static readonly byte[] MZ = { 0x4D, 0x5A };
        static readonly byte[] MZP = { 0x4D, 0x5A, 0x50 };

        public const long GrenamSize = 534016;   // tamanho do worm Grenam (constante do Killer)
        public const string GrenamDropper = "Ground.exe";

        public static string Name(VirusFamily f)
        {
            switch (f)
            {
                case VirusFamily.TJ: return Engine.V;
                case VirusFamily.SynapticsV1: return "Synaptics V1";
                case VirusFamily.SynapticsV2: return "Synaptics V2";
                case VirusFamily.Mofksys: return "Mofksys";
                case VirusFamily.Grenam: return "Grenam";
                case VirusFamily.Sality: return "Sality";
                case VirusFamily.FileInfector: return "Vírus de arquivo";
                default: return "";
            }
        }

        // Seções de empacotadores/protetores legítimos que também têm o ponto de entrada numa seção gravável no fim
        static readonly string[] PackerSections = { "upx", ".aspack", ".adata", "aspack", ".petite", ".mpress", "mpress", ".enigma", ".vmp", ".themida", ".winlice", ".packed",
            "pec", ".pec", ".nsp", "nsp", ".boom", ".perplex", ".yp", ".rlpack", ".mew", "mew", ".ccg", ".spack", ".svkp", ".taz", ".tsuarch", ".wwpack", "kkrunchy", ".neolit", ".exe32" };

        /// <summary>
        /// Padrão de vírus que se ANEXA ao programa (Sality, Virut, Expiro, Parite…): o ponto de entrada fica na
        /// última seção, que é gravável e executável. Só serve de triagem — a confirmação é feita pelo Defender.
        /// </summary>
        public static string AppenderHeuristic(byte[] d, int len)
        {
            try
            {
                if (len < 0x400 || !IsPE(d, 0)) return null;
                int pe = BitConverter.ToInt32(d, 0x3C);
                int nsec = BitConverter.ToUInt16(d, pe + 6), osz = BitConverter.ToUInt16(d, pe + 20);
                ushort chars = BitConverter.ToUInt16(d, pe + 22);
                if ((chars & 0x2000) != 0 || nsec < 2 || nsec > 40) return null;     // DLL ou estrutura estranha
                int opt = pe + 24;
                uint ep = BitConverter.ToUInt32(d, opt + 16);
                int tab = opt + osz;
                if (tab + nsec * 40 > len) return null;
                int last = -1, epSec = -1;
                for (int i = 0; i < nsec; i++)
                {
                    int so = tab + i * 40;
                    uint vs = BitConverter.ToUInt32(d, so + 8), va = BitConverter.ToUInt32(d, so + 12), rs = BitConverter.ToUInt32(d, so + 16);
                    if (rs > 0) last = i;
                    if (ep >= va && ep < va + Math.Max(vs, rs)) epSec = i;
                }
                if (epSec < 0 || epSec != last || epSec == 0) return null;
                int s = tab + epSec * 40;
                uint ch = BitConverter.ToUInt32(d, s + 36);
                if ((ch & 0x20000000) == 0 || (ch & 0x80000000) == 0) return null;   // precisa ser executável E gravável
                string name = Encoding.ASCII.GetString(d, s, 8).TrimEnd('\0').ToLowerInvariant();
                foreach (var p in PackerSections) if (name.StartsWith(p)) return null;
                if (name == ".rsrc" || name == ".reloc" || name == ".data" || name.Length == 0 || name == ".text" && nsec <= 3)
                    return "Ponto de entrada na última seção (\"" + name + "\"), gravável e executável — padrão de vírus que se anexa ao programa (Sality, Virut, Expiro).";
                return "Ponto de entrada na última seção (\"" + name + "\"), gravável e executável — padrão de vírus que se anexa ao programa (Sality, Virut, Expiro) ou de empacotador desconhecido.";
            }
            catch { return null; }
        }

        static readonly System.Text.RegularExpressions.Regex RxInfectorThreat = new System.Text.RegularExpressions.Regex(
            @"^Virus:(Win32|Win64)/(Sality|Virut|Ramnit|Expiro|Neshta|Parite|Jadtre|Xpaj|Mabezat|Floxif|Nabucur|Elkern|Polip|Viking|Madang|Induc|Pioneer|Shodi|Zusy|Lamer|Chir|Patchload)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        /// <summary>Família a partir do nome que o Defender deu (vírus que infectam outros programas).</summary>
        public static VirusFamily FromDefenderName(string threat)
        {
            if (string.IsNullOrEmpty(threat) || !RxInfectorThreat.IsMatch(threat)) return VirusFamily.None;
            return threat.IndexOf("Sality", StringComparison.OrdinalIgnoreCase) >= 0 ? VirusFamily.Sality : VirusFamily.FileInfector;
        }

        public static string Short(VirusFamily f)
        {
            switch (f)
            {
                case VirusFamily.SynapticsV1:
                case VirusFamily.SynapticsV2: return "Synaptics";
                case VirusFamily.None: return "";
                default: return Name(f);
            }
        }

        // ------------------------------------------------------------------ busca de bytes
        public static int IndexOf(byte[] b, int len, byte[] p, int start)
        {
            if (start < 0) start = 0;
            int last = len - p.Length;
            int i = start;
            while (i <= last)
            {
                i = Array.IndexOf(b, p[0], i, last - i + 1);
                if (i < 0) return -1;
                int j = 1;
                while (j < p.Length && b[i + j] == p[j]) j++;
                if (j == p.Length) return i;
                i++;
            }
            return -1;
        }

        static int LastIndexOf(byte[] b, byte[] p)
        {
            for (int i = b.Length - p.Length; i >= 0; i--)
            {
                if (b[i] != p[0]) continue;
                int j = 1;
                while (j < p.Length && b[i + j] == p[j]) j++;
                if (j == p.Length) return i;
            }
            return -1;
        }

        static bool Has(byte[] b, int len, byte[] p) { return IndexOf(b, len, p, 0) >= 0; }

        // ------------------------------------------------------------------ classificação
        /// <summary>Mesma árvore de decisão do Killer (o buffer pode ser só início+fim do arquivo).</summary>
        public static VirusFamily Classify(byte[] b, int len)
        {
            if (b == null || len < 64) return VirusFamily.None;
            if (Has(b, len, DriveWatcher)) return Has(b, len, SynV2) ? VirusFamily.SynapticsV2 : VirusFamily.SynapticsV1;
            // variante sem o texto "Drive Watcher": os dois recursos típicos do Synaptics (confirmado em amostras reais)
            if (b[0] == 'M' && b[1] == 'Z' && b[2] == 'P' && Has(b, len, ResOriginal) && Has(b, len, ResVersion)) return VirusFamily.SynapticsV1;
            if (Has(b, len, MofCode)) return Has(b, len, MofVbp) ? VirusFamily.Mofksys : VirusFamily.None;
            if (Has(b, len, CodeGear) && Has(b, len, GrenamCode)) return VirusFamily.Grenam;
            return VirusFamily.None;
        }

        // ------------------------------------------------------------------ PE
        public static bool IsPE(byte[] d, long s)
        {
            if (s < 0 || s + 0x40 > d.Length || d[s] != 'M' || d[s + 1] != 'Z') return false;
            int lf = BitConverter.ToInt32(d, (int)s + 0x3C);
            if (lf < 0x40 || lf > 0x1000 || s + lf + 0x18 > d.Length) return false;
            long pe = s + lf;
            if (d[pe] != 'P' || d[pe + 1] != 'E' || d[pe + 2] != 0 || d[pe + 3] != 0) return false;
            ushort mach = BitConverter.ToUInt16(d, (int)pe + 4);
            return mach == 0x14C || mach == 0x8664 || mach == 0x1C0 || mach == 0xAA64;
        }

        /// <summary>Tamanho do executável a partir do cabeçalho: fim da maior seção e da assinatura digital.</summary>
        public static long PeSize(byte[] d, long s)
        {
            try
            {
                int lf = BitConverter.ToInt32(d, (int)s + 0x3C);
                int pe = (int)(s + lf);
                int nsec = BitConverter.ToUInt16(d, pe + 6);
                int optSize = BitConverter.ToUInt16(d, pe + 20);
                int opt = pe + 24;
                ushort magic = BitConverter.ToUInt16(d, opt);
                long end = BitConverter.ToUInt32(d, opt + 60);      // SizeOfHeaders
                int secTab = opt + optSize;
                for (int i = 0; i < nsec && i < 96; i++)
                {
                    int so = secTab + i * 40;
                    if (so + 40 > d.Length) break;
                    long raw = BitConverter.ToUInt32(d, so + 16), ptr = BitConverter.ToUInt32(d, so + 20);
                    if (raw > 0 && ptr + raw > end) end = ptr + raw;
                }
                int dd = opt + (magic == 0x20B ? 112 : 96);           // data directories
                if (BitConverter.ToUInt32(d, opt + (magic == 0x20B ? 108 : 92)) > 4 && dd + 40 <= d.Length)
                {
                    long cOff = BitConverter.ToUInt32(d, dd + 32), cSize = BitConverter.ToUInt32(d, dd + 36);
                    if (cOff > 0 && cSize > 0 && cOff + cSize > end) end = cOff + cSize;   // offset de arquivo
                }
                return end;
            }
            catch { return -1; }
        }

        static byte[] Slice(byte[] d, long start, long len)
        {
            var r = new byte[len];
            Buffer.BlockCopy(d, (int)start, r, 0, (int)len);
            return r;
        }

        // ------------------------------------------------------------------ desinfecção
        /// <summary>Monta o plano para um arquivo (lido inteiro). Não altera nada no disco.</summary>
        public static DisinfectPlan Plan(string path, byte[] d)
        {
            var plan = new DisinfectPlan { Family = Classify(d, d.Length) };
            switch (plan.Family)
            {
                case VirusFamily.SynapticsV1:
                case VirusFamily.SynapticsV2:
                    PlanSynaptics(plan, d, plan.Family == VirusFamily.SynapticsV2 ? MZP : MZ);
                    break;
                case VirusFamily.Mofksys:
                    PlanMofksys(plan, d);
                    break;
                case VirusFamily.Grenam:
                    PlanGrenam(plan, path, d.LongLength);
                    break;
            }
            return plan;
        }

        /// <summary>Executável marcado com a assinatura do TJprojMain: tenta o formato Mofksys (mesmo vírus).</summary>
        public static DisinfectPlan PlanTJ(byte[] d)
        {
            var plan = new DisinfectPlan { Family = VirusFamily.TJ };
            if (IndexOf(d, d.Length, MofMarker, 0) >= 0) PlanMofksys(plan, d);
            plan.Family = VirusFamily.TJ;
            if (!plan.CanRestore) plan.Note = "Sem marcador de programa original: vai para a quarentena.";
            return plan;
        }

        static void PlanSynaptics(DisinfectPlan plan, byte[] d, byte[] needle)
        {
            int m = IndexOf(d, d.Length, DriveWatcher, 0);
            if (m < 0) m = 2;   // variante detectada pelos recursos: procura a partir do início (pula o MZ do próprio vírus)
            int last = LastIndexOf(d, needle);
            // regra do Killer: do primeiro MZ depois do marcador até 4 bytes antes do último MZ
            for (int s = IndexOf(d, d.Length, needle, m); s >= 0; s = IndexOf(d, d.Length, needle, s + 1))
            {
                if (!IsPE(d, s)) continue;
                long size = PeSize(d, s);
                if (size <= 0x200 || s + size > d.Length) continue;
                long killerLen = last > s ? last - 4 - s : -1;
                long len = killerLen >= size ? killerLen : size;   // mantém dados extras (instaladores) quando cabem
                plan.Original = Slice(d, s, len);
                plan.OriginalOffset = s;
                plan.Note = string.Format("Programa original embutido no deslocamento 0x{0:X} ({1:N0} bytes, cabeçalho PE válido).", s, len);
                return;
            }
            plan.WormOnly = true;
            plan.Note = "Nenhum programa original embutido: é o próprio vírus (ex.: Synaptics.exe).";
        }

        static void PlanMofksys(DisinfectPlan plan, byte[] d)
        {
            int k = IndexOf(d, d.Length, MofMarker, 0);
            while (k >= 0)
            {
                foreach (int skip in new[] { 9, 8, 10 })   // o Killer usa +9 (marcador + 1 byte)
                {
                    long s = (long)k + skip;
                    if (!IsPE(d, s)) continue;
                    long size = PeSize(d, s);
                    if (size <= 0x200 || s + size > d.Length) continue;
                    plan.Original = Slice(d, s, d.Length - s);      // até o fim do arquivo, como o Killer
                    plan.OriginalOffset = s;
                    plan.Note = string.Format("Programa original após o marcador do Mofksys (0x{0:X}, {1:N0} bytes, cabeçalho PE válido).", s, d.Length - s);
                    return;
                }
                k = IndexOf(d, d.Length, MofMarker, k + 1);
            }
            plan.WormOnly = true;
            plan.Note = "Sem programa original anexado: é o próprio vírus.";
        }

        static void PlanGrenam(DisinfectPlan plan, string path, long size)
        {
            string name = Path.GetFileName(path);
            if (string.Equals(name, GrenamDropper, StringComparison.OrdinalIgnoreCase))
            {
                plan.WormOnly = true; plan.Note = "Instalador do Grenam (" + GrenamDropper + ").";
                return;
            }
            string hidden = Path.Combine(Path.GetDirectoryName(path) ?? "", "g" + name);
            if (size == GrenamSize && File.Exists(hidden))
            {
                plan.RestoreFrom = hidden;
                plan.Note = "O Grenam escondeu o programa original como \"" + Path.GetFileName(hidden) + "\": ele volta ao nome certo.";
                return;
            }
            plan.WormOnly = true;
            plan.Note = File.Exists(hidden) ? "Tamanho diferente do worm conhecido; original \"g" + name + "\" não será mexido."
                                            : "Cópia do Grenam sem o original escondido ao lado.";
        }
    }
}
