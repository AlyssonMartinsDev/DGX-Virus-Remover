using System;

namespace TJRemover
{
    public enum FindingKind { Process, MaliciousFile, InfectedFile, Registry, Service, Task, Autorun, Policy, Suspicious, HiddenFolder, Hosts, Warning }
    public enum Severity { Critico, Alto, Medio, Info }
    public enum RegAction { DeleteValue, SetValue, SetDword }
    public enum LogLevel { Info, Ok, Warn, Error, Title }

    public class LogEntry
    {
        public DateTime Time;
        public string Text;
        public LogLevel Level;
    }

    public class ScanOptions
    {
        public bool DeepScan = true;    // procura executáveis infectados
        public bool WholeDisk = false;  // disco inteiro em vez das pastas de programas/usuários
        public bool Removable = true;   // pendrives
        public bool Offline = true;     // perfis não carregados e Windows em outros discos
        public bool Vaccine = true;     // vacina após a limpeza
        public bool Persistence = true; // inicialização, programas suspeitos e configurações de segurança do Windows
        public bool DefenderConfirm;    // confirma os suspeitos com o Windows Defender (MpCmdRun)
        public bool SystemChecks = true;// locais conhecidos, processos, registro, serviços (false = só a pasta escolhida)
        public string CustomFolder;     // varre só esta pasta (modo "Pasta escolhida" / pendrive)
        public string ModeName = "Completa";
    }

    public class Finding
    {
        public FindingKind Kind;
        public Severity Severity;
        public string Title = "";
        public string Detail = "";
        public string Status = "Detectado";
        public bool Selected = true;
        public bool Done;

        public int Pid;
        public string FilePath;

        public string RegRoot;      // "HKLM" ou "HKU"
        public string RegKey;       // caminho abaixo da raiz
        public string RegValue;
        public RegAction RegAct;
        public string RegNewValue;

        public string ServiceName;
        public string TaskName;     // nome no Agendador (Windows em execução)
        public string TaskFile;     // arquivo da tarefa (.xml / .job)

        public object Tag;          // ListViewItem na interface

        public VirusFamily Family;  // família reconhecida (TJprojMain, Synaptics, Mofksys, Grenam)
        public bool Disinfect;      // o programa original pode ser recuperado
        public string Extra;        // dados extras (ex.: linhas do hosts a remover)

        public bool Failed { get { return Status != null && Status.StartsWith("Falha"); } }

        public string FamilyText { get { return Families.Short(Family); } }

        public string KindText
        {
            get
            {
                string fam = Family == VirusFamily.None ? "" : " · " + FamilyText;
                switch (Kind)
                {
                    case FindingKind.Process: return "Processo ativo" + fam;
                    case FindingKind.MaliciousFile: return "Arquivo do vírus" + fam;
                    case FindingKind.InfectedFile: return (Disinfect ? "Infectado (recuperável)" : "Executável infectado") + fam;
                    case FindingKind.Registry: return "Inicialização";
                    case FindingKind.Service: return "Serviço";
                    case FindingKind.Task: return "Tarefa agendada";
                    case FindingKind.Autorun: return "Pendrive" + fam;
                    case FindingKind.Suspicious: return "Suspeito";
                    case FindingKind.HiddenFolder: return "Pasta escondida";
                    case FindingKind.Hosts: return "Arquivo hosts";
                    case FindingKind.Warning: return "Aviso";
                    default: return "Configuração de segurança";
                }
            }
        }

        public string SeverityText
        {
            get
            {
                switch (Severity)
                {
                    case Severity.Critico: return "Crítico";
                    case Severity.Alto: return "Alto";
                    case Severity.Medio: return "Médio";
                    default: return "Aviso";
                }
            }
        }

        public string Key
        {
            get
            {
                return Kind + "|" + (FilePath ?? "") + "|" + Pid + "|" + (RegRoot ?? "") + "\\" + (RegKey ?? "") + "|" +
                       (RegValue ?? "") + "|" + (ServiceName ?? "") + "|" + (TaskName ?? TaskFile ?? "");
            }
        }
    }
}
