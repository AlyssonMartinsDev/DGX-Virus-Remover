using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

namespace TJRemover
{
    static class Program
    {
        public const string AppName = "DGX Virus Remover";

        static bool IsAdmin()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        [STAThread]
        static void Main()
        {
            if (!IsAdmin())
            {
                try { Process.Start(new ProcessStartInfo(Application.ExecutablePath) { Verb = "runas", UseShellExecute = true }); }
                catch { MessageBox.Show("Este programa precisa ser executado como administrador.", AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
                return;
            }
            bool created;
            using (new Mutex(true, "Global\\DGXVirusRemover_UmaInstancia", out created))
            {
                if (!created)
                {
                    MessageBox.Show("O removedor já está aberto.", AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.ThreadException += (s, e) =>
                    MessageBox.Show("Erro inesperado:\r\n" + e.Exception.Message, AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Run(new MainForm());
            }
        }
    }
}
