using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TJRemover
{
    static class Native
    {
        public const int PROCESS_TERMINATE = 0x0001;
        public const int PROCESS_SUSPEND_RESUME = 0x0800;
        public const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const int SYNCHRONIZE = 0x00100000;
        public const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr h, uint exitCode);

        [DllImport("kernel32.dll")]
        public static extern uint WaitForSingleObject(IntPtr h, uint ms);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder sb, ref int size);

        [DllImport("ntdll.dll")]
        public static extern int NtSuspendProcess(IntPtr h);

        [DllImport("user32.dll")]
        public static extern int GetWindowLong(IntPtr h, int index);

        [DllImport("user32.dll")]
        public static extern bool ShowScrollBar(IntPtr h, int bar, bool show);

        [DllImport("shell32.dll")]
        public static extern void SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool MoveFileEx(string src, string dst, int flags);

        // ---------------------------------------------------------------- Restart Manager
        public class Locker { public int Pid; public string Name; public bool Critical; }

        [StructLayout(LayoutKind.Sequential)]
        struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
            public int ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        static extern int RmStartSession(out uint handle, int flags, StringBuilder key);
        [DllImport("rstrtmgr.dll")]
        static extern int RmEndSession(uint handle);
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        static extern int RmRegisterResources(uint handle, uint nFiles, string[] files, uint nApps, IntPtr apps, uint nServices, string[] services);
        [DllImport("rstrtmgr.dll")]
        static extern int RmGetList(uint handle, out uint needed, ref uint count, [In, Out] RM_PROCESS_INFO[] info, ref uint reasons);

        /// <summary>Processos que estão com o arquivo aberto (Restart Manager do Windows, sem handle.exe).</summary>
        public static System.Collections.Generic.List<Locker> GetLockingProcesses(string path)
        {
            var res = new System.Collections.Generic.List<Locker>();
            uint h;
            if (RmStartSession(out h, 0, new StringBuilder(64)) != 0) return res;
            try
            {
                if (RmRegisterResources(h, 1, new[] { path }, 0, IntPtr.Zero, 0, null) != 0) return res;
                uint needed, count = 0, reasons = 0;
                int rc = RmGetList(h, out needed, ref count, null, ref reasons);
                if (rc != 234 || needed == 0) return res;   // ERROR_MORE_DATA
                var info = new RM_PROCESS_INFO[needed];
                count = needed;
                if (RmGetList(h, out needed, ref count, info, ref reasons) != 0) return res;
                for (int i = 0; i < count; i++)
                    res.Add(new Locker
                    {
                        Pid = info[i].Process.dwProcessId, Name = info[i].strAppName,
                        Critical = info[i].ApplicationType == 1000 || info[i].ApplicationType == 3   // RmCritical / RmService
                    });
            }
            catch { }
            finally { RmEndSession(h); }
            return res;
        }

        // ---------------------------------------------------------------- assinatura digital (Authenticode)
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO { public int cbStruct; public string pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public int cbStruct; public IntPtr pPolicyCallbackData; public IntPtr pSIPClientData; public int dwUIChoice;
            public int fdwRevocationChecks; public int dwUnionChoice; public IntPtr pFile; public int dwStateAction;
            public IntPtr hWVTStateData; public IntPtr pwszURLReference; public int dwProvFlags; public int dwUIContext; public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WINTRUST_DATA data);

        static readonly Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        /// <summary>true se o arquivo tem assinatura digital válida embutida (sem consultar a internet).</summary>
        public static bool IsSigned(string path)
        {
            IntPtr pFile = IntPtr.Zero;
            try
            {
                var fi = new WINTRUST_FILE_INFO { cbStruct = Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path };
                pFile = Marshal.AllocHGlobal(fi.cbStruct);
                Marshal.StructureToPtr(fi, pFile, false);
                var wd = new WINTRUST_DATA
                {
                    cbStruct = Marshal.SizeOf(typeof(WINTRUST_DATA)), dwUIChoice = 2 /*WTD_UI_NONE*/, fdwRevocationChecks = 0,
                    dwUnionChoice = 1 /*WTD_CHOICE_FILE*/, pFile = pFile, dwStateAction = 0, dwProvFlags = 0x1000 /*WTD_CACHE_ONLY_URL_RETRIEVAL*/
                };
                return WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, ref wd) == 0;
            }
            catch { return false; }
            finally { if (pFile != IntPtr.Zero) { Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO)); Marshal.FreeHGlobal(pFile); } }
        }

        public static string GetProcessPath(int pid)
        {
            IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
            }
            finally { CloseHandle(h); }
        }
    }
}
