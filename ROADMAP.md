# Roadmap
This is the GreatSCT 1.0 development roadmap.

## Payloads

### MSBuild
- [x] msbuild/meterpreter/rev_https - Chris
- [ ] msbuild/meterpreter/rev_http
- [ ] msbuild/meterpreter/rev_tcp
- [x] msbuild/shellcode_inject/virtual.py - Chris
- [ ] msbuild/shellcode_inject/base64.py
- [ ] msbuild/powershell/cmd.py
- [ ] msbuild/powershell/script.py

### InstallUtil
- [ ] installutil/meterpreter/rev_https
- [ ] installutil/meterpreter/rev_http
- [ ] installutil/meterpreter/rev_tcp
- [ ] installutil/shellcode_inject/virtual.py
- [x] installutil/shellcode_inject/base64.py - Chris
- [ ] installutil/powershell/cmd.py
- [ ] installutil/powershell/script.py

### Mshta
- [ ] mshta/meterpreter/rev_https
- [ ] mshta/meterpreter/rev_http
- [ ] mshta/meterpreter/rev_tcp
- [ ] mshta/shellcode_inject/virtual.py
- [ ] mshta/shellcode_inject/base64.py - Chris (WIP)
    - Working on process migration and DotNotToJScript on Linux
    - This means each serialized object will be random within our HTAs.
- [ ] mshta/powershell/cmd.py
- [ ] mshta/powershell/script.py
- [ ] mshta/msbuild/*

### Regasm
- [ ] regasm/meterpreter/rev_https
- [ ] regasm/meterpreter/rev_http
- [ ] regasm/meterpreter/rev_tcp
- [ ] regasm/shellcode_inject/virtual.py
- [ ] regasm/shellcode_inject/base64.py
- [ ] regasm/powershell/cmd.py
- [ ] regasm/powershell/script.py

### Regsvcs
- [ ] regsvcs/meterpreter/rev_https
- [ ] regsvcs/meterpreter/rev_http
- [ ] regsvcs/meterpreter/rev_tcp
- [ ] regsvcs/shellcode_inject/virtual.py
- [ ] regsvcs/shellcode_inject/base64.py
- [ ] regsvcs/powershell/cmd.py
- [ ] regsvcs/powershell/script.py

### Regsvr32
- [ ] regsvr32/meterpreter/rev_https
- [ ] regsvr32/meterpreter/rev_http
- [ ] regsvr32/meterpreter/rev_tcp
- [ ] regsvr32/shellcode_inject/virtual.py
- [ ] regsvr32/shellcode_inject/base64.py
- [ ] regsvr32/powershell/cmd.py
- [ ] regsvr32/powershell/script.py

### Rundll32
- [ ] rundll32/meterpreter/rev_https
- [ ] rundll32/meterpreter/rev_http
- [ ] rundll32/meterpreter/rev_tcp
- [ ] rundll32/shellcode_inject/virtual.py
- [ ] rundll32/shellcode_inject/base64.py
- [ ] rundll32/powershell/cmd.py
- [ ] rundll32/powershell/script.py

## Features

- [x] Basic random variable renaming obfuscation - Chris
- [x] Sandbox detection - Chris
- [ ] GenerateAll
- Invoke-Obfuscation python ports
    + [x] ASCII encoding - Chris
    + [ ] Binary encoding
    + [ ] Any other favorites?

## Decisions
- Implement phyperion encryption for exe and dll payloads
- Ordnance from Veil 3.0
- Mshta obfuscation with various encoding methods
