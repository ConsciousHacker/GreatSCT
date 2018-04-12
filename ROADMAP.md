# Roadmap
This is the GreatSCT 1.0 development roadmap.

## Payloads

### MSBuild
- [x] msbuild/meterpreter/rev_https - Chris
- [x] msbuild/meterpreter/rev_http - Chris
- [x] msbuild/meterpreter/rev_tcp - Chris
- [x] msbuild/shellcode_inject/virtual.py - Chris
- [x] msbuild/shellcode_inject/base64.py - Chris
- [ ] msbuild/powershell/cmd.py
- [x] msbuild/powershell/script.py - Chris

### InstallUtil
- [x] installutil/meterpreter/rev_https - Chris
- [x] installutil/meterpreter/rev_http - Chris
- [x] installutil/meterpreter/rev_tcp - Chris
- [x] installutil/shellcode_inject/virtual.py
- [x] installutil/shellcode_inject/base64.py - Chris
- [ ] installutil/powershell/cmd.py
- [x] installutil/powershell/script.py - Chris

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
- [x] regasm/meterpreter/rev_https - Chris
- [x] regasm/meterpreter/rev_http - Chris
- [x] regasm/meterpreter/rev_tcp - Chris
- [x] regasm/shellcode_inject/virtual.py - Chris
- [x] regasm/shellcode_inject/base64.py - Chris
- [ ] regasm/powershell/cmd.py
- [x] regasm/powershell/script.py - Chris

### Regsvcs
- [x] regsvcs/meterpreter/rev_https - Chris
- [x] regsvcs/meterpreter/rev_http - Chris
- [x] regsvcs/meterpreter/rev_tcp - Chris
- [x] regsvcs/shellcode_inject/virtual.py - Chris
- [x] regsvcs/shellcode_inject/base64.py - Chris
- [ ] regsvcs/powershell/cmd.py
- [x] regsvcs/powershell/script.py - Chris

### Regsvr32
- [ ] regsvr32/meterpreter/rev_https
- [ ] regsvr32/meterpreter/rev_http
- [ ] regsvr32/meterpreter/rev_tcp
- [ ] regsvr32/shellcode_inject/virtual.py
- [ ] regsvr32/shellcode_inject/base64.py
- [ ] regsvr32/powershell/cmd.py
- [ ] regsvr32/powershell/script.py

###  pubprn.vbs
- [ ] pubprn/meterpreter/rev_https
- [ ] pubprn/meterpreter/rev_http
- [ ] pubprn/meterpreter/rev_tcp
- [ ] pubprn/shellcode_inject/virtual.py
- [ ] pubprn/shellcode_inject/base64.py
- [ ] pubprn/powershell/cmd.py
- [ ] pubprn/powershell/script.py

## Features

- [x] Basic random variable renaming obfuscation - Chris
- [x] Sandbox detection - Chris
- [ ] GenerateAll
- Invoke-Obfuscation python ports
    + [x] ASCII encoding - Chris
    + [ ] Binary encoding
    + [ ] Any other favorites?

## TODO
- [ ] Fix CLI generation
- [ ] Modify setup script to support all the Linux distributions
- [ ] Make C# imports more dynamic

## Decisions
- Implement phyperion encryption for exe and dll payloads
- Ordnance from Veil 3.0
- Mshta obfuscation with various encoding methods
