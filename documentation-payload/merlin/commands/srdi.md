+++
title = "srdi"
chapter = false
weight = 100
hidden = false
+++

## Summary

sRDI allows for the conversion of DLL files to position independent shellcode.
It attempts to be a fully functional PE loader supporting proper section permissions,
TLS callbacks, and sanity checks. It can be thought of as a shellcode PE loader strapped to a 
packed DLL. <https://github.com/monoxgas/sRDI>

- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

See the [Detailed Summary](#detailed-summary) section for additional information

### Arguments

#### dll

- Description: DLL to convert to shellcode
- Required Value: True
- Default Value: None

#### path

- Description: The directory path to change to
- Required Value: True
- Default Value: None

#### function-name

- Description: The function to call after DllMain
- Required Value: False
- Default Value: None

#### user-data

- Description: Data to pass to the target function
- Required Value: False
- Default Value: None

#### clear-header

- Description: Clear the PE header on load
- Required Value: False
- Default Value: False

#### obfuscate-imports

- Description: Randomize import dependency load order
- Required Value: False
- Default Value: False

#### import-delay

- Description: Number of seconds to pause between loading imports
- Required Value: False
- Default Value: None

#### verbose

- Description: Show verbose output from sRDI
- Required Value: False
- Default Value: False

#### method

- Description: The shellcode injection method to use. Use createprocess if you want output back
- Choices: createprocess, self, remote, RtlCreateUserThread, userapc
- Required Value: True
- Default Value: None

#### pid

- Description: The Process ID (PID) to inject the shellcode into. Not used with the `self` method
- Required Value: False
- Default Value: None

#### spawnto

- Description: The child process that will be started to execute the shellcode in. Only used with the createprocess method
- Required Value: True
- Default Value: C:\Windows\System32\WerFault.exe

#### spawntoargs

- Description: Argument to create the `spawnto` process with, if any. Only used with the createprocess method
- Required Value: False
- Default Value: None

## Usage

Use the pop-up dialog box

## MITRE ATT&CK Mapping

- [T1055](https://attack.mitre.org/techniques/T1055/) Process Injection
- [T1055.001](https://attack.mitre.org/techniques/T1055/002/) Process Injection: Portable Executable Injection
- [T1055.004](https://attack.mitre.org/techniques/T1055/004/) Process Injection: Asynchronous Procedure Call
- [T1055.012](https://attack.mitre.org/techniques/T1055/012/) Process Injection: Process Hollowing

## Detailed Summary

The `srdi` command uses the [sRDI](https://github.com/monoxgas/sRDI) tool to convert a DLL into a shellcode.
The shellcode is executed with either the [createprocess](./../createprocess) or 
[execute-shellcode](./../execute-shellcode) command.