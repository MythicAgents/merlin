+++
title = "createprocess"
chapter = false
weight = 100
hidden = false
+++

## Summary

The `createprocess` command uses process hollowing to create a child process from the `spawnto` argument, allocate the 
provided shellcode into it, execute it, and use anonymous pipes to collect STDOUT/STDERR.

- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

See the [Detailed Summary](#detailed-summary) section for additional information

### Arguments

#### shellcode

- Description: The shellcode file you want to execute in the `spawnto` process
- Required Value: True  
- Default Value: None  

#### spawnto

- Description: The child process that will be started to execute the shellcode in
- Required Value: True
- Default Value: `C:\Windows\System32\WerFault.exe`

#### spawntoargs

- Description: Argument to create the `spawnto` process with, if any
- Required Value: False
- Default Value: None

## Usage

```
createprocess <shellcode file> <spawnto> <spawntoargs>
```

The preferred method is to type `createprocess` and press enter while on the Agent's console that will provide a dialog
box.

## MITRE ATT&CK Mapping

[T1055.012](https://attack.mitre.org/techniques/T1055/012/) Process Injection: Process Hollowing

## Detailed Summary

The `createprocess` command will create a new child process from the spawnto argument in a suspended state.
The provided shellcode will then be allocated into the child process.
After allocation, the child process' 
[AddressofEntryPoint](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
will be updated to point to the shellcode, and the child process will be resumed which results in execution.
Anonymous pipes are used to redirect and collect STDOUT/STDERR from the child process.
This technique is known as process hollowing.