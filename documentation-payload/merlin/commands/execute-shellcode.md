+++
title = "execute-shellcode"
chapter = false
weight = 100
hidden = false
+++

## Summary

Execute the provided shellcode using the selected method. No output is captured or returned

- Needs Admin: False
- Version: 1
- Author: @Ne0nd0g

See the [Detailed Summary](#detailed-summary) section for additional information

### Arguments

#### shellcode

- Description: The binary file that contains the shellcode
- Required Value: True
- Default Value: None

#### method

- Description: The shellcode injection method to use 
- Choices: self, remote, RtlCreateUserThread, userapc
- Required Value: True
- Default Value: None

#### pid

- Description: The Process ID (PID) to inject the shellcode into. Not used with the `self` method
- Required Value: False
- Default Value: None

## Usage

```
execute-shellcode <shellcode path> <method> [<pid>]
```

## MITRE ATT&CK Mapping

- [T1055](https://attack.mitre.org/techniques/T1055/) Process Injection
- [T1055.001](https://attack.mitre.org/techniques/T1055/002/) Process Injection: Portable Executable Injection
- [T1055.004](https://attack.mitre.org/techniques/T1055/004/) Process Injection: Asynchronous Procedure Call

## Detailed Summary

The `execute-shellcode method` allocates memory, copies the shellcode into it, and then executes it.
Allocation is done using the Windows API 
[VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) and 
[VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) functions.

The `self` method executes the allocated shellcode by making a direct SYSCALL to address of the shellcode.

The `remote` method executes the allocated shellcode in a remote process with the
[CreateRemoteThreadEx](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex)
function call.

The `RtlCreateUserThread` method uses the undocumented function of the same name,
[RtlCreateUserThread](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FRtlCreateUserThread.html),
to execute shellcode in a remote process.

The `userapc` method executes the allocated shellcode in a remote process with the 
[QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
function call. This method should be used as a last resort as the implementation is unstable. It will add a UserAPC 
message to every thread except the first.
