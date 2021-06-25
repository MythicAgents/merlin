+++
title = "sharpgen"
chapter = false
weight = 100
hidden = false
+++

## Summary

Use the SharpGen project to compile and execute a .NET core assembly from input CSharp code.
SharpGen blog post: <https://cobbr.io/SharpGen.html>
SharpSploit Quick Command Reference: <https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/SharpSploit%20-%20Quick%20Command%20Reference.md>

- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

See the [Detailed Summary](#detailed-summary) section for additional information

### Arguments

#### code

- Description: The CSharp code you want to execute
- Required Value: True
- Default Value: `Console.WriteLine(Mimikatz.LogonPasswords());`

#### spawnto

- Description: The child process that will be started to execute the assembly in
- Required Value: True
- Default Value: C:\Windows\System32\WerFault.exe

#### spawntoargs

- Description: Argument to create the `spawnto` process with, if any
- Required Value: False
- Default Value: None

#### verbose

- Description: Show verbose output from SharpGen and Donut
- Required Value: False
- Default Value: None

## Usage

```
sharpgen <code> <spawnto> <spawnto args>
```

## MITRE ATT&CK Mapping

[T1055.012](https://attack.mitre.org/techniques/T1055/012/) Process Injection: Process Hollowing

## Detailed Summary

The `sharpgen` command allows Operators to execute arbitrary C# code on the fly. The SharpGen tool will use .NET Core 
and compile the C# code in the Merlin container. The output .NET assembly will then be convert to shellcode with Donut.
The SharpGen project also has built in support for [SharpSploit](https://github.com/cobbr/SharpSploit)

The `donut` command leverages [Donut](https://github.com/TheWover/donut) by @TheWover transforms an arbitrary .NET 
assembly into position-independent shellcode.
The [go-donut](https://github.com/Binject/go-donut) library specifically is used with Merlin to generate the shellcode.
Once the shellcode is generated, it is executed in the `spawnto` process using the process hollowing technique described
in the [createprocess](./../createprocess) command documentation.