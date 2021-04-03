+++
title = "execute-assembly"
chapter = false
weight = 100
hidden = false
+++

## Summary

Convert a .NET assembly into shellcode with Donut, execute it in the `spawnto` process, and return the output

- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

See the [Detailed Summary](#detailed-summary) section for additional information

### Arguments

#### assembly

- Description: The .NET assembly you want to execute
- Required Value: True
- Default Value: None

#### arguments

- Description: Arguments to execute the .NET assembly with
- Required Value: False
- Default Value: None

#### spawnto

- Description: The child process that will be started to execute the assembly in
- Required Value: True
- Default Value: `C:\Windows\System32\WerFault.exe`

#### spawntoargs

- Description: Argument to create the `spawnto` process with, if any
- Required Value: False
- Default Value: None

## Usage

```
execute-assembly <.NET Assembly File> <.NET Assembly Args> <SpawnTo> <SpawnTo Args>
```

## MITRE ATT&CK Mapping

[T1055.012](https://attack.mitre.org/techniques/T1055/012/) Process Injection: Process Hollowing

## Detailed Summary

The `donut` command leverages [Donut](https://github.com/TheWover/donut) by @TheWover transforms an arbitrary .NET 
assembly into position-independent shellcode.
The [go-donut](https://github.com/Binject/go-donut) library specifically is used with Merlin to generate the shellcode.
Once the shellcode is generated, it is executed in the `spawnto` process using the process hollowing technique described
in the [createprocess](./../createprocess) command documentation. The main difference between this command and the
[donut](./../donut) command is that many of the arguments are reduced to only those needed to execute a .NET assembly.
Use the [donut](./../donut) command if you want increased flexibility.