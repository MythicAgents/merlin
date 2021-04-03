+++
title = "mimikatz"
chapter = false
weight = 100
hidden = false
+++

## Summary

Converts mimikatz.exe into shellcode with Donut, executes it in the `spawnto` process, and returns output

- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

See the [Detailed Summary](#detailed-summary) section for additional information

### Arguments

#### commandline

- Description: Mimikatz commandline arguments
- Required Value: True
- Default Value: `token::whoami coffee`

#### spawnto

- Description: The child process that will be started to execute Mimikatz in
- Required Value: True
- Default Value: C:\Windows\System32\WerFault.exe

#### spawntoargs

- Description: Argument to create the `spawnto` process with, if any
- Required Value: False
- Default Value: None

#### verbose

- Description: Show verbose output from Donut
- Required Value: False
- Default Value: None

## Usage

```
mimikatz <args> <spawnto> <spawntoargs>
```

## MITRE ATT&CK Mapping

[S00002](https://attack.mitre.org/software/S0002/) Mimikatz

## Detailed Summary

The most recent version of Mimikatz is downloaded when the Merlin container is created.
Mimikatz is retrieved from <https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip>

The `donut` command leverages [Donut](https://github.com/TheWover/donut) by @TheWover transforms an arbitrary PE
into position-independent shellcode.
The [go-donut](https://github.com/Binject/go-donut) library specifically is used with Merlin to generate the shellcode.
Once the shellcode is generated, it is executed in the `spawnto` process using the process hollowing technique described
in the [createprocess](./../createprocess) command documentation. The main difference between this command and the
[donut](./../donut) command is that many of the arguments are reduced to only those needed to execute a PE.
Use the [donut](./../donut) command if you want increased flexibility.

