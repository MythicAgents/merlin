+++
title = "shell"
chapter = false
weight = 100
hidden = false
+++

## Summary

Execute the commandline string or arguments in the operating system's default shell

- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

See the [Detailed Summary](#detailed-summary) section for additional information

### Arguments

#### arguments

- Description: Commandline string or arguments to run in the shell
- Required Value: True
- Default Value: None

## Usage

```
shell <arguments>
```

## MITRE ATT&CK Mapping

* [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter 
* [T1059.003](https://attack.mitre.org/techniques/T1059/003/) Command and Scripting Interpreter: Windows Command Shell
* [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Command and Scripting Interpreter: Unix Shell 

## Detailed Summary

View the Merlin documentation website [here](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#shell)
for an in-depth explanation.

The `shell` command uses the host operating systems' default shell. On Windows that is typically `cmd.exe`, on Linux it 
is `/bin/bash`, and on MacOS it is `/bin/zsh`. For Linux and MacOS a symbolic link from `/bin/sh` is used. 
