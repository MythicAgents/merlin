+++
title = "run"
chapter = false
weight = 100
hidden = false
+++

## Summary

Run the executable with the provided arguments and return the results

- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

See the [Detailed Summary](#detailed-summary) section for additional information

### Arguments

#### executable

- Description: The executable program to start
- Required Value: True
- Default Value: whoami

#### arguments

- Description: Arguments to start the executable with
- Required Value: False
- Default Value: None

## Usage

```
run <executable> <args>
```

## MITRE ATT&CK Mapping

[T1106](https://attack.mitre.org/techniques/T1106/) Native API

## Detailed Summary

View the Merlin documentation website [here](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#run) for
an in-depth explanation.

The `run` command executes the provided process directly and DOES NOT use a shell like `cmd.exe` or `/bin/bash`.
Because a shell is not used, Operators can't leverage shell functions such as pipes (e.g., `|`, `>`, `<`)
The command can be used on any operating system. If a full file path is not provided, the executable must be in the
host's PATH environment variable. 