+++
title = "ssh"
chapter = false
weight = 100
hidden = false
+++

## Summary

Connect to target host over the SSH protocol, executes the provided command, and returns the results.

{{% notice warning %}}
This command is insecure by design because it does not validate the remote host's public key
{{% /notice %}}

- Needs Admin: False
- Version: 1
- Author: @Ne0nd0g

View the Merlin documentation website [here](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#ssh)
for up-to-date information.

## Arguments

### user

- Description: Username to SSH with
- Required Value: True
- Default Value: None

### pass

- Description: The account's password
- Required Value: True
- Default Value: None

### host

- Description: The target host:port
- Required Value: True
- Default Value: `127.0.0.1:22`

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
ssh -user <username> -pass <password> -host <host:port> -executable <executable> [-args <arguments>]
```
OR
```text
ssh <user> <password> <host:port> <executable> [<arguments>]
```

## MITRE ATT&CK Mapping

- [T1021.004](https://attack.mitre.org/techniques/T1021/004/) Remote Services: SSH

## Detailed Summary
