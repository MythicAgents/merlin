+++
title = "runas"
chapter = false
weight = 100
hidden = false
+++

## Summary

Run a program as user for the provided credentials.

- Needs Admin: False
- Version: 1
- Author: @Ne0nd0g

## Arguments

### user

- Description: Domain and username to make a token for (e.g. ACME\\RASTLEY)
- Required Value: True
- Default Value: None

### pass

- Description: The account's password
- Required Value: True
- Default Value: None

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
runas -user <DOMAIN\Username> -pass <password> -executable <executable> [-args <arguments>]
```
OR
```text
runas <DOMAIN\Username> <password> <executable> [<arguments>]
```

## MITRE ATT&CK Mapping

- [T1106](https://attack.mitre.org/techniques/T1106/) Native API

## Detailed Summary

View the Merlin documentation website [here](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#runas)
for an in-depth explanation.

The `runas` command will run a program as another user. This is done using the [CreateProcessWithLogonW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) Windows API call.
The `LOGON_WITH_PROFILE` logon flag is used that: "Log on, then load the user profile in the HKEY_USERS registry key." 
