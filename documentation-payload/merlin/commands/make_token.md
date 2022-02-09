+++
title = "make_token"
chapter = false
weight = 100
hidden = false
+++

## Summary

Create a new [Type 9](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types)
logon session and Windows access token for the provided credentials.

{{% notice warning %}}
Type 9 - NewCredentials tokens only work for **NETWORK** authenticated activities
{{% /notice %}}

{{% notice tip %}}
View the [RunAs](https://127.0.0.1:7443/docs/agents/merlin/commands/runas/) command to execute programs on the local 
host as a different user.
{{% /notice %}}

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

## Usage

```
make_token -user <DOMAIN\Username> -pass <password>
```
OR
```text
make_token <DOMAIN\Username> <password>
```

## MITRE ATT&CK Mapping

- [T1134.003](https://attack.mitre.org/techniques/T1134/003/) Access Token Manipulation: Make and Impersonate Token

## Detailed Summary

View the Merlin documentation website [here](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#make)
for an in-depth explanation.

The `make_token` command is used to create a new Windows access token with the Windows [LogonUserW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw) API call. 
The token is created with a type `9 - NewCredentials` [logon type](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types>). 
This is the equivalent of using `runas.exe /netonly`.

{{% notice warning %}}
Type 9 - NewCredentials tokens only work for **NETWORK** authenticated activities
{{% /notice %}}

{{% notice note %}}
Commands such as ``token whoami`` will show the username for the process and not the created token due to the logon type, but will reflect the new Logon ID
{{% /notice %}}

{{% notice tip %}}
View the [RunAs](https://127.0.0.1:7443/docs/agents/merlin/commands/runas/) command to execute programs on the local
host as a different user.
{{% /notice %}}
