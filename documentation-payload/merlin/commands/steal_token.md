+++
title = "steal_token"
chapter = false
weight = 100
hidden = false
+++

## Summary

Steal a Windows access token from the target process and impersonate it

- Needs Admin: False
- Version: 1
- Author: @Ne0nd0g

## Arguments

### pid

- Description: The process ID to steal a Windows access token from
- Required Value: True
- Default Value: None

## Usage

```
steal_token -pid <Process ID>
```
OR
```text
make_token <Process ID>
```

## MITRE ATT&CK Mapping

- [T1134.001](https://attack.mitre.org/techniques/T1134/001/) Access Token Manipulation: Token Impersonation/Theft

## Detailed Summary

View the Merlin documentation website [here](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#steal)
for an in-depth explanation.

The `steal_token` command obtains a handle to a remote process' access token, duplicates it through the
[DuplicateTokenEx](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
Windows API, and subsequently uses it to perform future post-exploitation commands.
