+++
title = "token"
chapter = false
weight = 100
hidden = false
+++

## Summary

- Needs Admin: False
- Version: 1
- Author: @Ne0nd0g

Interact with Windows Access Tokens 
- Use the [Make Token](#make-token) parameter group to create a new access token
- Use the [Steal Token](#steal-token) parameter group to steal an access token
- Use the [Token Privs](#token-privs) parameter group to view a token's privileges
- The [Default](#default) parameter group can be used to interact with ANY method


* [Alias Commands](#alias-commands)
* [Methods](#methods)
* [Parameter Groups](#parameter-groups)

See the [Detailed Summary](#detailed-summary) section for additional information

## Alias Commands

There are several alias commands that facilitate interacting directly with a specific method

* [make_token](https://127.0.0.1:7443/docs/agents/merlin/commands/make_token/)
* [rev2self](https://127.0.0.1:7443/docs/agents/merlin/commands/rev2self/)
* [steal_token](https://127.0.0.1:7443/docs/agents/merlin/commands/steal_token/)

## Methods

* [make](#make)
* [privs](#privs)
* [rev2self](#rev2self)
* [whoami](#whoami)

### make

Make a Windows Access Token, see the [Make Token](#make-token) parameter group for additional details

### privs

Enumerate Windows Access Token privleges, see the [Token Privs](#token-privs) parameter group for additional details

Usage:

`token -method privs -args [<PID>]`

### rev2self

The `rev2self` method leverages the [RevertToSelf](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself)
Windows API function and releases, or drops, any access token that have been created or stolen.

See the [rev2self](https://127.0.0.1:7443/docs/agents/merlin/commands/rev2self/) command alias

Usage:

`token -method rev2self` or `token rev2self`

### steal

Steal a Windows Access Token from a target process, see the [Steal Token](#steal-token) parameter group for additional details

Usage:

`token -method steal -args <PID>`

### whoami

The `whoami` command leverages the Windows [GetTokenInformaion](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation) API call to return information
about both the process and thread Windows access token. This information includes:
* Username
* Token ID
* Logon ID
* Privilege Count
* Group Count
* Token Type
* Token Impersonation Level
* Integrity Level

Usage:

`token -method whoami` or `token whoami`

Example output:

```text
Process (Primary) Token:
        User: ACME\rastley,Token ID: 0x9CA475E,Logon ID: 0x26C3A6,Privilege Count: 24,Group Count: 14,Type: Primary,Impersonation Level: Anonymous,Integrity Level: High
Thread (Primary) Token:
        User: NT AUTHORITY\SYSTEM,Token ID: 0x9CC08EB,Logon ID: 0x3E7,Privilege Count: 28,Group Count: 4,Type: Primary,Impersonation Level: Impersonation,Integrity Level: System
```

## Parameter Groups

* [Default](#default)
* [Make Token](#make-token)
* [Steal Token](#steal-token)
* [Token Privs](#token-privs)

### Default

The default parameter group facilitates executing any available Windows Access token method

#### Arguments

##### method

- Description: The "method" to interact with Windows access tokens
- Required Value: True
- Choices: make, privs, rev2self, steal, whoami
- Default Value: whoami

#### arguments

- Description: Arguments that are specific to the selected token method
- Required Value: False
- Default Value: None

#### Usage

```
token -method <method> [-args <arguments>]
```

### Make Token

The _Make Token_ parameter group is used to explicitly create a Windows Access Token and apply it to the agent

Additionally, there is the [make_token](https://127.0.0.1:7443/docs/agents/merlin/commands/make_token/) command that can be called directly

#### Arguments

#### user

- Description: Domain and username to make a token for (e.g. ACME\\RASTLEY)
- Required Value: True
- Default Value: None

#### pass

- Description: The account's password
- Required Value: True
- Default Value: None

#### Usage

```text
token -user <DOMAIN\Username> -pass <password>
```

### Steal Token

The _Steal Token_ parameter group is used to copy a Windows Access Token from a target process and apply it to the agent

Additionally, there is the [steal_token](https://127.0.0.1:7443/docs/agents/merlin/commands/steal_token/) command that can be called directly

#### Arguments

#### pid

- Description: The process ID to interact with
- Required Value: True
- Default Value: None

#### Usage

```text
token -pid <Process ID>
```

### Token Privs

The _Token Privs_ parameter group is used to enumerate the privileges for the Windows access token associated with 
the target process. If a PID is not provided, the privileges for the current process will be returned

Example results:

```text
[+] Process ID 6892 access token integrity level: High, privileges (24):
        Privilege: SeIncreaseQuotaPrivilege, Attribute:
        Privilege: SeSecurityPrivilege, Attribute:
        Privilege: SeTakeOwnershipPrivilege, Attribute:
        Privilege: SeLoadDriverPrivilege, Attribute:
        Privilege: SeSystemProfilePrivilege, Attribute:
        Privilege: SeSystemtimePrivilege, Attribute:
        Privilege: SeProfileSingleProcessPrivilege, Attribute:
        Privilege: SeIncreaseBasePriorityPrivilege, Attribute:
        Privilege: SeCreatePagefilePrivilege, Attribute:
        Privilege: SeBackupPrivilege, Attribute:
        Privilege: SeRestorePrivilege, Attribute:
        Privilege: SeShutdownPrivilege, Attribute:
        Privilege: SeDebugPrivilege, Attribute: SE_PRIVILEGE_ENABLED
        Privilege: SeSystemEnvironmentPrivilege, Attribute:
        Privilege: SeChangeNotifyPrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED
        Privilege: SeRemoteShutdownPrivilege, Attribute:
        Privilege: SeUndockPrivilege, Attribute:
        Privilege: SeManageVolumePrivilege, Attribute:
        Privilege: SeImpersonatePrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED
        Privilege: SeCreateGlobalPrivilege, Attribute: SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED
        Privilege: SeIncreaseWorkingSetPrivilege, Attribute:
        Privilege: SeTimeZonePrivilege, Attribute:
        Privilege: SeCreateSymbolicLinkPrivilege, Attribute:
        Privilege: SeDelegateSessionUserImpersonatePrivilege, Attribute:
```

#### Arguments

#### token-pid

- Description: The process ID to interact with
- Required Value: False
- Default Value: None

#### Usage

```text
token [-target-pid <Process ID>]
```

## MITRE ATT&CK Mapping

- [T1134](https://attack.mitre.org/techniques/T1134/) Access Token Manipulation
- [T1134.001](https://attack.mitre.org/techniques/T1134/001/) Access Token Manipulation: Token Impersonation/Theft
- [T1134.003](https://attack.mitre.org/techniques/T1134/003/) Access Token Manipulation: Make and Impersonate Token

## Detailed Summary

Visit Merlin's documentation at https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#token for the most
up-to-date information.
