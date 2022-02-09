+++
title = "rev2self"
chapter = false
weight = 100
hidden = false
+++

## Summary

Drop or release any impersonated Windows access tokens and revert to the original state

- Needs Admin: False
- Version: 1
- Author: @Ne0nd0g

### Arguments

None

## Usage

```
rev2self
```

## MITRE ATT&CK Mapping

None

## Detailed Summary

View the Merlin documentation website [here](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#token-rev2self)
for an in-depth explanation.

The `rev2self` command leverages the [RevertToSelf](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself)
Windows API function and releases, or drops, any access token that have been created or stolen.

