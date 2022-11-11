+++
title = "parrot"
chapter = false
weight = 100
hidden = false
+++

## Summary

Parrot, or mimic, the TLS ClientHello of a specific web browser.

**WARNING**: Make sure the Mythic server, or an intermediary redirector, can support the client configuration

- Needs Admin: False
- Version: 1
- Author: @Ne0nd0g

### Arguments

#### client

- Description: The string of TLS client to mimic or parrot from the https://github.com/refraction-networking/utls 
library. Examples include HelloChrome_Auto or HelloFirefox_55
- Required Value: True
- Default Value: ""

## Usage

```
parrot HelloChrome_Auto
```

## MITRE ATT&CK Mapping

None

## Detailed Summary

View the Merlin documentation website [here](https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#sleep)
for an in-depth explanation.
