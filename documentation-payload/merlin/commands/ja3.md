+++
title = ""
chapter = false
weight = 100
hidden = false
+++

## Summary

Instruct the agent to use a client derived from the input JA3 string to communicate with the server.
**WARNING**: Make sure the server can support the client configuration

- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

See the [Detailed Summary](#detailed-summary) section for additional information

### Arguments

#### ja3string

- Description: The JA3 "string" that the client should use
- Required Value: True
- Default Value: None

## Usage

```
ja3 <ja3 string>
```

## MITRE ATT&CK Mapping

None

## Detailed Summary

>JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence.

The `ja3` command allows the operator to change the Agent's JA3 fingerprint while running.
Do not submit a JA3 string that configures the Agent's TLS client to use TLS settings that the server can not support.
If the server does not support the TLS configuration, the agent will not be able to check back in.

Resources:

- [Github JA3](https://github.com/salesforce/ja3)
- [Open Sourcing JA3](https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41)
- [TLS Fingerprinting with JA3 and JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)