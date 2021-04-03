+++
title = "download"
chapter = false
weight = 100
hidden = false
+++

## Summary
 
The `download` command downloads a file from the host where the agent is running

- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

### Arguments

#### file

- Description: The file to download from the host where the agent is running
- Required Value: True
- Default Value: None

## Usage

```
download <file>
```

## MITRE ATT&CK Mapping

- [T1560.003](https://attack.mitre.org/techniques/T1560/003/) Archive Collected Data: Archive via Custom Method
- [T1041](https://attack.mitre.org/techniques/T1041/) Exfiltration Over C2 Channel 

## Detailed Summary