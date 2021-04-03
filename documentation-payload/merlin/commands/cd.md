+++
title = "cd"
chapter = false
weight = 100
hidden = false
+++

![Merlin Banner Logo](/agents/merlin/merlin-horizontal.png?width=1000px)

## Summary

The `cd` command is used to change the current working directory the Merlin agent is using.
Relative paths can be used (e.g.,`.` `./../` or `downloads\\Merlin`).
This command uses native Go and will not execute the cd binary program found on the host operating system.
 
- Needs Admin: False  
- Version: 1  
- Author: @Ne0nd0g

### Arguments

#### path

- Description: The directory path to change to
- Required Value: True  
- Default Value: None  

## Usage

```
cd /path/to/directory
```

## MITRE ATT&CK Mapping

## Detailed Summary