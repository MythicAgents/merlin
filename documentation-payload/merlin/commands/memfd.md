+++
title = "memfd"
chapter = false
weight = 100
hidden = false
+++

## Summary

The memfd command loads a Linux executable file into memory (RAM) as an anonymous file using the [memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html) API call, 
executes it, and returns the results. The file is created with an empty string as its name. Less the fact that RAM is a 
file on Linux, the executable is not written to disk. 
View the [Detecting Linux memfd_create() Fileless Malware with Command Line Forensics](https://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/) 
for detection guidance.

Change the Parameter Group to "Default" to use a file that was previously registered with Mythic and "New File" to 
register and use a new file from your host OS.

- Needs Admin: False
- Version: 1
- Author: @Ne0nd0g

### Arguments

#### file

The Linux executable file you want to run in memory

### args

Arguments to start the executable with

## Usage

```
memfd file [args]
```

## MITRE ATT&CK Mapping

[T1055](https://attack.mitre.org/techniques/T1055/) Process Injection

## Detailed Summary

None
