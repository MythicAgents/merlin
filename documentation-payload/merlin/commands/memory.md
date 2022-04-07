+++
title = "memory"
chapter = false
weight = 100
hidden = false
+++

## Summary

- Needs Admin: False
- Version: 1
- Author: @Ne0nd0g

Interact with the agent's virtual memory and read/write a target function's bytes
- Use the [Path](#patch) parameter group to read and then overwrite the target function's memory
- Use the [Read](#read) parameter group to read target function's memory
- Use the [Write](#write) parameter group to overwrite target function's memory with provided bytes
- The [Default](#default) parameter group can be used to interact with ANY method

Uses direct syscalls for `NtReadVirtualMemory`, `NtProtectVirtualMemory`, & `ZwWriteVirtualMemory` implemented
using [BananaPhone](https://github.com/C-Sto/BananaPhone)

* [Methods](#methods)
* [Parameter Groups](#parameter-groups)

See the [Detailed Summary](#detailed-summary) section for additional information

## Methods

### Patch

The `patch` method locates the address of the provided procedure/function, reads the existing bytes, and the
overwrites them with the provided bytes. A second read is performed to validate the write event. The method would be
the same as calling the `read` and `write` methods individually.

Usage:

`memory patch <module> <proc> <bytes>`

### Read

The `read` method locates the address of the provided procedure/function and reads the specified number of bytes.

Usage:

`memory read <module> <proc> <number of bytes>`

### Write

The `write` method locates teh address of the provided procedure/function and writes the specified bytes.

Usage:

`memory write <module> <proc> <bytes>`

## Arguments

### Module

This argument specifies the module (e.g., `ntdll.dll`) that contains the target procedure/function

### Procedure

This argument specifies the target procedure/function to patch/read/write bytes from

### Bytes

This argument is used with the [Patch](#patch) and [Read](#read) methods. Provide the bytes, as a hex string, that
you want to replace the existing bytes with

### Length

This argument is used with the [Read](#read) method and is used to read the specified number of bytes from the target
procedure/function.

## MITRE ATT&CK Mapping

- [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Impair Defenses: Disable or Modify Tools

## Detailed Summary

Visit Merlin's documentation at https://merlin-c2.readthedocs.io/en/latest/server/menu/agents.html#memory for the most
up-to-date information.
