# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 1.4.0 - 2022-07-22

## Added

- SOCKS5 functionality

## Changed

- Updated merlin-agent v1.4.2

## 1.3.2 - 2022-05-04

### Changed

- Updated merlin-agent v1.4.2

## 1.3.1 - 2022-04-12

### Changed

- [Issue 4](https://github.com/MythicAgents/merlin/issues/4) Updated `builder.py` to use `mythic` Golang build tag
- Updated merlin-agent v1.4.1

### Fixed

- [Issue 3](https://github.com/MythicAgents/merlin/issues/3) skew correctly calculated

## 1.3.0 - 2022-04-07

### Added

- Added new [memory](https://github.com/MythicAgents/merlin/blob/main/documentation-payload/merlin/commands/memory.md) command

### Changed

- Updated to merlin-agent v1.4.0

## 1.2.0 - 2022-03-25

### Added

- Added version number confusion, don't even know what number I should be on :0)
- Generate Merlin as a DLL or Shellcode
- Support for the [Service Wrapper](https://github.com/MythicAgents/service_wrapper) and [ScareCrow Wrapper](https://github.com/MythicAgents/scarecrow_wrapper) payloads

### Changed

- Garble now uses ldflags to build instead of modifying the file directly

## 1.1.0 - 2021-10-12

### Added

- Added support for Garble to obfuscate payloads
- Added the following commands
  - `env` - to interact with environment variables
  - `ifconfig` - to view network interface configuration
  - `killprocess` - to kill a running process
  - `netstat` - view network connections (Windows)
  - `pipes` - retrieve a list of named pipes (Windows)
  - `ps` - retrieve a list of running processes (Windows)
  - `sdelete` - securely delete a file
  - `timestomp` - copy one file's timestamp to another
  - `uptime` - retrieve the amount of time the host has been up (Windows)

### Changed 

- Upgrade the merlin-agent codebase dependency to v1.1.0

## 1.0.1 - 2021-07-27

- Fixed [issue 1](https://github.com/MythicAgents/merlin/issues/1) with `memfd` command parsing

## 1.0.0 - 2021-06-25

### Added

- This Changelog
- Updated for Mythic 2.2 [release](https://posts.specterops.io/learning-from-our-myths-45a19ad4d077)
- Centralized Merlin specific Python functions to `merlin.py`
- `memfd` command to load an ELF into memory with the 
  [memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html) API call and execute it
