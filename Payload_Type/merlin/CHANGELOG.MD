# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 2.3.2 - 2024-08-30

### Added

- Enabled the remote Docker image capability through the `config.json` file

### Changed

- Upgraded github.com/MythicMeta/MythicContainer v1.3.13 => v1.4.3 to support Mythic v3.3
- Minimum supported version of Go is v1.21
- Upgraded Dockerfile image from ne0nd0g/merlin-base:v1.6.0 to v1.7.0 significantly reducing the image size
- Modified the mimikatz command to point to the updated location of Mimikatz executable in the image

### Removed

- Removed SharpGen from the Docker image and the agent_capabilities.json file

## 2.3.1 - 2024-04-23

### Changed

- Upgraded github.com/MythicMeta/MythicContainer v1.3.12 => v1.3.13
- Upgraded github.com/pelletier/go-toml/v2 v2.2.0 => v2.2.1
- Upgraded golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8 => v0.0.0-20240416160154-fe59bbe5cc7f
- Upgraded golang.org/x/net v0.22.0 => v0.24.0
- Upgraded golang.org/x/sys v0.18.0 => v0.19.0
- Upgraded google.golang.org/genproto/googleapis/rpc v0.0.0-20240325203815-454cdb8f5daa => v0.0.0-20240415180920-8c6c420018be
- Upgraded google.golang.org/grpc v1.62.1 => v1.63.2
- Upgraded github.com/Ne0nd0g/merlin-agent/v2 v2.4.0 => v2.4.1
- Upgraded github.com/google/pprof v0.0.0-20240320155624-b11c3daa6f07 => v0.0.0-20240422182052-72c8669ad3e7
- Upgraded github.com/klauspost/compress v1.17.7 => v1.17.8
- Upgraded github.com/onsi/ginkgo/v2 v2.17.0 => v2.17.1
- Upgraded github.com/refraction-networking/utls v1.6.3 => v1.6.4
- Upgraded golang.org/x/crypto v0.21.0 => v0.22.0
- Upgraded golang.org/x/mod v0.16.0 => v0.17.0
- upgraded golang.org/x/tools v0.19.0 => v0.20.0

### Fixed

- Fixed 3 `Incorrect conversion between integer types` issues in `donut.go`

### Security

- [GO-2024-2687](https://pkg.go.dev/vuln/GO-2024-2687) - Upgraded `golang.org/x/net` to v0.23.0 to address CVE-2024-2687

## 2.3.0 - 2024-03-28

### Added

- Added an HTTP client provider build parameter for Windows agents
  - Use `go` for the default Go HTTP client
  - Use `winhttp` to use the Windows winhttp API to facilitate automatic proxy authentication

### Changed

- Upgraded `github.com/Ne0nd0g/merlin-agent` to v2.4.0
- Upgraded `github.com/Ne0nd0g/merlin-docker` to v1.6.0
  - Upgraded `https://github.com/burrowers/garble` to v0.12.1 
- Upgraded github.com/MythicMeta/MythicContainer v1.2.1 => v1.3.12

### Fixed

- [Issue 15](https://github.com/MythicAgents/merlin/issues/15) - Parse and use multiple HTTP headers
- [PR 16](https://github.com/MythicAgents/merlin/pull/16) - @galoryber fixed argument parsing for the `invoke-assembly` command

## 2.2.0 - 2023-12-27

### Added

- Added `agent_capabilities.json` for [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- Added GitHub workflow Actions for automated testing and building
- Added `github.com/Ne0nd0g/merlin-agent/v2` features to `main.go` for agent builds
  - `auth` variable with a static `rsa` value to use the RSA authenticator
  - `secure` variable with a static `false` value to NOT require valid TLS certificates
  - `transforms` variable with a static `mythic,aes` value to use the AES encrypter and Mythic data encoder

### Changed

- Upgraded `github.com/Ne0nd0g/merlin-agent` to v2.3.0
- Upgraded `github.com/MythicMeta/MythicContainer` to v1.2.1
- Swapped `github.com/Ne0nd0g/merlin-agent/pkg/jobs` to `github.com/Ne0nd0g/merlin-message/jobs`
- Upgraded ne0nd0g/merlin-base Docker image to v1.5.0

## 2.1.1 - 2023-08-11

### Fixed

- [Issue 12](https://github.com/MythicAgents/merlin/issues/12) - Unset `LD_PRELOAD` at the start of shared-object payloads

## 2.1.0 - 2023-08-02

### Fixed

- [Issue 11](https://github.com/MythicAgents/merlin/issues/11) - Enabled linux shared object payload generation

### Changed

- Renamed `dll.go` from the `agent` directory to `shared_windows.go`
- Updated `merlin.c` to contain the source for both Windows and Linux shared object payloads (DLLs and .so files)
- Replaced two-step Windows DLL build using c-archive and x86_64-w64-mingw32-gcc with a single step using go's c-shared buildmode

## 2.0.1 - 2023-07-12

### Fixed

- Added in the missing sleep command

## 2.0.0 - 2023-06-11

### Changed

- Upgraded code base for Mythic v3.0.0
- Merlin agent code is now in the `agent` directory
- Code to run the Merlin container for Mythic is in the `container` directory

### Removed

- All Python code, replaced with Golang native code

## 1.5.2 - 2023-03-03

### Added 

- Updated agent build architectures to include 64-bit ARM and MIPS

## 1.5.1 - 2023-03-01

### Fixed

- [Issue 7](https://github.com/MythicAgents/merlin/issues/7) - Adjusted the `shell` function call

## 1.5.0 - 2022-11-11

### Added

- Parrot specific web browsers through [utls](https://github.com/refraction-networking/utls#parroting) library
  - The builder contains a drop-down list of acceptable options
  - Use the `parrot` command to change while the agent is running
  - If a JA3 string is provided, the parrot string will be ignored

### Changed

- Updated merlin-agent v1.4.2
- Upgraded `merlin-base` Docker image to v1.3.0
  - Upgrades to Go v1.19


## 1.4.1 - 2022-10-31

## Changed

- Upgraded `merlin-base` Docker image to v1.2.0
  - Upgrades Python to `3.8.15`
  - Upgrades Garble to `v0.7.2`
  - Checks out known working sRDI hash `5690685aee6751d0dbcf2c50b6fdd4427c1c9a0a`

## Fixed

- [Issue 5](https://github.com/MythicAgents/merlin/issues/5) - Invoke-Assembly Errors Without Assembly Arguments
- [Issue 6](https://github.com/MythicAgents/merlin/issues/6) - Generated Shellcode Does Not Work

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
