# AGENTS.md — merlin-mythic (Mythic payload type)

Guidance for AI coding agents working in this repo. Human contributors may find it useful too.

## What this is

The **Merlin payload type for [Mythic](https://github.com/its-a-feature/Mythic)**. It lets operators
build and task Merlin agents from a Mythic server. Currently targets **Mythic 3.3**
(`agent_capabilities.json`: `mythic_version 3.3`, `agent_version 2.4.1`). Mythic v4 support is a
planned, not-yet-started forward task.

This repo is **not** a Go module at its root — it holds **two** Go modules under
[`Payload_Type/merlin/`](Payload_Type/merlin/):

- [`container/`](Payload_Type/merlin/container/) — module
  `github.com/MythicAgents/merlin/Payload_Type/merlin/container`. The Mythic **payload-type
  container**: a normal Go service that talks to Mythic over RabbitMQ (`MythicContainer` +
  `amqp091-go`), defines the command set in [`commands/`](Payload_Type/merlin/container/commands/),
  and compiles agents in [`payload/build/`](Payload_Type/merlin/container/payload/build/).
- [`agent/`](Payload_Type/merlin/agent/) — module `github.com/MythicAgents/merlin/Payload_Type/agent`.
  A thin **cgo wrapper** (`main.go` + `merlin.c`) that builds the Merlin agent as a native binary or
  a Windows c-shared DLL. It imports the real agent from `github.com/Ne0nd0g/merlin-agent/v2`.

Target Go: **1.27** (both modules).

## Build / run / test

Each module is built on its own — there is no root module, so `go ...` must be run inside a module dir.

```bash
# Container (full tooling applies)
cd Payload_Type/merlin/container
go build ./... && go vet ./... && go test ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
golangci-lint run --max-same-issues=0 --max-issues-per-linter=0 ./...   # see the lint note below

# Agent (bespoke targets — ./... does NOT work; see gotchas)
cd Payload_Type/merlin/agent
go build -o merlin.bin -tags=mythic main.go                             # Linux binary
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
  go build -o merlin.dll -buildmode=c-shared -tags=mythic,shared .      # Windows DLL (needs mingw-w64)
```

The payload-type container runs as a Docker image (`ne0nd0g/merlin-mythic`, see `config.json`) and is
started by Mythic, not run standalone during normal use.

## Non-obvious facts (learned the hard way)

- **The agent module cannot be analyzed with `./...` tooling.** `merlin.c` is a C source that only
  compiles under cgo, so a plain `go build ./...` / `go vet ./...` / `golangci-lint ./...` /
  `govulncheck ./...` fails with *"C source files not allowed when not using cgo."* The agent is also
  gated behind the `mythic` build tag (and `shared` for the DLL). Build it only with the exact
  commands above; `gosec -tags mythic ./...` is the one scanner that works on it.
- **Pin `GOARCH=amd64` for the Windows DLL.** `merlin-agent`'s `os/windows/pkg/evasion` ships only
  amd64/386 files. On an amd64 host `GOOS=windows` implies amd64, but on other hosts (e.g. arm64 under
  `act`) Go defaults `GOARCH` to the host arch → *"build constraints exclude all Go files … evasion."*
- **golangci-lint hides findings by default** — always pass `--max-same-issues=0
  --max-issues-per-linter=0 ./...` to see the true count.
- `commands/template.go` is an intentional **copy-me scaffold** for authoring new commands; its
  `template()`/`templateCreateTask()` are deliberately unregistered and excluded from the `unused`
  linter in [`.golangci.yml`](.golangci.yml).
- Mythic build/task parameters are read with `msg.GetStringArg`/`GetBooleanArg` (promoted from the
  embedded `BuildParameters`) and `task.Args.GetStringArg`, each returning `(value, error)` — check
  the **error**, not a stale `ok` from a nearby map lookup.

## CI

- [`.github/workflows/go.yml`](.github/workflows/go.yml): a `container` job (build/vet/test +
  govulncheck + gosec), a `lint` job (golangci-lint on the container), and a bespoke `agent` job
  (Linux bin + Windows DLL + gosec). golangci-lint/govulncheck are **not** run on the agent module
  (see gotchas).
- [`.github/workflows/codeql.yml`](.github/workflows/codeql.yml): CodeQL with **`build-mode: none`** —
  two subdir modules, one needing mingw/cgo, defeat autobuild; `none` extracts all sources without a
  build.
- Qodana was dropped repo-wide. If CodeQL shows `disabled_inactivity`, re-enable it:
  `gh workflow enable CodeQL -R <owner/repo>`.
- gosec is pinned (`@v2.29.0 -exclude G115`) and run via `go run` so it uses the job's Go 1.27
  toolchain. There is no `release.yml` — this payload type ships as a pushed Docker image.

## Cross-repo dependencies

```
merlin-message (base, v1.3.0) ──> merlin-mythic/container (imports it)
merlin-agent (v2) ──> merlin-mythic/agent (cgo wrapper; require is RELEASE-GATED)
merlin-docker (base build image) ── feeds the agent/DLL builds
```

- The `agent` module's `github.com/Ne0nd0g/merlin-agent/v2` require is **release-gated** (currently
  `v2.4.2`): bump it to the new agent tag at coordinated-release time, not during routine work.
- At release, also bump `agent_version` in `agent_capabilities.json` and rebuild/push the
  `ne0nd0g/merlin-mythic` image (and the `remote_images` tag in `config.json`).

## Conventions

- **Branches:** work on `dev` (or a feature branch). **Never commit to `main`.** (There are stale
  `issue_25` and `mythic_3.3` remote branches — `mythic_3.3` is slated for deletion.)
- **Commits:** the maintainer signs every commit with a YubiKey. **Do not run `git commit`** — stage
  changes and propose a commit message for the maintainer to run. Do **not** add a `Co-Authored-By`
  trailer. PR descriptions may keep the "Generated with Claude Code" line.
- Match surrounding style; keep the GPLv3 license header on new Go source files (test files in this
  repo omit it, matching the existing `*_test.go`).
