# Runbook — Windows

**Status: unverified draft.** Nothing in this document has been run on an actual
Windows machine yet — it's written from direct verification of what cross-compiles
cleanly (`GOOS=windows go build`/`go vet`, confirmed in a Linux sandbox) plus careful
reading of the relevant source, not from a real Windows test pass. Treat every command
below as a hypothesis to confirm, and report back anything that doesn't match so this
document converges on reality. Versions referenced below are pinned in
[`scripts/versions.env`](../scripts/versions.env).

**The genuinely good news first:** Windows does **not** need RocksDB, CGO, or a C
compiler for the normal build/test path. `internal/storage/engine_badger.go` carries
`//go:build windows` — Windows uses a pure-Go BadgerDB-backed storage engine instead of
the RocksDB one Linux and macOS use (ADR-046). This was confirmed directly:
`GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/provider/` (and
`./cmd/microservice/`, `./cmd/operator/`, `./cmd/client/`) all succeed cleanly. Skip
any instinct to replicate the macOS/Linux runbooks' RocksDB section here — it does not
apply.

**The other thing already fixed, as of this patch:** `scripts/test` (the entire
integration suite) previously failed to compile on Windows at all —
`syscall.SysProcAttr{Setpgid: true}` and `syscall.Kill` are POSIX-only and don't exist
in Windows' `syscall` package. This is now split by build tag
(`scripts/test/daemon_process_unix.go` / `daemon_process_windows.go`), and
`GOOS=windows go vet -tags integration ./scripts/test/...` is confirmed clean in the
same cross-compile check. The Windows-side implementation uses `taskkill /T /F` (tree
kill) and PowerShell's `Get-Process` in place of Unix process groups and `ps` — this
part **is** new, untested-on-real-Windows code; watch it closely during your first run.

## 1. Prerequisites

- Go, matching `GO_VERSION` exactly — download from
  [go.dev/dl](https://go.dev/dl/) (the `.msi` installer) or `winget install GoLang.Go`,
  then confirm:
  ```powershell
  go version
  ```
- [PowerShell 7+](https://github.com/PowerShell/PowerShell) (`winget install
  Microsoft.PowerShell`) — `scripts/demo/*.ps1` are written against PowerShell 7
  semantics (`#Requires -Version 7.0` at the top of each) and have **not** been tested
  against Windows PowerShell 5.1's older `System.Diagnostics.ProcessStartInfo` API
  surface.
- Docker Desktop for Windows, with the WSL2 backend — for the Postgres container only,
  same as macOS and Linux.
- `psql` client — either the official
  [PostgreSQL Windows installer](https://www.postgresql.org/download/windows/) (adds
  `psql` to PATH) or `winget install PostgreSQL.PostgreSQL`.
- `golangci-lint`, matching `GOLANGCI_LINT_VERSION`:
  ```powershell
  winget install golangci-lint.golangci-lint
  golangci-lint version   # confirm it matches the pin
  ```
- **Only if you plan to run `go test -race`:** a MinGW-w64 GCC toolchain (e.g. via
  [MSYS2](https://www.msys2.org/), `pacman -S mingw-w64-x86_64-toolchain`, with that
  toolchain's `bin` directory on `PATH`). Nothing else on this platform needs a C
  compiler — this is the *only* reason to install one.

## 2. Per-session setup

PowerShell has no direct equivalent to bash's `VAR=val command` inline-prefix syntax —
environment variables are set on their own line and persist for the rest of the
session (or until you close the terminal).

**Step 0 — clear orphaned processes:**
```powershell
Stop-Process -Name microservice,provider -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
```

**Step 1 — fresh Postgres:**
```powershell
docker compose -f deployments/dev/docker-compose.yml down -v
docker compose -f deployments/dev/docker-compose.yml up -d postgres
```

**Step 2 — schema + roles + environment:**
```powershell
$env:PGPASSWORD = "devpass"
psql -h localhost -U vyomanaut_migrator -d vyomanaut_dev `
  -c "CREATE DATABASE vyomanaut_test OWNER vyomanaut_migrator;"

go run migrations/generator.go --profile=demo | Out-File -Encoding utf8 "$env:TEMP\demo_schema.sql"

psql -h localhost -U vyomanaut_migrator -d vyomanaut_test `
  -v ON_ERROR_STOP=1 -f "$env:TEMP\demo_schema.sql"

psql -h localhost -U vyomanaut_migrator -d vyomanaut_test -c `
  "ALTER ROLE vyomanaut_app WITH LOGIN PASSWORD 'testpass'; ALTER ROLE vyomanaut_gc WITH LOGIN PASSWORD 'testpass';"

$env:PGHOST = "localhost"; $env:PGPORT = "5432"; $env:PGDATABASE = "vyomanaut_test"; $env:PGSSLMODE = "disable"
$env:PGUSER = "vyomanaut_app"; $env:PGPASSWORD = "testpass"
$env:PGMIGRATORUSER = "vyomanaut_migrator"; $env:PGMIGRATORPASSWORD = "devpass"
```

No `CGO_CFLAGS`/`CGO_LDFLAGS`/library-path block — see the note at the top of this
document. If you're specifically running `go test -race` (§1's MinGW-w64 prerequisite),
also set:
```powershell
$env:CGO_ENABLED = "1"
```
For every other command in this runbook, leave `CGO_ENABLED` unset — Go will not need
it, since nothing on the Windows build path requires cgo.

## 3. Whole-repo compile + unit tests

```powershell
go vet ./...
go build ./...
golangci-lint run
go test -race -count=1 -p 1 ./...
```

If `-race` fails to build with a linker error, that's almost certainly the MinGW-w64
toolchain (§1) — confirm `gcc --version` resolves in the same PowerShell session before
assuming it's a code problem.

## 4. Integration package compile check

```powershell
go build -tags integration ./scripts/test/...
go vet -tags integration ./scripts/test/...
```

This is the check that was failing outright before this patch (Setpgid, see this
document's opening note). A failure here now would be a **new** regression worth
reporting immediately, not a known, already-diagnosed issue.

## 5. The integration suite

Same test names and `-run`/`-timeout` values as the macOS runbook's §6 — copy that
section's `go test -tags integration ...` invocations verbatim; only §2 above (the
environment setup) differs by platform. `date` in the macOS/Linux versions becomes
`Get-Date` if you want the same timestamp markers between steps:
```powershell
Get-Date
go test -tags integration -v -run '^TestDemoTimeline$' ./scripts/test/ -timeout 60m
Get-Date
# ...and so on, same test names, same order, same timeouts as macos.md §6
```

## 6. `scripts/demo/*.ps1` — the Windows demo runner

Not part of Session 17.8.2's own test list, but relevant to this platform: `up.ps1`,
`down.ps1`, and `join.ps1` are new, entirely unexecuted PowerShell — no `pwsh` was
available in the sandbox they were written in, so nothing beyond careful manual
reading has verified them. If you run these, watch specifically for:

- Whether `Get-NetIPConfiguration` (used for LAN-IP autodetection in `up.ps1`)
  resolves sensibly on your network adapter setup, or needs `--advertise-addr` passed
  explicitly.
- Whether the FIFO-less stdin-pipe approach to feeding `provider onboard` its OTP code
  (a `System.Diagnostics.Process` with `RedirectStandardInput`, since Windows has no
  named-pipe-with-nonblocking-open equivalent to the bash version's `mkfifo`) actually
  unblocks the child process the way it does in testing against .NET's own documented
  behavior.
- `down.ps1`'s `CloseMainWindow()` best-effort graceful-stop attempt — flagged in its
  own comments as an unconfirmed analog to POSIX SIGTERM; `Stop-Process -Force` is the
  fallback this script actually depends on for a guaranteed teardown.

## 7. Windows-specific notes

- `cmd/provider/advertise.go`'s autodetection now skips interface names containing
  `vethernet` (Hyper-V/WSL2/Docker Desktop's virtual switches) — if your machine's real
  LAN adapter happens to also match one of the filtered patterns (unlikely, but
  Windows' adapter-naming is less predictable than Linux/macOS), pass
  `--advertise-addr` explicitly rather than relying on autodetection.
- File permission modes (`0600`, `0700` in Go source) have very limited effect on
  Windows — `os.Chmod`/`os.OpenFile`'s mode bits are not enforced the same way NTFS
  ACLs would be. This is a known, accepted platform gap, not something this runbook
  attempts to close.
