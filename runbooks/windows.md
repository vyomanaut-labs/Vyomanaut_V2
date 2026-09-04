# Runbook — Windows

**Status: unverified draft**, same caveat as before this rewrite: nothing below has
been run end-to-end on a real Windows machine yet. It is written from direct
verification of what cross-compiles cleanly (`GOOS=windows go build`, confirmed in a
Linux sandbox), careful reading of the relevant source, and the actual macOS Stage 1
run this project has already completed live. Treat every command as a hypothesis to
confirm on the real machine, and correct this document against whatever you find —
that correction is the actual deliverable of the Stage 2 session this document exists
for.

**Who this is for:** someone sitting down at a Windows laptop that has never seen this
project before, whose job is to get to a working `operator watch` console and a
completed upload/retrieve/departure/repair demo cycle — the same cycle already proven
on macOS. Sections 1–4 are that path. Sections 5–7, kept from the previous version of
this document, are for a developer setting up the full CI-equivalent build/test loop
beyond just the demo; they are not required for Stage 2.

**The genuinely good news, unchanged:** Windows needs **no RocksDB, no CGO, and no C
compiler** for anything in this document except §5's optional `-race` flag.
`internal/storage/engine_badger.go` carries `//go:build windows` — Windows uses a
pure-Go BadgerDB-backed storage engine instead of the RocksDB one Linux and macOS use
(ADR-046). `up.ps1` now sets `$env:CGO_ENABLED = "0"` explicitly before every build,
specifically so a future dependency that *did* need cgo would fail with Go's own clear
"C compiler not found" message rather than a confusing linker error.

---

## 1. Prerequisites

Every requirement below follows the same two-step pattern: **check** what's already on
the machine, **then** the exact command to run only if that check comes back empty.
Run the checks in order — a later step sometimes explains a gap an earlier one left.

Versions are pinned in [`scripts/versions.env`](../scripts/versions.env), the single
source of truth every runbook (including this one) is supposed to read from rather
than repeat a number that can drift. §1.7 below is the actual parse this file's own
header comment promises and previous versions of this document never delivered.

### 1.1 — winget (Windows' own package manager)

Modern Windows (10 1709+, all of 11) ships this already.

**Check:**
```powershell
winget --version
```
Expect something like `v1.7.xxxx`. If you get "winget is not recognized," it's missing
or too old.

**If absent:** install "App Installer" from the Microsoft Store (search "App
Installer," or open
[this direct link](https://apps.microsoft.com/detail/9nblggh4nns1) in Edge), then
re-open PowerShell and re-run the check.

### 1.2 — git

**Check:**
```powershell
git --version
```
Expect `git version 2.x.x`.

**If absent:**
```powershell
winget install --id Git.Git -e --source winget
```
Close and reopen your terminal afterward — PATH changes from an installer don't reach
an already-open shell.

### 1.3 — PowerShell 7+

Windows ships PowerShell 5.1 by default. `scripts/demo/*.ps1` declare
`#Requires -Version 7.0` and use APIs 5.1 lacks (in particular,
`System.Diagnostics.ProcessStartInfo.ArgumentList`, used by `up.ps1`'s provider
onboarding).

**Check:**
```powershell
$PSVersionTable.PSVersion
```
Expect `Major` ≥ 7. If you see `5.1.x`, you're in Windows PowerShell, not PowerShell 7
— they coexist; this isn't an upgrade, it's a second install.

**If absent:**
```powershell
winget install --id Microsoft.PowerShell -e --source winget
```
Then **open a new window specifically titled "PowerShell 7" or "pwsh"** from the Start
menu (or run `pwsh` from any terminal) — installing it does not change what your
existing "Windows PowerShell" shortcut launches. Re-run the version check inside that
new window before continuing; every command in this document from here on assumes
you're inside it.

### 1.4 — Go

**Check:**
```powershell
go version
```
Compare the reported version against `GO_VERSION` in `scripts/versions.env` (§1.7
shows how to read that file directly rather than eyeballing it).

**If absent, or the version doesn't match:**
```powershell
winget install --id GoLang.Go -e --source winget
```
`winget` installs whatever the latest Go release is, which may not exactly match the
pin — if it doesn't, download the specific `.msi` for `GO_VERSION` from
[go.dev/dl](https://go.dev/dl/) instead and run that installer over the winget one.

### 1.5 — Docker Desktop (for the Postgres container only)

Nothing else in this project's demo or test path runs in a container — see the Design
Council verdict on Docker in the M17-E session history for why. Docker Desktop's WSL2
backend is what actually runs the container; you do not write or run any WSL2 commands
yourself.

**Check:**
```powershell
docker --version
docker compose version
```
Both should print a version. If Docker Desktop is installed but not running, these
commands will hang or error — start Docker Desktop from the Start menu and wait for
its whale icon in the system tray to stop animating before retrying.

**If absent:**
```powershell
winget install --id Docker.DockerDesktop -e --source winget
```
This requires a reboot and, on some machines, a one-time "enable WSL2" prompt Windows
handles itself — follow whatever it asks for, then re-run the check above.

### 1.6 — psql (PostgreSQL client)

**Check:**
```powershell
psql --version
```
Expect `psql (PostgreSQL) 1x.x`.

**If absent:**
```powershell
winget install --id PostgreSQL.PostgreSQL -e --source winget
```
This installs a full local PostgreSQL server alongside the client — you don't need or
use the server (Docker's container is what up.ps1 actually connects to), only the
`psql` binary it also puts on PATH. If `psql --version` still fails after install,
close and reopen your terminal (same PATH-refresh caveat as §1.2).

### 1.7 — Confirm your versions against `scripts/versions.env` directly

Once §1.2 (git) is done and the repository is cloned (§2), don't eyeball the pinned
versions against what §1.3–1.6 reported — parse the actual file:

```powershell
Get-Content scripts\versions.env |
  Where-Object { $_ -match '^\s*([A-Z_]+)=(.+)$' } |
  ForEach-Object {
    $name, $value = $Matches[1], $Matches[2]
    Write-Host "$name = $value"
  }
```

This prints `GO_VERSION`, `ROCKSDB_VERSION`, `GROCKSDB_VERSION`, and
`GOLANGCI_LINT_VERSION` from the file itself — the first two don't apply to you (§1's
own opening note), but `GO_VERSION` is the number `go version` should match, and
`GOLANGCI_LINT_VERSION` matters only if you do §5.

### 1.8 — Only if you plan to run `go test -race` (§5): a C compiler

Nothing else in this document needs one.

**Check:**
```powershell
gcc --version
```

**If absent:**
```powershell
winget install --id MSYS2.MSYS2 -e --source winget
```
then, inside the MSYS2 terminal it installs:
```
pacman -S mingw-w64-x86_64-toolchain
```
and add that toolchain's `bin` directory to your PATH (MSYS2's installer tells you the
exact path, typically `C:\msys64\mingw64\bin`) before opening a new PowerShell 7
window.

---

## 2. Get the code

**Check** whether you already have a clone:
```powershell
Test-Path .\Vyomanaut_V2\go.mod
```

**If false**, clone it and step inside:
```powershell
git clone https://github.com/masamasaowl/Vyomanaut_V2.git
cd Vyomanaut_V2
```

Every command from here on assumes your working directory is the repository root.

---

## 3. Running the demo

This is Stage 2's actual goal: the same register → upload → retrieve → depart → repair
cycle already proven on macOS, on a machine that has never seen this project until
§1–2 just now.

### 3.1 — Start Postgres

`up.ps1` resets and migrates the database itself, but expects a running Postgres
container already listening — it does not start Docker for you, matching `up.sh`'s own
division of responsibility on macOS/Linux.

```powershell
docker compose -f deployments\dev\docker-compose.yml down -v
docker compose -f deployments\dev\docker-compose.yml up -d postgres
```

### 3.2 — Bring the network up

```powershell
.\scripts\demo\up.ps1 --Providers 7
```
(or just `.\scripts\demo\up.ps1` — 7 is the default, and ADR-075's own finding is that
7 is the canonical rehearsal fleet size, not an arbitrary round number; see that
script's header comment.)

This builds all four binaries fresh, resets and migrates Postgres, starts the
microservice, then onboards and starts 7 local provider processes. Expect it to take a
few minutes — most of that time is the 7 sequential provider onboarding cycles, each
of which waits for its own OTP round-trip.

When it finishes, it prints the real values for this run (admin key, OTP log path,
bin directory) and the exact commands to use them. **Copy that block somewhere** — the
same values are also saved to `$env:TEMP\vyomanaut-demo\env.ps1` (or wherever
`$env:VYOMANAUT_DEMO_STATE_DIR` points, if you set it).

### 3.3 — Load the run's values into a new terminal

Every terminal after this one — for `operator watch`, for `client` commands, for
`kill_provider.ps1` — needs these values loaded first. Open a **new** PowerShell 7
window (not the one `up.ps1` is still occupying) and:

```powershell
. $env:TEMP\vyomanaut-demo\env.ps1
```

That leading `. ` (dot, space) is not a typo — it's PowerShell's dot-sourcing operator,
the actual equivalent of bash's `source`. Confirm it worked:
```powershell
$env:MICROSERVICE_URL
```
should print the URL `up.ps1` reported, not nothing.

### 3.4 — Watch the console

```powershell
& "$env:BIN_DIR\operator.exe" watch --mode=demo --microservice-url=$env:MICROSERVICE_URL --admin-api-key=$env:ADMIN_API_KEY
```

`--mode=demo` is not optional — without it the console evaluates every readiness
number against the production profile's thresholds instead of the demo profile's, and
every figure on screen will look wrong even though the real system underneath is fine.
Leave this running in its own window for the rest of the session.

### 3.5 — Register, deposit, and upload

In a third window (dot-source `env.ps1` here too — §3.3):

```powershell
& "$env:BIN_DIR\client.exe" register --mode=demo --microservice-url=$env:MICROSERVICE_URL --data-dir="$env:OWNER_DIR"
& "$env:BIN_DIR\client.exe" deposit --mode=demo --microservice-url=$env:MICROSERVICE_URL --data-dir="$env:OWNER_DIR" --amount-rupees=500
```

Wait for the console's Readiness gate panel to show **7/7 promoted to ACTIVE** before
uploading — `client upload` genuinely requires five ACTIVE (not just VETTING)
providers, by design (two independent gates; see §6's `TestDemoTimeline` and this
project's own M18 findings for the full reasoning). The console's own progress bar
labels the wait accurately.

```powershell
& "$env:BIN_DIR\client.exe" upload --mode=demo --microservice-url=$env:MICROSERVICE_URL --data-dir="$env:OWNER_DIR" README.md
```

**README.md, specifically — this is the entropy demo, run right here.** Uploading this
repository's own `README.md` (plaintext, ~3 KB, guaranteed present on any clone — no
extra file to find or download) instead of a compressed video gives a dramatically
clearer confidentiality demonstration than compressed media does: ordinary English
text measures roughly 4.9 bits/byte of entropy, while an already-compressed video
measures around 7.995 — visually indistinguishable from the ~7.999 a stored,
AONT-RS-transformed chunk measures either way. Confirm the contrast once it's uploaded
and vetted onto a provider:

```powershell
& "$env:BIN_DIR\client.exe" ls --mode=demo --microservice-url=$env:MICROSERVICE_URL --data-dir="$env:OWNER_DIR"
```
note the FILE_ID it prints, then — once you know which provider holds a shard (`&
"$env:BIN_DIR\operator.exe" shards <file_id>` shows placement) —
```powershell
& "$env:BIN_DIR\provider.exe" inspect --data-dir="$env:DATA_DIR\provider-<N>" --hex --compare="README.md"
```
The stored chunk's entropy (~7.999) against README.md's own (~4.9, printed by the same
`compare` line) is the whole point made visible: on-disk, this owner's file is
statistically indistinguishable from random noise, and the plaintext it came from
plainly is not.

### 3.6 — Depart a provider and watch repair

This is the second half of the demo that matters most: proving the network survives
losing a provider, using the script this session specifically wrote for Windows.

```powershell
& "$env:BIN_DIR\operator.exe" shards <file_id>
```
pick any `PROVIDER_ID` from its output, then:
```powershell
.\scripts\demo\kill_provider.ps1 <provider_id>
```
This resolves the ID to its rehearsal data directory and stops that one process — never
the microservice — and prints the exact `provider inspect` command to look at what it
was holding, copy-pasteable straight from the output. Watch the console's Repair panel
pick up the resulting departure and re-converge the affected ASN back to full shard
count.

### 3.7 — Retrieve, and tear down

```powershell
& "$env:BIN_DIR\client.exe" retrieve --mode=demo --microservice-url=$env:MICROSERVICE_URL --data-dir="$env:OWNER_DIR" <file_id> --output=retrieved_README.md
fc README.md retrieved_README.md
```
`fc` is Windows' byte-comparison tool — the direct equivalent of macOS/Linux `cmp`.
"FC: no differences encountered" is a pass.

When you're done:
```powershell
.\scripts\demo\down.ps1
```

---

## 4. Cross-machine join (the bridge to Stage 3)

Not required to close out Stage 2's own demo cycle above, but the actual reason Stage 2
exists at all: a second machine (this Windows laptop, or another one) joining a
coordinator running elsewhere.

On the machine running `up.ps1`, pass `--AdvertiseAddr` explicitly rather than relying
on autodetection if the two machines aren't on the same simple LAN segment (§7 covers
why autodetection can guess wrong). On the joining machine:
```powershell
.\scripts\demo\join.ps1 <coordinator's MICROSERVICE_URL>
```
`join.ps1` will prompt for how much storage to share and then for a 6-digit code — ask
whoever is running `up.ps1` for it; they read it via the same `operator otp` command
§3.2's own output block shows.

---

## 5. Whole-repo compile + unit tests

Only needed if you're setting up to develop against this repository generally, not
just to run the demo.

```powershell
go vet ./...
go build ./...
go test -count=1 -p 1 ./...
```

`golangci-lint` (§1.7 for its pin) is CI's own additional check:
```powershell
golangci-lint run
```

**Only with §1.8's MinGW-w64 toolchain installed:**
```powershell
go test -race -count=1 -p 1 ./...
```
If `-race` fails to build with a linker error, confirm `gcc --version` resolves in the
same PowerShell session before assuming it's a code problem.

## 6. Integration package compile check + the integration suite

```powershell
go build -tags integration ./scripts/test/...
go vet -tags integration ./scripts/test/...
```

`scripts/test/daemon_process_windows.go` (`taskkill /T /F`, PowerShell's `Get-Process`
in place of POSIX process groups) is the Windows-specific half of this package — watch
it closely on a first real run, it has not yet been exercised on real Windows.

Same test names and `-run`/`-timeout` values as the macOS runbook's own integration
section — copy those invocations verbatim; only environment setup differs by platform,
and §3 above already covers the demo-specific case of that setup. `Get-Date` stands in
for macOS/Linux's `date` if you want the same timestamp markers between steps:
```powershell
Get-Date
go test -tags integration -v -run '^TestDemoTimeline$' ./scripts/test/ -timeout 60m
Get-Date
```

---

## 7. Known risks and Windows-specific notes

- **LAN-IP autodetection** (`up.ps1`'s `Get-NetIPConfiguration` call) may resolve to
  the wrong adapter on a machine with multiple active network interfaces (VPN clients,
  Hyper-V/WSL2/Docker Desktop's virtual switches, etc.). Pass `--AdvertiseAddr`
  explicitly if a volunteer or a joining machine reports it can't reach the printed URL.
- `cmd/provider/advertise.go`'s own autodetection skips interface names containing
  `vethernet` for the same reason — if your real LAN adapter happens to also match a
  filtered pattern, the same explicit-flag workaround applies.
- **The FIFO-less stdin-pipe approach** `up.ps1` uses to feed `provider onboard` its
  OTP code (`System.Diagnostics.Process` with `RedirectStandardInput`, since Windows
  has no named-pipe-with-nonblocking-open equivalent to `up.sh`'s `mkfifo`) has not
  been exercised on real Windows — if provider onboarding hangs rather than failing
  outright, this is the first place to look.
- **`down.ps1`'s `CloseMainWindow()`** graceful-stop attempt is flagged in its own
  comments as an unconfirmed analog to POSIX SIGTERM — `Stop-Process -Force` is the
  mechanism it actually depends on for guaranteed teardown, and is the only mechanism
  `kill_provider.ps1` (§3.6) uses at all, deliberately (see that script's own header).
- **File permission modes** (`0600`, `0700` in Go source) have very limited effect on
  Windows — `os.Chmod`/`os.OpenFile`'s mode bits are not enforced the same way NTFS
  ACLs would be. Known, accepted platform gap, not something this runbook attempts to
  close.
- **`Out-File -Encoding utf8`** (used by `up.ps1` for the generated demo SQL schema)
  writes UTF-8 without a BOM under PowerShell 7 — if `psql` ever reports a parse error
  on the first line of a generated `.sql` file specifically, a BOM slipping back in
  (e.g. from a different PowerShell version or a manual edit in an editor that adds
  one) is the first thing to rule out.
- **`kill_provider.ps1`** (§3.6, added this session) has the same untested-on-real-
  Windows status as the rest of this file's `.ps1` scripts — no `pwsh` was available in
  the sandbox it was written in. Its logic was reviewed for correctness (variable-name
  collisions with PowerShell's automatic `$Matches`, array-vs-scalar pipeline
  unrolling on a single match) but never executed. Report anything that doesn't match
  this document.
