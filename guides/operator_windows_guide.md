# Operator & Data Owner Guide — Windows

Two roles live in this guide. They can be one machine or two.

- **Operator** — runs the network and watches the live console. Sees everything about the
  network, never sees file contents.
- **Data owner** — uploads and gets back a file. Holds the keys, sees the contents.

> Use two machines if you have them. It makes the point of the whole system visible: the
> machine holding the keys is not the machine running the network.

Everyone lending a machine follows `provider_windows_guide.md` or `provider_unix_guide.md`.
Send those out early — their setup can happen while you do yours.

---

## Part 1 — Setup

### 1.1 For the operator

You need the most of anyone. Do this once.

**Package installer, Git, PowerShell 7:**

```pwsh
winget --version
git --version
$PSVersionTable.PSVersion
```

> Expect winget v1.2.xxxx and PowerShell `Major` ≥ 7
> Git — <https://git-scm.com/download/win>
> PowerShell 7 — `winget install --id Microsoft.PowerShell -e --source winget`

Open a new terminal called **pwsh** from the Windows button, then fix the path:

```pwsh
$profileDir = Split-Path $PROFILE

New-Item -ItemType Directory -Path $profileDir -Force | Out-Null

$pathBlock = @'
# --- Windows environment PATH ---
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$userPath    = [Environment]::GetEnvironmentVariable("Path", "User")

$env:Path = "$machinePath;$userPath"
# --- End Windows environment PATH ---
'@

if (-not (Test-Path $PROFILE)) {
    New-Item -ItemType File -Path $PROFILE -Force | Out-Null
}

$profileContent = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue

if ($profileContent -notmatch '# --- Windows environment PATH ---') {
    Add-Content -Path $PROFILE -Value "`r`n$pathBlock"
}
```

**Close pwsh. From here onwards run every command inside pwsh only.**

> Windows PowerShell 5 will not work. The scripts refuse to run on it.

**Go:**

```pwsh
go version
```

> If absent, visit <https://go.dev/dl/>
> Install `go1.26.2.windows-amd64.msi` — Installer, Windows x86-64, 59MB

**gcc**, needed to run the test suite:

```pwsh
gcc --version
```

> Look for 15.x.x. If absent, install MSYS2, open the **MSYS2 UCRT64** shell, and run:

```bash
pacman -Syu
```

> Press Y. The shell closes itself. Open MSYS2 UCRT64 again, run `pacman -Syu` once more,
> then:

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc
```

> Then, in pwsh **as administrator**:

```pwsh
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")

if ($machinePath -notlike "*C:\msys64\ucrt64\bin*") {
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$machinePath;C:\msys64\ucrt64\bin",
        "Machine"
    )
}
```

> New pwsh, then check:

```pwsh
where.exe gcc
gcc -dumpmachine
```

> Expect `C:\msys64\ucrt64\bin\gcc.exe` and `x86_64-w64-mingw32`
> **NOTE:** if you get `C:\MinGW\bin\gcc.exe`, an older gcc is in the way. As administrator:

```pwsh
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")

$machinePath = ($machinePath -split ';' |
    Where-Object { $_ -and $_ -ne 'C:\MinGW\bin' }) -join ';'

$machinePath += ';C:\msys64\ucrt64\bin'

[Environment]::SetEnvironmentVariable("Path", $machinePath, "Machine")
```

**Docker Desktop** — runs the database:

> <https://www.docker.com/products/docker-desktop/>, install and launch it once

```pwsh
docker --version
```

**psql** — the database client the start script needs:

```pwsh
psql --version
```

> If absent, download PostgreSQL from EnterpriseDB, Windows x86-64
> If the path doesn't pick up, check it directly:

```pwsh
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" --version
```

> Then, as administrator:

```pwsh
$pgPath = "C:\Program Files\PostgreSQL\18\bin"

$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")

if ($machinePath -notlike "*$pgPath*") {
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$machinePath;$pgPath",
        "Machine"
    )
}
```

> You only need the psql **client** from this install. The database server itself runs in
> Docker.

### 1.2 For the data owner

Much shorter. No Docker, no Postgres, no gcc.

```pwsh
git --version
go version
$PSVersionTable.PSVersion
```

> Expect go1.26.2 and PowerShell `Major` ≥ 7
> That is genuinely all. The owner's tool is a plain program that talks to the coordinator
> over the network.

### 1.3 Both

Turn off sleep for the duration:

> Settings → System → Power → Screen and sleep → set sleep to **Never**

---

## Part 2 — The private network

Every machine talks over one private network called a tailnet. You own it, so you set it up
first, before sending anyone their guide.

### 2.1 Create it and invite everyone

> Sign in at <https://login.tailscale.com/> and create your tailnet
> **Machines → Add device**, or use **Users → Invite** to send join links
> Send a link to every teammate lending a machine

### 2.2 Install and register your own machine

```pwsh
winget install --id Tailscale.Tailscale -e --source winget
tailscale up
tailscale ip -4
```

> Expect an address starting with `100.` — write it down, this is your coordinator address

### 2.3 Make auth keys ready in advance

Do this now, not when someone is stuck.

> Admin console → **Settings → Keys → Generate auth key**
> Make it reusable, set an expiry that covers your demo day

Some networks — college and office Wi-Fi especially — block the Tailscale login page. A
teammate on such a network cannot sign in through a browser, but they can join with:

```pwsh
tailscale up --auth-key=tskey-auth-xxxxxxxxxxxx
```

Have two or three of these ready to hand out.

### 2.4 Check who has actually joined

> Admin console → **Machines**

You should see every teammate's machine listed with a green dot and a `100.` address before
you start. If someone is missing, fix that before going further — nothing else will work
for them.

### 2.5 Open your port

As administrator, once:

```pwsh
New-NetFirewallRule -DisplayName "Vyomanaut coordinator" -Direction Inbound `
  -Protocol TCP -LocalPort 8080 -Action Allow -Profile Any
```

---

## Part 3 — Every command you will use

### Operator

```pwsh
# ── set once per terminal ────────────────────────────────────────────────
$MyIp = (tailscale ip -4)

# ── start and stop the network ───────────────────────────────────────────
docker compose -f deployments/dev/docker-compose.yml up -d postgres
.\scripts\demo\down.ps1
.\scripts\demo\up.ps1 -Providers 0 -AdvertiseHost $MyIp

# ── load this run's values into any new terminal (note the leading dot) ──
. $env:TEMP\vyomanaut-demo\env.ps1

# ── the live console ─────────────────────────────────────────────────────
& "$env:BIN_DIR\operator.exe" watch --mode=demo --microservice-url=$env:MICROSERVICE_URL --admin-api-key=$env:ADMIN_API_KEY

# ── read a teammate's join code (flags BEFORE the phone number) ──────────
& "$env:BIN_DIR\operator.exe" otp --mode=demo --otp-delivery-log=$env:OTP_LOG +919790000001

# ── inspect the network ──────────────────────────────────────────────────
& "$env:BIN_DIR\operator.exe" shards --mode=demo --microservice-url=$env:MICROSERVICE_URL --admin-api-key=$env:ADMIN_API_KEY <file_id>
& "$env:BIN_DIR\operator.exe" audit  --mode=demo --microservice-url=$env:MICROSERVICE_URL --admin-api-key=$env:ADMIN_API_KEY <provider_id> <chunk_id>
& "$env:BIN_DIR\operator.exe" payout --mode=demo --microservice-url=$env:MICROSERVICE_URL --admin-api-key=$env:ADMIN_API_KEY
```

### Data owner

```pwsh
# ── set once per terminal ────────────────────────────────────────────────
$MSURL     = "http://100.126.233.20:8080"          # the operator's address
$OwnerDir  = "$env:USERPROFILE\.vyomanaut-owner"

# ── identity and money ───────────────────────────────────────────────────
& "$env:BIN_DIR\client.exe" register --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir
& "$env:BIN_DIR\client.exe" recover  --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir --mnemonic="<24 words>"
& "$env:BIN_DIR\client.exe" deposit  --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir --amount-paise=1000000
& "$env:BIN_DIR\client.exe" balance  --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir

# ── files ────────────────────────────────────────────────────────────────
& "$env:BIN_DIR\client.exe" upload   --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir <path>
& "$env:BIN_DIR\client.exe" upload   --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir --resume <file_id>
& "$env:BIN_DIR\client.exe" ls       --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir
& "$env:BIN_DIR\client.exe" retrieve --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir -o <out> <file_id>
& "$env:BIN_DIR\client.exe" rm       --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir <file_id>
```

> `--mode=demo` on every single call. Without it the numbers on screen are computed against
> a different rulebook and everything looks broken while the system underneath is fine.

---

## Part 4 — Starting the network

### 4.1 Get the code

```pwsh
cd ~
git clone https://github.com/vyomanaut-labs/Vyomanaut_V2.git
cd .\Vyomanaut_V2\
```

Then check it builds:

```pwsh
go mod tidy
go vet ./...
go build ./...
```

> All three should finish silently.

### 4.2 Start Postgres — once, and leave it running

```pwsh
docker compose -f deployments/dev/docker-compose.yml up -d postgres
```

> Leave this container up for the whole session. The start script wipes and rebuilds the
> database itself on every run, so you do not need to touch Docker between attempts.
> Only if something seems genuinely broken:

```pwsh
docker compose -f deployments/dev/docker-compose.yml down -v
docker compose -f deployments/dev/docker-compose.yml up -d postgres
```

> The database holds only bookkeeping — who the machines are, which piece went where, the
> ledger. It never sees the contents of anything.

### 4.3 Start the coordinator

```pwsh
$MyIp = (tailscale ip -4)
$MyIp

.\scripts\demo\down.ps1
.\scripts\demo\up.ps1 -Providers 0 -AdvertiseHost $MyIp
```

> **Always run `down.ps1` first.** Leftover processes from a previous attempt holding the
> port are the most common cause of a failed restart.

> `-Providers 0` means the coordinator starts alone, leaving every slot free for a real
> machine to join. `-AdvertiseHost` is what the others will dial — pass it explicitly,
> always. Without it the script guesses which network card to publish, and on a machine
> running Tailscale alongside ordinary Wi-Fi that guess is a coin flip.

Save what it prints. **The admin key exists only on this machine and only for this run.**

Sanity check the output before continuing:

```
[up.ps1] MICROSERVICE_URL = http://100.126.233.20:8080
```

> It must be your `100.` address, not `127.0.0.1`.
> You should see **no** "onboarding local provider" lines at all with `-Providers 0`.

### 4.4 Give everyone the address

Tell your teammates:

```
http://<your 100. address>:8080
```

They can now start Part 4 of their own guide.

### 4.5 Open the console

New pwsh window:

```pwsh
. $env:TEMP\vyomanaut-demo\env.ps1
& "$env:BIN_DIR\operator.exe" watch --mode=demo --microservice-url=$env:MICROSERVICE_URL --admin-api-key=$env:ADMIN_API_KEY
```

> The leading `. ` (dot, space) matters. That is what loads the values into *your* terminal
> rather than a throwaway one.

Leave it running. `?` for the legend, `1`–`7` to focus a panel, arrows or `j`/`k` to scroll,
`q` to quit.

---

## Part 5 — Bringing machines in

Bring them in **one at a time**, confirming each appears before starting the next.

When a teammate asks for their code, in another pwsh window:

```pwsh
. $env:TEMP\vyomanaut-demo\env.ps1
& "$env:BIN_DIR\operator.exe" otp --mode=demo --otp-delivery-log=$env:OTP_LOG +919790000001
```

> **Flags before the phone number, always.** The parser stops reading at the first
> non-flag argument, so putting the number first silently drops every flag after it and you
> get a usage message instead of a code.

Assign numbers in order as people join: `+919790000001`, `+919790000002`, and so on.

### What you are watching for

**Provider fleet** — each machine appears, then walks through:

```
PENDING_ONBOARDING  →  VETTING  →  ACTIVE
```

**Readiness gate** — needs five machines at `ACTIVE`. Expect **ten to twelve minutes** after
the last one joins. The countdown on screen is accurate; nothing is stuck.

Things that look wrong but are not:

- Scores swinging by tens of points — the demo compresses a full day of scoring into minutes
- Audit timeouts early on — many challenges against few machines
- `operator audit` replying `PENDING` — that command queues the check, a background loop runs it
- A big machine holding zero pieces — placement spreads by network diversity, not by disk size
- **Escrow** showing charged above zero but released still zero — that is the hold window
  working, not a stalled payout

---

## Part 6 — The data owner's turn

On the owner's machine, once the console says the network is ready.

### 6.1 Set up

```pwsh
$MSURL    = "http://100.126.233.20:8080"      # the operator's real address
$OwnerDir = "$env:USERPROFILE\.vyomanaut-owner"
```

> The owner needs the `client.exe` binary. Easiest: copy it from the operator's
> `%TEMP%\vyomanaut-demo\bin\`, or clone the repo and run
> `go build -o client.exe .\cmd\client\`.

### 6.2 Register

```pwsh
& "$env:BIN_DIR\client.exe" register --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir
```

> **Write down the 24 words it shows.** They appear once. They are the only way back into
> this identity.

### 6.3 Add funds and check

```pwsh
& "$env:BIN_DIR\client.exe" deposit --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir --amount-paise=1000000
& "$env:BIN_DIR\client.exe" balance --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir
```

### 6.4 Upload

Use a **plain text file**. `README.md` from the repo works well.

```pwsh
& "$env:BIN_DIR\client.exe" upload --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir README.md
```

Save the file ID it prints.

> Why text: the point you are demonstrating is that the stored pieces look like noise. Text
> scores about 4.9 on the randomness scale and the stored pieces score about 7.999 — a
> visible gap. A video is already near 7.995 before you start, so the comparison shows
> nothing.

### 6.5 Show the two views side by side

Owner's view:

```pwsh
& "$env:BIN_DIR\client.exe" ls --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir
```

Operator's view:

```pwsh
& "$env:BIN_DIR\operator.exe" shards --mode=demo --microservice-url=$env:MICROSERVICE_URL --admin-api-key=$env:ADMIN_API_KEY <file_id>
```

The owner sees names, sizes, cost. The operator sees piece IDs, which machine holds what,
and the filename as unreadable ciphertext. Putting these next to each other is the clearest
way to show where the trust boundary sits.

### 6.6 Get it back

```pwsh
& "$env:BIN_DIR\client.exe" retrieve --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir -o out.md <file_id>
fc README.md out.md
```

> *"FC: no differences encountered"* is the sentence this whole project exists to earn.

---

## Part 7 — Killing a machine

Any machine can be stopped. There is no wrong one to pick.

**Abruptly** — have that teammate close their terminal or shut the lid.
**Politely** — have them run `provider depart` from their own guide.

Expect the network to notice within about three minutes. Watch the **Repair** panel go from
`queued: 0` to a job, then complete. Then check where the rebuilt piece landed:

```pwsh
& "$env:BIN_DIR\operator.exe" shards --mode=demo --microservice-url=$env:MICROSERVICE_URL --admin-api-key=$env:ADMIN_API_KEY <file_id>
```

Then retrieve the file again, with that machine still off, and compare. **Byte-identical
with a machine physically dead** is the whole claim, demonstrated rather than asserted.

While they are off, have them run `provider inspect` — their disk still holds encrypted
pieces, useless on their own. Two points in one moment.

---

## Part 8 — Deleting a file

```pwsh
& "$env:BIN_DIR\client.exe" rm --mode=demo --microservice-url=$MSURL --data-dir=$OwnerDir <file_id>
```

To show it rather than claim it: pick a machine holding a piece (`operator shards` before
deleting), have them stop their daemon and run `provider inspect --hex` to note what they
hold, restart, then run `rm`, wait under a minute, and have them stop and inspect again. The
pieces are gone.

> Be straight about the limits: it happens in the background, so a machine that is offline
> keeps its pieces until it comes back and is told again. And it is a database delete, not a
> forensic disk wipe.

---

## Part 9 — Shutting down

```pwsh
.\scripts\demo\down.ps1
```

Teammates stop their own machines with Ctrl-C in their own windows — `down.ps1` only touches
processes this machine started.

Between runs, on your machine:

```pwsh
.\scripts\demo\down.ps1
Remove-Item -Recurse -Force $env:TEMP\vyomanaut-demo
```

> **Tell every teammate to delete their data folder too** before rejoining. Their guide
> covers it. This is the single most common cause of a machine failing to rejoin after you
> restart — the start script rebuilds the network from scratch, and their old membership is
> no longer recognised.

---

## Part 10 — When something goes wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `database is being accessed by other users` | Leftover processes from the last attempt | `down.ps1` first, always |
| `microservice never became reachable` | Port 8080 still held | Same |
| The printed URL is `127.0.0.1` | `-AdvertiseHost` not passed, autodetect picked the wrong card | 4.3 — pass your `100.` address |
| "onboarding local provider" appears despite `-Providers 0` | Old copy of the start script | `git pull` and try again |
| A teammate registers, then goes DEPARTED with `401 invalid token` on their side | They kept a data folder from before you restarted | They delete it and rejoin — their guide, Part 4 |
| A teammate is never asked for a code | Same cause | Same fix |
| Script refuses to run, mentions version | You are in Windows PowerShell 5, not pwsh | 1.1 |
| `. env.ps1` throws a parser error | Missing the leading dot and space | 4.5 |
| Every number on the console looks wrong | `--mode=demo` missing | Add it |
| OTP prints usage instead of a code | Phone number placed before the flags | Flags first |
| `NETWORK_NOT_READY` on upload | Fewer than five machines at `ACTIVE` | Wait — the countdown is accurate |
| `INSUFFICIENT_PROVIDER_CAPACITY` | Machines registered but still in probation | Also just wait |
| A machine looks like it left but nobody touched it | That machine went to sleep | Their guide, sleep settings |
| A provider's repair-download or vetting-gc requests get rejected | That provider's clock is off by more than two minutes (`NetworkProfile.AuthRequestFreshnessWindow`, ADR-036) | Have them resync their clock — their guide's own troubleshooting section |
| A provider's heartbeats get rejected with `400: "timestamp skew exceeds 5 minutes"`, and they eventually go `DEPARTED` without ever leaving | Same root cause, different (looser) threshold — heartbeat's own check is a separate, hardcoded 5 minutes (`internal/api/provider.go: heartbeatTimestampSkew`), not the 2-minute `AuthRequestFreshnessWindow` above | Their guide's own troubleshooting section — usually campus/lab Wi-Fi blocking outbound NTP |
| Firewall popup | Expected, once | **Allow** |

> This demo runs over a private mesh network that handles the machine-to-machine
> connectivity for us. If anyone asks: the connectivity layer is Tailscale's, the storage,
> repair, auditing and payment logic on top of it is ours.
