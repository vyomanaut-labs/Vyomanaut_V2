# Provider Guide — Windows

You are lending a Windows machine to the Vyomanaut demo network. Your machine stores
encrypted pieces of someone else's file and proves, on demand, that it still has them.

You need two things from the operator. Ask for them when you get there:

- the **coordinator address** — looks like `http://100.126.233.20:8080`
- a **6-digit code** — only the first time you join

> Your machine never sees a filename and never holds a readable copy of anything. What it
> stores looks like random noise, because it is.

---

## Part 1 — Setting up Windows

Do this once. Skip anything you already have.

### 1.1 Package installer

```pwsh
winget --version
```

> Expect v1.2.xxxx

### 1.2 Git

```pwsh
git --version
```

> If absent, install from <https://git-scm.com/download/win>

### 1.3 PowerShell 7

```pwsh
$PSVersionTable.PSVersion
```

> Expect `Major` ≥ 7
> If not:

```pwsh
winget install --id Microsoft.PowerShell -e --source winget
```

> Open a new terminal called **pwsh** from the Windows button
> Check the version again

```pwsh
$PSVersionTable.PSVersion
```

> Then fix the path:

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

### 1.4 Go

```pwsh
go version
```

> If absent, visit <https://go.dev/dl/>
> Install `go1.26.2.windows-amd64.msi` — Installer, Windows x86-64, 59MB
> Open a fresh pwsh afterwards

### 1.5 gcc

Needed to run the test suite.

```pwsh
gcc --version
```

> Look for 15.x.x
> If absent, download MSYS2
> After installing, open the specific shell: **MSYS2 UCRT64**

Inside MSYS2 UCRT64:

```bash
pacman -Syu
```

> Press Y when prompted
> The shell closes by itself
> Open MSYS2 UCRT64 again and run it once more

```bash
pacman -Syu
```

Then:

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc
```

> Now set the path
> Click the Windows icon, right click **pwsh**, run as administrator

Inside pwsh (administrator):

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

> Close it, open a new pwsh

```pwsh
where.exe gcc
gcc --version
gcc -dumpmachine
```

> Expect `C:\msys64\ucrt64\bin\gcc.exe` and `x86_64-w64-mingw32`
> **NOTE:** if you get `C:\MinGW\bin\gcc.exe`, an older gcc is already installed
> Fix it as administrator:

```pwsh
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")

$machinePath = ($machinePath -split ';' |
    Where-Object { $_ -and $_ -ne 'C:\MinGW\bin' }) -join ';'

$machinePath += ';C:\msys64\ucrt64\bin'

[Environment]::SetEnvironmentVariable("Path", $machinePath, "Machine")
```

> You do **not** need Docker or a Postgres server. Those are the operator's job.

---

## Part 2 — Joining the private network

Every machine in this demo talks over one private network called a tailnet. Join it before
anything else, or nothing will connect.

### 2.1 Accept the invite

> The operator sends you a join link
> Open it, sign in, accept

### 2.2 Install Tailscale

```pwsh
winget install --id Tailscale.Tailscale -e --source winget
```

> Or download from <https://tailscale.com/download/windows>

### 2.3 Log in and register this machine

```pwsh
tailscale up
```

> A browser window opens. Sign in with the same account you accepted the invite on.
> Your machine now appears on the operator's device list.

### 2.4 Get your address

```pwsh
tailscale ip -4
```

> Expect something starting with `100.`
> **Write it down.** This is the single most important value in this guide.

### 2.5 If your network blocks the login

Common on college, office and hotel Wi-Fi.

```pwsh
tailscale status
```

- **The browser page won't load at all** — ask the operator for an auth key instead. They
  generate one from their admin console. Then:

  ```pwsh
  tailscale up --auth-key=tskey-auth-xxxxxxxxxxxx
  ```

  This skips the browser entirely.

- **`tailscale status` says `relay`, not `direct`** — that is fine. It means the network
  blocked the fast path and Tailscale fell back to routing over standard web traffic.
  Slower, still works.

- **Nothing connects at all** — tether to a phone hotspot and try again. Tell the operator
  either way.

---

## Part 3 — Every command you will use

All of these run inside pwsh, from the `Vyomanaut_V2` folder. Set the two values at the top
first — everything else refers to them.

```pwsh
# ── set once per terminal ────────────────────────────────────────────────
$MyIp  = "100.105.176.94"              # yours, from `tailscale ip -4`
$MSURL = "http://100.126.233.20:8080"  # the operator's, ask them

# ── join the network (this is the main one) ──────────────────────────────
.\scripts\demo\join.ps1 $MSURL -ListenPort 30303 -AdvertiseAddr $MyIp -DataDir $env:USERPROFILE\.vyomanaut

# ── look at what you are storing (stop the daemon first) ─────────────────
& ".\.vyomanaut-bin\provider.exe" inspect --data-dir="$env:USERPROFILE\.vyomanaut" --hex
& ".\.vyomanaut-bin\provider.exe" inspect --data-dir="$env:USERPROFILE\.vyomanaut" --chunk <chunk_id>
& ".\.vyomanaut-bin\provider.exe" inspect --data-dir="$env:USERPROFILE\.vyomanaut" --hex --compare="<original file>"

# ── what you have earned ─────────────────────────────────────────────────
& ".\.vyomanaut-bin\provider.exe" earnings --microservice-url=$MSURL --data-dir="$env:USERPROFILE\.vyomanaut"

# ── leave politely (tells the network first) ─────────────────────────────
& ".\.vyomanaut-bin\provider.exe" depart --microservice-url=$MSURL --data-dir="$env:USERPROFILE\.vyomanaut"

# ── start over as a brand new machine ────────────────────────────────────
Remove-Item -Recurse -Force "$env:USERPROFILE\.vyomanaut"
```

---

## Part 4 — Running it

Open pwsh. Work through this in order.

### 4.1 Get the code

```pwsh
cd ~
git clone https://github.com/vyomanaut-labs/Vyomanaut_V2.git
cd .\Vyomanaut_V2\
```

> Already cloned? Just `cd ~\Vyomanaut_V2` and pull the latest:

```pwsh
git pull
```

### 4.2 Check it builds

```pwsh
go mod tidy
go vet ./...
go build ./...
```

> All three should finish silently. Silence is success.

### 4.3 Open your port, once per machine

Right click pwsh, run as administrator:

```pwsh
New-NetFirewallRule -DisplayName "Vyomanaut provider" -Direction Inbound `
  -Protocol TCP -LocalPort 30303 -Action Allow -Profile Any
```

> You may also get a popup: *"Do you want to allow public and private networks to access
> this app?"* — click **Allow**. Clicking Cancel makes your machine unreachable in a way
> that is annoying to diagnose later.

### 4.4 Turn off sleep

> Settings → System → Power → Screen and sleep → set sleep to **Never**

A machine that dozes off looks exactly like a machine that left the network. That matters
later, when leaving is something we test on purpose.

### 4.5 Set your two values

```pwsh
$MyIp  = (tailscale ip -4)
$MSURL = "http://100.126.233.20:8080"   # the operator's real address
$MyIp
```

> Check `$MyIp` printed a `100.` address before continuing.

### 4.6 Fresh start check — do not skip this

**If the operator has restarted the coordinator since you last joined, delete your data
folder first:**

```pwsh
Remove-Item -Recurse -Force "$env:USERPROFILE\.vyomanaut"
```

> Why: when the operator restarts, the network is rebuilt from scratch and your old
> membership is no longer recognised. Keeping the old folder makes the join script skip the
> code step and the daemon then gets rejected on every heartbeat with `401 invalid token`.
> Deleting the folder is the fix. When in doubt, delete it.

### 4.7 Join

```pwsh
.\scripts\demo\join.ps1 $MSURL -ListenPort 30303 -AdvertiseAddr $MyIp -DataDir $env:USERPROFILE\.vyomanaut
```

The first run builds the provider, which takes a minute or two. Then it asks you three
things:

1. **Your phone number**, like `+919790000001` — the operator tells you which one to use
2. **How much storage to share, in GB** — enter **10** unless told otherwise
3. **A 6-digit code** — this is when you ask the operator. They read it off their screen.

Then the daemon starts and stays in the foreground.

**Leave this window open.** Closing it or pressing Ctrl-C takes your machine off the network.

### 4.8 Check the right things happened

You should see, in order:

```
[STARTUP][single] Peer ID: 12D3Koo...
[STARTUP][single] advertising 100.105.176.94:30303 to the network
[STARTUP][single] Vyomanaut provider daemon ready
```

> **Check the advertised address matches your own `100.` address.** If it doesn't, stop and
> tell the operator.

Then tell the operator you are up. They will confirm you appeared on their screen.

### 4.9 Nothing happens for about ten minutes

That is correct. New machines go through a probation period — the network stores test
pieces on your disk and challenges you to prove you still have them. Five successful proofs
and at least five minutes, then you are promoted.

You do not need to do anything during this time.

---

## Part 5 — Things you might be asked to do

### Look inside your own storage

The storage is locked while the daemon runs, so stop it first with Ctrl-C, then:

```pwsh
& ".\.vyomanaut-bin\provider.exe" inspect --data-dir="$env:USERPROFILE\.vyomanaut" --hex
```

You will see chunks of identical size and a hex dump whose text column is nothing but dots.
The "entropy" figure will read about **7.999** out of a maximum of 8.0 — meaning it is
statistically indistinguishable from random noise. Ordinary English text measures about 4.9.

Restart the daemon afterwards with the same join command. It remembers who you are.

### Leave on purpose

Politely, so the network can move your data first:

```pwsh
& ".\.vyomanaut-bin\provider.exe" depart --microservice-url=$MSURL --data-dir="$env:USERPROFILE\.vyomanaut"
```

Or abruptly — just close the lid or the window. Both are legitimate things to demonstrate.
The network notices, rebuilds your pieces from the others, and puts them somewhere else. The
owner's file survives either way.

> Departing does not wipe your disk. Your own copy stays where it is, still meaningless on
> its own. Delete the folder yourself if you want it gone.

---

## Part 6 — When something goes wrong

| What you see | What it means | What to do |
| --- | --- | --- |
| `401` / `invalid token`, repeating | Your saved membership is from an older run of the network | 4.6 — delete the data folder and join again |
| Join script never asks for a phone number or code | Same cause: you still have an old data folder | 4.6 |
| `The term '...join.ps1' is not recognized` | Wrong folder | `cd ~\Vyomanaut_V2` first |
| Script refuses to run, mentions version | You are in Windows PowerShell 5, not pwsh | 1.3 |
| `tailscale ip -4` prints nothing | Not on the tailnet yet | Part 2 — stop and tell the operator |
| `bind: address already in use` | A provider is already running here | Close the other window, or use `-ListenPort 30304` |
| Registered, but the operator sees nothing connect | Usually the wrong advertised address | Recheck 4.5 and 4.8 — pass your `100.` address explicitly |
| `connection refused` to the coordinator | Coordinator down, wrong address, or firewall | Recheck 4.3 and your `$MSURL`, then ask |
| Operator mentions `NETWORK_NOT_READY` | Not your problem — not enough machines yet | Wait |
| You look like you left, but you didn't touch anything | The machine went to sleep | 4.4 |
| Firewall popup | Expected, once | **Allow** |

If you are stuck, send the operator: your Peer ID, your `100.` address, and the last five
lines of your terminal.
