# Provider Guide — joining a Vyomanaut demo network

**Who this is for:** you are lending a machine to a Vyomanaut demo network. Your machine
will store encrypted pieces of someone else's file and prove, on demand, that it still has
them. You are a **provider**.

**Companion document:** whoever runs the network follows
[`operator_and_client_guide.md`](./operator_and_client_guide.md). You need two things from
them, and this guide tells you exactly when to ask for each:

- the **coordinator address** — an overlay-mesh IP like `http://100.101.102.5:8080` — needed
  in §3
- a **6-digit code**, read to you over voice/chat when you ask — needed in §5

**This run is wireless — no Ethernet cable, no shared office LAN.** Every machine, including
yours, joins one private mesh network first (§2), and that mesh address is what the rest of
this guide uses everywhere. See the box in §2 for why, in one paragraph.

---

## 0. Everything this demo can do — full command reference

This is the complete command surface of the demo build. You will only run the **provider**
rows yourself; the rest are here so you know what the operator and the data owner are doing
when you watch the console, and so you recognise a command if someone asks you to try it.

`$MSURL` below means "the coordinator's address," which you will set once in §3.

| Role | macOS / Linux | Windows (PowerShell 7) |
| --- | --- | --- |
| **Provider** — inspect your storage | `provider inspect --data-dir=<dir> --hex --compare=<plaintext>` | `& ".\.vyomanaut-bin\provider.exe" inspect --data-dir=<dir> --hex --compare=<plaintext>` |
| Provider — inspect one chunk | `provider inspect --data-dir=<dir> --chunk <chunk_id>` | `& ".\.vyomanaut-bin\provider.exe" inspect --data-dir=<dir> --chunk <chunk_id>` |
| Provider — check earnings | `provider earnings --microservice-url=$MSURL --data-dir=<dir>` | `& ".\.vyomanaut-bin\provider.exe" earnings --microservice-url=$MSURL --data-dir=<dir>` |
| Provider — leave gracefully | `provider depart --microservice-url=$MSURL --data-dir=<dir>` | `& ".\.vyomanaut-bin\provider.exe" depart --microservice-url=$MSURL --data-dir=<dir>` |
| Provider — join the network | `scripts/demo/join.sh $MSURL --listen-port 30303 --advertise-addr $MY_IP --data-dir ~/.vyomanaut` | `.\scripts\demo\join.ps1 $MSURL -ListenPort 30303 -AdvertiseAddr $MyIp -DataDir $env:USERPROFILE\.vyomanaut` |
| *Operator* — live console | `operator watch --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY` | `& "operator.exe" watch --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY` |
| *Operator* — read a join code | `operator otp --mode=demo --otp-delivery-log=$OTP_LOG <phone>` | `& "operator.exe" otp --mode=demo --otp-delivery-log=$OTP_LOG <phone>` |
| *Operator* — see a file's shards | `operator shards --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY <file_id>` | `& "operator.exe" shards --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY <file_id>` |
| *Operator* — trigger an audit | `operator audit --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY <provider_id> <chunk_id>` | `& "operator.exe" audit --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY <provider_id> <chunk_id>` |
| *Operator* — payout table | `operator payout --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY` | `& "operator.exe" payout --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY` |
| *Data owner* — register | `client register --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` | `& "client.exe" register --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` |
| *Data owner* — recover identity | `client recover --mode=demo --microservice-url=$MSURL --data-dir=<dir> --mnemonic="<24 words>"` | `& "client.exe" recover --mode=demo --microservice-url=$MSURL --data-dir=<dir> --mnemonic="<24 words>"` |
| *Data owner* — deposit funds | `client deposit --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR --amount-paise=10000` | `& "client.exe" deposit --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR --amount-paise=10000` |
| *Data owner* — upload a file | `client upload --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR <path>` | `& "client.exe" upload --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR <path>` |
| *Data owner* — resume an upload | `client upload --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR --resume <file_id>` | `& "client.exe" upload --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR --resume <file_id>` |
| *Data owner* — list files | `client ls --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` | `& "client.exe" ls --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` |
| *Data owner* — retrieve a file | `client retrieve --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR -o <out> <file_id>` | `& "client.exe" retrieve --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR -o <out> <file_id>` |
| *Data owner* — check balance | `client balance --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` | `& "client.exe" balance --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` |
| *Data owner* — delete a file | `client rm --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR <file_id>` | `& "client.exe" rm --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR <file_id>` |
| *Operator* — shut everything down | `scripts/demo/down.sh` | `.\scripts\demo\down.ps1` |

**What this build can already do, in plain terms:** store a file split into encrypted
pieces across several independent machines; prove on demand that a piece hasn't been
tampered with or lost; automatically rebuild a piece and move it elsewhere if a machine
disappears; genuinely erase a piece from every machine holding it when the owner deletes the
file; and track what each provider is owed for the storage it contributed. Nobody except the
data owner's own machine ever assembles a readable copy of the file — not the coordinator,
not any single provider.

---

## 1. What your machine will and will not do

It stores fixed-size encrypted chunks that are individually meaningless — the provider
software has no code path that can decode anything, by construction. It does not run a
database, does not need Docker, and never sees a filename. You can look at exactly what it
holds (§8); it looks like noise, because it is.

**Time:** about 10 minutes if your machine is already set up (§1 assumptions below), most of
it the join command itself building the provider binary the first time.

**Assumed already done on your machine** (not covered here — ask the operator if any of
these are missing): Git; Go 1.26.2; on Windows, PowerShell 7; on macOS/Linux, RocksDB built
per `runbooks/macos.md` / `runbooks/linux.md` and its build-environment variables exported
in this terminal; and a Tailscale client, already installed and signed in to the shared demo
tailnet the operator invited you to.

---

## 2. Join the mesh network, and note your address

> **Why a mesh instead of a cable or the office Wi-Fi.** This run is deliberately wireless
> and deliberately not confined to one room's network — see `ADR-089` in the research repo
> if you want the full reasoning. In short: Vyomanaut's own machine-to-machine networking
> cannot yet get through a home router's NAT on its own, so every machine in this demo joins
> one shared, encrypted mesh (Tailscale) first. Once you're on it, every other machine in
> the demo is reachable at a stable address, regardless of whose Wi-Fi or which city you're
> actually on. **Be plain about this if anyone asks how it works:** the mesh is doing the
> NAT traversal here, not Vyomanaut's own networking — that piece of Vyomanaut is built but
> not yet wired up.

Confirm you're connected and get your own address — same command on every platform

Inside the terminal share the two export:
**macOS / Linux:**

```bash
MY_IP="$(tailscale ip -4)"
export MY_IP=MY_IP
export MSURL="http://100.126.233.20:8080"
```

**Windows (PowerShell 7):**

```powershell
$MyIp = (tailscale ip -4)
$env:MyIp = $MyIp
$env:MSURL = "http://100.126.233.20:8080"
```

You should see an address starting `100.`. **Write it down** — it's your `-AdvertiseAddr` /
`--advertise-addr` in §4, and the single most important value in this whole guide. If
nothing prints, or the command isn't found, stop and tell the operator before continuing —
you are not on the mesh yet.

---

## 3. Get the code, and get the coordinator's address

```bash
cd ~
cd Vyomanaut_V2
```

Next for **macOS** set up the CGO flags (not for windows):

```bash
export CGO_CFLAGS="-I$HOME/rocksdb/include"
export CGO_LDFLAGS="-L$HOME/rocksdb/lib -L$(brew --prefix)/lib -L$(brew --prefix snappy)/lib \
  -Wl,-rpath,$HOME/rocksdb/lib -Wl,-rpath,$(brew --prefix)/lib -Wl,-rpath,$(brew --prefix snappy)/lib \
  -lrocksdb -lstdc++ -lm -lz -lbz2 -lsnappy -llz4 -lzstd"
export DYLD_LIBRARY_PATH="$HOME/rocksdb/lib:$(brew --prefix)/lib:$(brew --prefix snappy)/lib:$DYLD_LIBRARY_PATH"

```

Then test everything working well:

```bash
go vet ./...
go build ./...
```

Ask the operator for the coordinator's address — it will look like
`http://100.101.102.5:8080`, their own mesh IP from §2 plus `:8080`. Save it:

---

## 4. Open your port

**Windows** — as Administrator, once per machine:

```powershell
New-NetFirewallRule -DisplayName "Vyomanaut provider" -Direction Inbound `
  -Protocol TCP -LocalPort 30303 -Action Allow -Profile Any
```

You may also see a one-time popup, *"Do you want to allow public and private networks to
access this app?"* — click **Allow**. Clicking Cancel makes your machine unreachable in a
way that is hard to diagnose later.

**macOS** — usually nothing to do. If the firewall is on, allow incoming connections for
`provider` when prompted.

**Sleep and Wi-Fi power saving — turn both off** for the duration of the demo, on every
platform. A machine that lets its network adapter idle looks, to the network, exactly like a
machine that has abruptly left — which matters a lot once we start deliberately testing that
scenario later and you don't want it to happen to you by accident.

---

## 5. Join the network

You'll need your listen port (30303 unless the operator says otherwise), your own mesh
address from §2, and the coordinator's address from §3.

**macOS / Linux:**

```bash
scripts/demo/join.sh "$MSURL" --listen-port 30303 --advertise-addr "$MY_IP" --data-dir ~/.vyomanaut
```

**Windows (PowerShell 7):**

```powershell
.\scripts\demo\join.ps1 $env:MSURL -ListenPort 30303 -AdvertiseAddr $env:MyIp -DataDir $env:USERPROFILE\.vyomanaut
```

`-AdvertiseAddr` / `--advertise-addr` is **your own** mesh address from §2 — always pass it
explicitly. Left out, the software tries to guess, and on a machine with more than one active
network connection (which having joined the mesh makes true for every machine here) it can
easily guess your ordinary Wi-Fi address instead — reachable by nobody else in this demo.

The first run builds the provider binary from source, which takes a minute or two. Then it
asks you three things:

1. **Your phone number**, in `+91...` format — an identifier only, the operator will tell
   you which number to use.
2. **How much storage to share, in GB.** Enter **1** unless told otherwise.
3. **A 6-digit code** — this is where you **ask the operator for your code**. They read it
   off their own screen.

After that your daemon starts and stays in the foreground. **Leave this window open.**
Closing it, or pressing Ctrl-C, takes your machine off the network.

You should see, in order: a startup banner, your Peer ID, `advertising <your mesh IP>:30303`,
and finally `Vyomanaut provider daemon ready`. **Check that the advertised address matches
the one you wrote down in §2** — if it doesn't, stop and tell the operator; something guessed
wrong. Then tell them you're up; they'll confirm you've appeared on their console.

---

## 6. What "vetting" means, and why nothing happens for 10 minutes

You will not receive any data immediately. New providers go through a probation period —
the network stores test chunks on your machine and challenges you to prove you still hold
them. You need five successful proofs and at least five minutes before you're promoted to
`ACTIVE`. The operator's console shows this happening. **Roughly 10–12 minutes** from when
the last machine joins to when the network accepts its first real upload. You don't need to
do anything during this time.

---

## 7. Looking at what you are storing

Worth doing once you're `ACTIVE`. The storage engine holds an exclusive lock while the
daemon runs, so **stop your daemon first** (Ctrl-C in its window), then:

**macOS / Linux:**

```bash
.vyomanaut-bin/provider inspect --data-dir=~/.vyomanaut --hex
```

**Windows (PowerShell 7):**

```powershell
& ".\.vyomanaut-bin\provider.exe" inspect --data-dir="$env:USERPROFILE\.vyomanaut" --hex
```

You'll see every chunk you hold: an ID, a uniform size, an entropy figure around **7.999
bits per byte**, and a hex dump whose text column is nothing but dots. The theoretical
maximum is 8.0 — what's on your disk is statistically indistinguishable from random noise.
Ordinary English text measures about 4.9, for contrast. Every chunk is exactly the same
size, so even the size tells you nothing about what the file was.

To make the contrast concrete, ask the operator for the plaintext file they uploaded and add
`--compare=<that file>` to the command above. The provider software contains no code that
can reverse this — structurally, not as a promise: there is no import path anywhere in it to
a decoding routine.

**Restart your daemon afterward** — same `join` command as §5; it finds your saved
registration and skips straight to running, keeping your identity.

---

## 8. Leaving the network

**Politely** — tells the network in advance so it can move your data first:

**macOS / Linux:** `provider depart --microservice-url="$MSURL" --data-dir=~/.vyomanaut`
**Windows:** `& ".\.vyomanaut-bin\provider.exe" depart --microservice-url=$MSURL --data-dir="$env:USERPROFILE\.vyomanaut"`

**Abruptly** — close the lid, or pull the power. This is a legitimate thing to demonstrate:
the network notices you're gone, rebuilds your pieces from the others, and places them
elsewhere. The owner's file survives. Since ADR-088, **any** provider can be stopped this
way — there is no longer a "wrong" machine to pick.

**Rejoining** is the same `join` command from §5. It finds your saved registration and
resumes your original identity.

One honest note: **departing does not erase what's on your disk.** The network moves your
pieces elsewhere, but your own copy stays put — individually meaningless, but not deleted.
Delete your data directory yourself if you want it gone. Deletion *by the owner* is
different — see §9.

---

## 9. When the owner deletes a file, your copy really goes

If the data owner runs `client rm`, the coordinator tells every provider holding a shard of
that file to erase it, over the same authenticated channel used for everything else. Worth
watching:

1. With your daemon **stopped**, run `provider inspect --data-dir=... --hex` and note a
   chunk ID or two.
2. Restart your daemon and leave it running.
3. Have the owner run `client rm <file_id>`.
4. Wait for the coordinator's next delivery cycle (under a minute on this demo profile).
5. Stop your daemon again and re-run `inspect`. Those chunk IDs are gone.

Two honest caveats: it's **asynchronous** (a machine offline at deletion time keeps its
shards until reachable again, and the coordinator retries), and it's a **storage-engine
delete**, not a forensic wipe of the underlying disk sectors.

---

## 10. Sharing metrics with the operator (optional)

Your daemon already reports Prometheus metrics to your own machine only
(`127.0.0.1:9091`), because that endpoint has no authentication. If the operator is
collecting metrics across the rig, add this to your `join` command:

```
--metrics-addr=<your mesh IP>:9091
```

**Bind it to your own mesh address specifically — never `0.0.0.0`.** `0.0.0.0` publishes
those figures on *every* network interface your laptop has, including whatever Wi-Fi it's
also connected to, not just the mesh. Your own address only reaches other machines already
on the mesh.

**Windows** also needs the port opened, same as §4:
```powershell
New-NetFirewallRule -DisplayName "Vyomanaut metrics" -Direction Inbound `
  -Protocol TCP -LocalPort 9091 -Action Allow -Profile Any
```

---

## 11. Cleaning up before a fresh run

If your machine was in a previous run, stop the daemon (Ctrl-C), then delete its data
directory so it joins as a genuinely new volunteer rather than resuming a stale registration:

**macOS / Linux:** `rm -rf ~/.vyomanaut`
**Windows:** `Remove-Item -Recurse -Force "$env:USERPROFILE\.vyomanaut"`

This removes your identity keystore, your registration, and every chunk you were holding.
Skipping this is a real trap: your daemon rejoins as its old self, pointing at a coordinator
that may no longer exist, and just quietly never appears on the new console.

---

## 12. When something goes wrong

| What you see | What it means | What to do |
| --- | --- | --- |
| `bind: address already in use` on port 30303 | Another provider already running on this machine | Close the other window, or pass a different `-ListenPort` |
| `tailscale ip -4` prints nothing / command not found | Not on the mesh yet | Stop — tell the operator before continuing |
| Registered, but the operator can't see you connect | Almost always the wrong advertised address | Recheck §2 and §5 — pass your mesh IP explicitly, don't rely on autodetection |
| Onboarding hangs after entering the code | Usually a wrong code, or the operator read the wrong line | Ask them to re-read it — codes are per phone number |
| `connection refused` to the coordinator | Coordinator not running, wrong address, or your firewall | Recheck §3 and §4, then ask the operator |
| `NETWORK_NOT_READY` mentioned by the operator | Not your problem — fewer than five machines are `ACTIVE` yet | Wait |
| Build fails on macOS with linker errors | RocksDB build-environment variables not exported in this terminal | See `runbooks/macos.md` |
| Windows firewall popup | Expected, once per program | Click **Allow** |
| Daemon rejoins as an old provider you didn't expect | Stale `~/.vyomanaut` from a previous run | §11 |
| Operator can't scrape your metrics | Bound to loopback by default, or bound to `0.0.0.0` | §10 — use your own mesh address, not `0.0.0.0` |
| Chunks didn't disappear after the owner deleted a file | Delivery is asynchronous; your daemon must be running and reachable | Leave it running, wait a cycle, re-check |
| You register fine but the operator says you never send a heartbeat, and eventually you show `DEPARTED` | A now-fixed bug: `join.ps1`'s `run` step was missing a required flag, so a Windows provider silently ran with a ~4-hour heartbeat interval instead of demo's ~30-second one | Make sure your checkout is current, then just re-run the join command (§5) |
| Your machine looks like it "departed" but nobody touched it | Wi-Fi/sleep power saving idled the adapter | §4 — turn both off for the whole session |

If you're stuck, the useful things to tell the operator are: your Peer ID, your mesh
address from §2, and the last five lines of your terminal.
