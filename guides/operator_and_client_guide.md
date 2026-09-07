# Operator & Client Guide — running a Vyomanaut demo network

**Who this is for:** you are running the demo. This guide covers two roles, which may be
one machine or two:

- **Operator** — runs the coordinator and the live console. Sees the network; never sees
  file contents.
- **Data owner** — uploads and retrieves a file. Holds the keys; sees the contents.

**Companion document:** everyone lending a machine follows
[`provider_guide.md`](./provider_guide.md). You supply them with two things: the
**coordinator address** and a **6-digit code** on request. Send them that guide ahead of
time — their setup is short and can happen in parallel with yours.

**This run is wireless — no Ethernet cable, no shared office LAN.** Every machine joins one
private mesh network first (§3), and that mesh address is what the rest of this guide uses
everywhere. See the box in §3 for why, in one paragraph, and §3's fallback note for what to
do if the mesh doesn't cooperate on the day.

---

## 0. Everything this demo can do — full command reference

Two placeholders recur through this whole guide: `$MSURL` — the coordinator's address,
`http://<mesh IP>:8080` — and `$KEY` — the admin API key printed when the network starts
(§5). Both are this guide's own shorthand for readability, used the same way on every
platform. **The one place they're not shorthand** is right after you load the network's
own env file (§6–§7): there, the real exported names are `$MICROSERVICE_URL` /
`$ADMIN_API_KEY` (`$env:MICROSERVICE_URL` / `$env:ADMIN_API_KEY` on Windows) — identical
values, just the literal names the scripts themselves chose. Everywhere else in this guide,
including this table, `$MSURL` / `$KEY` is what you'll actually type.

| Role | macOS / Linux | Windows (PowerShell 7) |
| --- | --- | --- |
| **Operator** — live console | `operator watch --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY` | `& "$env:BIN_DIR\operator.exe" watch --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY` |
| Operator — read a join code | `operator otp --mode=demo --otp-delivery-log=$OTP_LOG <phone>` | `& "$env:BIN_DIR\operator.exe" otp --mode=demo --otp-delivery-log=$OTP_LOG <phone>` |
| Operator — see a file's shards | `operator shards --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY <file_id>` | `& "$env:BIN_DIR\operator.exe" shards --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY <file_id>` |
| Operator — trigger an audit | `operator audit --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY <provider_id> <chunk_id>` | `& "$env:BIN_DIR\operator.exe" audit --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY <provider_id> <chunk_id>` |
| Operator — payout table | `operator payout --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY` | `& "$env:BIN_DIR\operator.exe" payout --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY` |
| **Data owner** — register | `client register --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` | `& "$env:BIN_DIR\client.exe" register --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` |
| Data owner — recover identity | `client recover --mode=demo --microservice-url=$MSURL --data-dir=<dir> --mnemonic="<24 words>"` | `& "$env:BIN_DIR\client.exe" recover --mode=demo --microservice-url=$MSURL --data-dir=<dir> --mnemonic="<24 words>"` |
| Data owner — deposit funds | `client deposit --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR --amount-paise=10000` | `& "$env:BIN_DIR\client.exe" deposit --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR --amount-paise=10000` |
| Data owner — upload a file | `client upload --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR <path>` | `& "$env:BIN_DIR\client.exe" upload --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR <path>` |
| Data owner — resume an upload | `client upload --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR --resume <file_id>` | `& "$env:BIN_DIR\client.exe" upload --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR --resume <file_id>` |
| Data owner — list files | `client ls --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` | `& "$env:BIN_DIR\client.exe" ls --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` |
| Data owner — retrieve a file | `client retrieve --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR -o <out> <file_id>` | `& "$env:BIN_DIR\client.exe" retrieve --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR -o <out> <file_id>` |
| Data owner — check balance | `client balance --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` | `& "$env:BIN_DIR\client.exe" balance --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR` |
| Data owner — delete a file | `client rm --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR <file_id>` | `& "$env:BIN_DIR\client.exe" rm --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR <file_id>` |
| *Provider* — join the network (their own `$MSURL`, set by hand — they have no env file) | `scripts/demo/join.sh "$MSURL" --listen-port 30303 --advertise-addr "$MY_IP" --data-dir ~/.vyomanaut` | `.\scripts\demo\join.ps1 $MSURL -ListenPort 30303 -AdvertiseAddr $MyIp -DataDir $env:USERPROFILE\.vyomanaut` |
| *Provider* — inspect storage | `provider inspect --data-dir=<dir> --hex --compare=<plaintext>` | `& ".\.vyomanaut-bin\provider.exe" inspect --data-dir=<dir> --hex --compare=<plaintext>` |
| *Provider* — earnings | `provider earnings --microservice-url="$MSURL" --data-dir=<dir>` | `& ".\.vyomanaut-bin\provider.exe" earnings --microservice-url=$MSURL --data-dir=<dir>` |
| *Provider* — leave gracefully | `provider depart --microservice-url="$MSURL" --data-dir=<dir>` | `& ".\.vyomanaut-bin\provider.exe" depart --microservice-url=$MSURL --data-dir=<dir>` |
| **You** — start the network | `scripts/demo/up.sh --providers 0 --advertise-host "$MY_IP"` | `.\scripts\demo\up.ps1 -Providers 0 -AdvertiseHost $MyIp` |
| **You** — shut everything down | `scripts/demo/down.sh` | `.\scripts\demo\down.ps1` |

**What this build can already do, in plain terms:** store a file split into encrypted
pieces across several independent machines; prove on demand that a piece hasn't been
tampered with or lost; automatically rebuild a piece and move it elsewhere if a machine
disappears; genuinely erase a piece from every machine holding it when the owner deletes the
file; and track what each provider is owed. Nobody except the data owner's own machine ever
assembles a readable copy of the file — not the coordinator, not any single provider.

---

## 1. Roles and machines

| Role | Needs | Guide |
| --- | --- | --- |
| Operator + coordinator | Docker, psql client, Go, git, Tailscale | this guide, §2–7 |
| Data owner | Go, git, Tailscale | this guide, §8 |
| Providers ×N | Go, git, Tailscale | `provider_guide.md` |

**Should the owner be a separate machine? Yes, if you have one.** `client` needs only the
coordinator's address and its own data directory; it never touches the database or the
admin API. Splitting it makes the demo's central claim visible rather than asserted: the
machine holding the keys is not the machine running the network, and neither is a machine
storing data.

One hard constraint: the owner's identity keystore lives in its data directory, so
`register` and any later `retrieve` **must run on the same machine**.

**Recommended size: 7 providers.** Five is the minimum the network will accept uploads at;
seven gives two spare machines so you can stop one — twice — and stay above the floor.

---

## 2. Assumptions

Not covered here — confirm these are ready before starting, per-machine, ahead of time:

- **Operator machine:** Git, Go 1.26.2, Docker (with `docker compose`), the `psql` client,
  and — on macOS/Linux — RocksDB built per `runbooks/macos.md` / `runbooks/linux.md` with
  its build-environment variables exported in every terminal you compile in.
- **Owner machine:** Git, Go 1.26.2. Nothing else — `client` has no database or RocksDB
  dependency.
- **Every machine, including yours:** a Tailscale client, installed and signed in to the
  shared demo tailnet. (If you haven't created that tailnet and invited everyone yet, do
  that before sending out `provider_guide.md` — it's the one prerequisite this guide
  introduces that older runs didn't need, and it's yours to set up once, not each
  volunteer's.)

---

## 3. Join the mesh network, and note your address

> **Why a mesh instead of a cable or the office Wi-Fi (ADR-089).** Vyomanaut's own
> machine-to-machine networking cannot yet get through a home router's NAT on its own — the
> code for it exists but nothing wires it up yet. So every machine in this demo joins one
> shared, encrypted mesh (Tailscale) first, and every address this guide uses from here on
> is a mesh address, not a LAN one. Once everyone's on it, machines are reachable at a
> stable address regardless of whose Wi-Fi or which city they're actually on — which is
> also a better rehearsal of Vyomanaut's real target shape (providers connected over the
> open internet) than a single switch ever was. **Be plain about this if it comes up on the
> day:** the mesh is doing the NAT traversal here, not Vyomanaut's own networking.
>
> **Fallback, decided in advance, not improvised at the rig:** if the mesh isn't cooperating,
> every machine falls back to one Wi-Fi access point instead — same commands throughout this
> guide, just substitute each machine's Wi-Fi IP for its mesh IP, disable AP client
> isolation, and use static DHCP reservations so an address never changes mid-run. Nothing
> else in this guide changes.

**macOS / Linux:**
```bash
MY_IP="$(tailscale ip -4)"
echo "$MY_IP"
```
**Windows (PowerShell 7):**
```powershell
$MyIp = (tailscale ip -4)
$MyIp
```

Write this down. It's what you pass to `up.sh`/`up.ps1` in §5 instead of letting the script
guess, and once the network is up, it's the basis of the coordinator address you hand every
volunteer (§5.3).

---

## 4. Get the code and verify the build

```bash
cd ~
git clone https://github.com/vyomanaut-labs/Vyomanaut_V2.git
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

Once this is clean, you already know what `$MSURL` will be — `http://<your mesh IP from
§3>:8080` — even before the network is running. Share that with your team as soon as the
network is actually up (§5), so they can start `provider_guide.md`'s §2–§5 (mesh through
join) in parallel with yours.

Inside the terminal share the two export:
**macOS / Linux:**

```bash
export MSURL="http://100.126.233.20:8080"
export MY_IP="100.126.233.20"
```

For windows:
**Windows (PowerShell 7):**

```pwsh
$env:MSURL = "http://100.126.233.20:8080"
$env:MyIp = "100.126.233.20:8080"
```

---

## 5. Start the network

### 5.1 Postgres — once, not before every retry

```bash
docker compose -f deployments/dev/docker-compose.yml down -v
docker compose -f deployments/dev/docker-compose.yml up -d postgres
```

**Run this once, the first time, and leave the container running** for the rest of the
session — `up.sh`/`up.ps1` already run a full `DROP DATABASE` / `CREATE DATABASE` themselves
on every single invocation (`up.sh`'s own Postgres-reset step), so tearing the container
itself down and recreating it before every retry is redundant work that also adds a real
race: a freshly-recreated container needs a moment before Postgres inside it is actually
accepting connections, and `up.sh`/`up.ps1` don't wait for that, only for the *microservice*
they start afterward to come up.

**Postgres holds metadata only** — who the providers are, which chunk went where, the
ledger. It never sees chunk contents; every shard lives on its own provider's local disk.
Only this machine needs Docker at all.

### 5.2 Coordinator

Always tear down the previous *coordinator* run first (this is separate from, and much more
frequent than, the Postgres container above) — skipping it is the single most common cause
of "database is being accessed by other users" or a hung port 8080 on the next attempt:

**macOS / Linux:**

```bash
scripts/demo/down.sh
scripts/demo/up.sh --providers 0 --advertise-host "$MY_IP"
```

**Windows (PowerShell 7):**

```powershell
.\scripts\demo\down.ps1
.\scripts\demo\up.ps1 -Providers 0 -AdvertiseHost $env:MyIp
```

**`--providers 0` / `-Providers 0`** — resets the database (see §5.1 — this happens inside
`up.sh`/`up.ps1` itself, every time, regardless of what you did with Docker), builds all
four binaries, starts the coordinator, and stops, leaving every provider slot for a real
volunteer machine.

**`--advertise-host` / `-AdvertiseHost` is new for this run, and matters.** Without it the
script tries to guess which of your network adapters is the right one to advertise — and on
a machine that's joined a mesh *and* still has ordinary Wi-Fi active (every machine here),
that guess has no principled way to prefer the mesh adapter, and is exactly as likely to
print your Wi-Fi address as your mesh one. Pass your own mesh IP from §3 explicitly and this
is never a question.

Save what it prints — **the admin key and OTP log path exist only on this machine.**

> Running everything on **one machine** instead, as a rehearsal? Use `--providers 7` (or
> `-Providers 7`) and skip §6 — the script onboards seven local providers itself. Note that
> a same-machine rehearsal doesn't need the mesh at all; everything else in this guide still
> applies unchanged.

### 5.3 Share the coordinator address

Tell your volunteers `$MSURL` now — `http://<your mesh IP>:8080` — so they can start §5 of
their own guide while you continue.

---

## 6. The console

In its own window, left running. This is the one place this guide shows the env file's
actual variable names (`$MICROSERVICE_URL`/`$ADMIN_API_KEY`) instead of the `$MSURL`/`$KEY`
shorthand used elsewhere — same values either way:

**macOS / Linux:**

```bash
source /tmp/vyomanaut-demo/env
"$BIN_DIR/operator" watch --mode=demo --microservice-url="$MICROSERVICE_URL" --admin-api-key="$ADMIN_API_KEY"
```

**Windows (PowerShell 7):**

```powershell
. $env:TEMP\vyomanaut-demo\env.ps1
& "$env:BIN_DIR\operator.exe" watch --mode=demo --microservice-url=$env:MICROSERVICE_URL --admin-api-key=$env:ADMIN_API_KEY
```

**`--mode=demo` is not optional.** Without it every threshold on screen is computed against
production values and every number looks wrong while the system underneath is fine.

Press `?` for the legend, `1`–`7` to focus a panel, arrows or `j`/`k` to scroll, `q` to quit.
Things that look wrong but aren't: scores swinging by tens of points (demo compresses a
24-hour scoring window into a couple of minutes); audit timeouts at 15–25% early on (many
challenges against few machines); `operator audit` returning `PENDING` (that command writes
the row, a background loop does the actual dispatch); a large provider holding zero chunks
(placement spreads across ASNs, not by declared capacity).

**Watch the Readiness gate panel until every provider is `ACTIVE` and it reads `READY`.**
Expect **10–12 minutes** after the last machine joins — uploads genuinely require five
`ACTIVE` providers, not merely five registered, and the console's own countdown is accurate.

Two panels worth knowing before anyone asks:

- **Escrow & release** — charged, released, and **held** (accrued but not yet released).
  Charged above zero with released still zero is the hold window working, not a stalled
  payout. `unavailable` means one refresh failed and will retry — not a zero balance.
- **ASN diversity** — each provider gets its own synthetic ASN (ADR-088), so the per-ASN
  cap is enforced but never has to reject anything in this demo profile. In production these
  come from real routing data and the cap does real work; the `?` legend says this on
  screen.

---

## 7. Providers join

Give each volunteer your coordinator address and a phone number to use
(`+919790000001`, `+919790000002`, …). They run `join.sh` / `join.ps1` per their guide,
passing **their own** mesh address as `--advertise-addr` / `-AdvertiseAddr`.

When one asks for their code, in a terminal on your machine:

**macOS / Linux:**

```bash
source /tmp/vyomanaut-demo/env
"$BIN_DIR/operator" otp --mode=demo --otp-delivery-log="$OTP_LOG" "+91<phone>"
```

**Windows (PowerShell 7):**

```powershell
. $env:TEMP\vyomanaut-demo\env.ps1
& "$env:BIN_DIR\operator.exe" otp --mode=demo --otp-delivery-log=$env:OTP_LOG +91<phone>
```

**Flags before the phone number, always.** The flag parser stops at the first non-flag
argument — put the number first and every flag after it is silently ignored. On Windows,
note the leading `. ` (dot, space) when loading `env.ps1` — PowerShell's equivalent of
`source`.

**Bring volunteers up one at a time**, confirming each appears on the console before
starting the next.

---

## 8. The owner: upload and retrieve

On the owner's machine (same as the operator's, or separate — §1).

**macOS / Linux:**
```bash
MSURL="http://<your mesh IP>:8080"
OWNER_DIR="$HOME/.vyomanaut-owner"
```
**Windows (PowerShell 7):**
```powershell
$MSURL = "http://<your mesh IP>:8080"
$env:OWNER_DIR = "$env:USERPROFILE\.vyomanaut-owner"
```

**Register** — writes down the 24-word mnemonic shown once:

```bash
client register --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR
```

**Fund and check:**

```bash
client deposit --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR --amount-paise=1000000
client balance --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR
```

**Upload** — use a **plain text file** (`README.md` from the repo is ideal):

```bash
client upload --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR README.md
```

Save the file ID it prints.

> **Why text, not video.** The confidentiality demo compares the entropy of the original
> against the encrypted chunks. Plain text measures ~4.9 bits/byte against ~7.999 on disk —
> a visible gap. A compressed video already measures ~7.995, so the comparison shows almost
> no difference. Upload a video too if you like, but make the entropy argument with text.

**See what happened:**
```
client ls       --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR
operator shards --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY <file_id>
```
`client ls` is the owner's view — names, sizes, cost. `operator shards` is the operator's:
chunk IDs, providers, ASNs, and the filename as **unreadable ciphertext**, labelled as such.
Showing these side by side is the most direct way to make the trust boundary concrete.

**Retrieve and prove it:**
```
client retrieve --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR -o out.md <file_id>
```
**macOS / Linux:** `cmp README.md out.md && echo IDENTICAL`
**Windows:** `fc README.md out.md` → *"FC: no differences encountered"* is the sentence the
whole project exists to earn.

---

## 9. Killing a machine

The best part of the demo — since ADR-088, **any** provider can be stopped. There's no
longer a correct one to choose.

**Abruptly (recommended):** close its terminal, or have that volunteer close the laptop lid.
No graceful shutdown, no warning to the network.

**Politely:** that volunteer runs `provider depart` (their guide, §8).

The coordinator starts with a 180-second departure threshold (raised from an original 90s
after Stage 3's first real run — see ADR-089's addendum: over a real internet path rather
than a LAN, two consecutive stalled heartbeat attempts could plausibly approach 90s on
their own, which risked a live, connected provider being wrongly marked departed), so
expect detection within about three minutes, not instantly. Watch the Repair panel go from `queued: 0` to a departure-triggered job and then
complete. Confirm where the rebuilt shard landed:
```
operator shards --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY <file_id>
```
Then retrieve again, with that machine still dead, and compare — **byte-identical with a
machine physically off** is the durability claim demonstrated rather than asserted.

Have the departed volunteer run `provider inspect` (their guide, §7) while offline — their
disk still holds encrypted chunks, useless in isolation. Two claims in one moment.

**Rejoining:** rerun `join`. It keeps its original identity from the encrypted keystore.

---

## 10. Deleting a file, and watching it leave the providers' disks

```
client rm --mode=demo --microservice-url=$MSURL --data-dir=$OWNER_DIR <file_id>
```

The coordinator marks every shard of that file for erasure and, on its next delivery cycle
(under a minute on this profile), instructs each holding provider to delete it over the same
authenticated channel used for vetting cleanup.

To show it rather than assert it: pick a provider that holds a shard (`operator shards`
before deleting), have them stop their daemon and run `provider inspect --hex` to note the
chunk count, restart the daemon, run `client rm` yourself, wait a cycle, then have them stop
and re-inspect. The chunks are gone and `used:` has dropped.

Be straight about the two limits: it's **asynchronous** (an offline provider keeps its
shards until reachable again, retried automatically), and it's a **storage-engine delete**,
not a forensic disk wipe. `client ls` stops listing the file immediately, and charges stop
accruing on the next billing tick.

---

## 11. Money

```
provider earnings --microservice-url=$MSURL --data-dir=<dir>    # on a provider
operator payout   --mode=demo --microservice-url=$MSURL --admin-api-key=$KEY
```
Charges accrue on a timer — run these a few minutes after upload, not immediately. The
payout table reconciles exactly, remainder tracked rather than dropped. The demo storage
rate is deliberately high (₹1000/GB/month) so the numbers read clearly on screen; production
pricing is a separate, unset decision.

---

## 12. Collecting metrics (Prometheus + Grafana) — optional

**Start the stack**, a separate compose file from Postgres so tearing down the demo doesn't
delete collected metrics:
```
docker compose -f deployments/observability/docker-compose.yml up -d
```
Grafana at `http://localhost:3000` (admin/admin), Prometheus at `http://localhost:9090`.

**Two things must be switched on, both off by default for good reason** — both endpoints are
unauthenticated:
1. Each provider starts with `--metrics-addr=<their mesh IP>:9091` — never `0.0.0.0` (their
   guide, §10).
2. The coordinator starts with `--expose-metrics` (or `VYOMANAUT_EXPOSE_METRICS=1`), serving
   `GET /metrics` on port 8080.

Then edit `deployments/observability/prometheus.yml` so the target list matches your actual
mesh addresses, and restart the Prometheus container.

**What you get:** provider-side audit latency, storage-append latency, chunks stored,
content-hash failures, heartbeats, RAM pressure; coordinator-side repair queue depth, repair
completions, audit challenges/results, provider scores, escrow events, DB read latency — the
coordinator series are what LTS research actually needs. **No dashboards ship with this** —
building them against invented metric names would be guesswork; explore in Grafana against
your first real run and save what proves useful.

---

## 13. Shutting down

```
scripts/demo/down.sh          # macOS/Linux
.\scripts\demo\down.ps1       # Windows
docker compose -f deployments/dev/docker-compose.yml down -v
```
Providers stop with Ctrl-C in their own windows — `down` only ever touches processes this
machine started.

**Always run `down` before starting a new run.** Skipping it is the single most common cause
of a failed restart — orphaned processes hold port 8080 and open database connections.

### Cleaning up between runs — full checklist

`down` handles this machine's own processes and any local rehearsal fleet. It does **not**
touch machines that joined themselves, or the owner's keys.

**On your machine (coordinator):**
```
scripts/demo/down.sh                                                  # or down.ps1
docker compose -f deployments/dev/docker-compose.yml down -v
rm -rf /tmp/vyomanaut-demo                                             # or Remove-Item -Recurse -Force $env:TEMP\vyomanaut-demo
```
`down -v` on the compose file is what actually discards the database volume.

**On the owner's machine** (if separate): delete its data directory — this destroys the
identity keystore, so old file IDs and the mnemonic are gone for good; don't do this while
you still want a previous run's uploads.

**On every provider machine** — each volunteer does this themselves (their guide, §11).
Skipping it is a real trap: the daemon finds its old registration and rejoins pointing at a
coordinator that no longer exists, and just never appears on the new console.

**Keep your metrics** — don't run `down -v` on the observability compose file unless you
actually want to discard collected data; that's the point of it being separate.

---

## 14. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `database is being accessed by other users` | Orphans from a previous run | `down` first, always |
| `microservice never became reachable` | Port 8080 still held | Same |
| The URL `up.sh`/`up.ps1` prints is `127.0.0.1` | No `--advertise-host` / `-AdvertiseHost` passed, and autodetection guessed the wrong adapter | §5.2 — always pass your mesh IP explicitly |
| Provider registered, nothing connects | Wrong advertised address, or Wi-Fi power saving idled their adapter | Their guide §2 and §4; have them pass their mesh IP explicitly |
| A provider likely was never touched but nobody remembers connecting it | Not stale — `up.sh`/`up.ps1` fully reset the database on every run (§5.1), so anything on the console is from *this* run. It's your own earlier attempt on that machine | Check its phone number against who's actually joined; harmless to leave, or `down` + restart for a clean console |
| A provider registers (`PENDING_ONBOARDING` appears) but never becomes `ACTIVE`, eventually `DEPARTED` | Its `provider run` started without `--mode=demo` — defaults to PROD's 4-hour heartbeat interval against a coordinator enforcing demo's ~30-second one; a real bug found and fixed on `join.ps1` during Stage 3's first run (was already fixed on `join.sh` from an earlier session — the two had silently diverged) | Confirm your `join.sh`/`join.ps1` is current; re-`join` that machine |
| Every signed request rejected | Clock skew > 2 minutes on some machine | Resync that machine's clock |
| `NETWORK_NOT_READY` on upload | Fewer than five `ACTIVE` providers | Wait — the countdown is accurate |
| `INSUFFICIENT_PROVIDER_CAPACITY` | Registered but still `VETTING` | Different, stricter gate — also just wait |
| Every number on the console looks wrong | `--mode=demo` missing | Add it |
| OTP command prints usage instead of a code | Phone number placed before the flags | Flags first |
| A provider looks like it departed but nobody touched it | Sleep or Wi-Fi power saving on that machine | Their guide §4 — both must stay off all session |
| Firewall popups during tests or on first run | Expected | **Allow** |

**Be plain, if it comes up:** this demo runs over a mesh overlay network handling the
machine-to-machine NAT traversal Vyomanaut's own networking doesn't do yet — see ADR-089 in
the research repository for the full reasoning and what was ruled out.
