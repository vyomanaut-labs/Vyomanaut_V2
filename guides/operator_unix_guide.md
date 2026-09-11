# Operator & Data Owner Guide — macOS

Two roles live in this guide. They can be one Mac or two.

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

```bash
brew --version
git --version
go version
docker --version
psql --version
```

> Expect go1.26.2
> Homebrew — if absent:
> `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
> Go — <https://go.dev/dl/>, install `go1.26.2.darwin-arm64.pkg`
> Docker — <https://www.docker.com/products/docker-desktop/>, then launch it once
> psql client — `brew install libpq` then follow the path hint it prints

Then RocksDB:

```bash
brew install snappy lz4 zstd
```

> Then follow `runbooks/macos.md` to build RocksDB into `~/rocksdb`

### 1.2 For the data owner

Much shorter. No Docker, no Postgres, no RocksDB.

```bash
git --version
go version
```

> Expect go1.26.2
> That is genuinely all. The owner's tool is a plain program that talks to the coordinator
> over the network.

### 1.3 Both

Turn off sleep for the duration:

> System Settings → Lock Screen → set display and sleep to **Never**

---

## Part 2 — The private network

Every machine talks over one private virtual network — a ZeroTier network. You own it, so
you set it up first, before sending anyone their guide.

### 2.1 Create it

> Sign in at <https://my.zerotier.com/> (a free account is enough) and click
> **Create A Network**
> Copy the 16-character **network ID** it generates — e.g. `b103a835d24e3e5f`. That string
> is the *only* thing you send teammates. No invite links, no email, no accounts for them.
> Leave the network set to **Private** (the default) so you control who joins.

### 2.2 Install and register your own machine

```bash
brew install --cask zerotier-one
sudo zerotier-cli join <network-id>
```

> Then authorize yourself: Central → **Members**, tick the checkbox next to your own device
> — yes, even the operator needs this. Then:

```bash
zerotier-cli listnetworks
```

> Expect an address starting with `10.` — write it down, this is your coordinator address.
> The pattern changed from `100.` to `10.`, the role hasn't.

### 2.3 Authorize each machine the moment it asks

There's no equivalent of a pre-generated auth key to hand out in advance — instead, every
teammate who runs `zerotier-cli join <network-id>` shows up in Central's **Members** list as
**unauthorized** (grey, unticked). Nothing works for them until you tick that box.

The good news: this replaces the old "campus Wi-Fi blocks the login page" problem entirely.
Joining a ZeroTier network never opens a browser on the teammate's end — the only browser
step in this whole flow is you, ticking checkboxes in Central. What campus firewalls *can*
still block is the raw UDP ZeroTier prefers; when that happens the teammate's
`zerotier-cli info` will show `TUNNELED` instead of `ONLINE` — that's an automatic TCP
fallback, not a failure, and needs nothing from you.

### 2.4 Check who has actually joined

> Central → **Members**

You should see every teammate's machine listed, **Authorized**, with a `10.` address before
you start. If someone is missing or still shows unauthorized, fix that before going further
— nothing else will work for them.

---

## Part 3 — Every command you will use

### Operator

```bash
# ── set once per terminal ────────────────────────────────────────────────
export NETWORK_ID="b103a835d24e3e5f"   # your ZeroTier network ID
export MY_IP="$(sudo zerotier-cli listnetworks | grep "$NETWORK_ID" | awk '{print $NF}' | cut -d'/' -f1)"

export CGO_CFLAGS="-I$HOME/rocksdb/include"
export CGO_LDFLAGS="-L$HOME/rocksdb/lib -L$(brew --prefix)/lib -L$(brew --prefix snappy)/lib \
  -Wl,-rpath,$HOME/rocksdb/lib -Wl,-rpath,$(brew --prefix)/lib -Wl,-rpath,$(brew --prefix snappy)/lib \
  -lrocksdb -lstdc++ -lm -lz -lbz2 -lsnappy -llz4 -lzstd"
export DYLD_LIBRARY_PATH="$HOME/rocksdb/lib:$(brew --prefix)/lib:$(brew --prefix snappy)/lib:$DYLD_LIBRARY_PATH"

# ── start and stop the network ───────────────────────────────────────────
docker compose -f deployments/dev/docker-compose.yml up -d postgres
scripts/demo/down.sh
scripts/demo/up.sh --providers 0 --advertise-host "$MY_IP"

# ── load this run's values into any new terminal ─────────────────────────
source /tmp/vyomanaut-demo/env

# ── the live console ─────────────────────────────────────────────────────
"$BIN_DIR/operator" watch --mode=demo --microservice-url="$MICROSERVICE_URL" --admin-api-key="$ADMIN_API_KEY"

# ── read a teammate's join code (flags BEFORE the phone number) ──────────
"$BIN_DIR/operator" otp --mode=demo --otp-delivery-log="$OTP_LOG" "+919790000001"

# ── inspect the network ──────────────────────────────────────────────────
"$BIN_DIR/operator" shards --mode=demo --microservice-url="$MICROSERVICE_URL" --admin-api-key="$ADMIN_API_KEY" "<file_id>"
"$BIN_DIR/operator" audit  --mode=demo --microservice-url="$MICROSERVICE_URL" --admin-api-key="$ADMIN_API_KEY" "<provider_id>" "<chunk_id>"
"$BIN_DIR/operator" payout --mode=demo --microservice-url="$MICROSERVICE_URL" --admin-api-key="$ADMIN_API_KEY"
```

### Data owner

```bash
# ── set once per terminal ────────────────────────────────────────────────
export MSURL="http://10.35.114.52:8080"   # the operator's address
export OWNER_DIR="$HOME/.vyomanaut-owner"

# ── identity and money ───────────────────────────────────────────────────
"$BIN_DIR/client" register --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR"
"$BIN_DIR/client" recover  --mode=demo --microservice-url="$MSURL" --data-dir="$NEWDEVICE_DIR" --phone="+919790000001"   # new device: prompts for the OTP code, then the passphrase
"$BIN_DIR/client" recover  --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR" --mnemonic="<24 words>"       # only if the passphrase itself is lost
"$BIN_DIR/client" deposit  --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR" --amount-paise=1000000
"$BIN_DIR/client" balance  --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR"

# ── files ────────────────────────────────────────────────────────────────
"$BIN_DIR/client" upload   --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR" "<path>"
"$BIN_DIR/client" upload   --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR" --resume "<file_id>"
"$BIN_DIR/client" ls       --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR"
"$BIN_DIR/client" retrieve --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR" -o "<out>" "<file_id>"
"$BIN_DIR/client" rm       --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR" "<file_id>"
```

> `--mode=demo` on every single call. Without it the numbers on screen are computed against
> a different rulebook and everything looks broken while the system underneath is fine.

---

## Part 4 — Starting the network

### 4.1 Get the code and set your flags

**First Time here?**
Clone the code if starting fresh:

```pwsh

# Only for first time people
cd ~
git clone https://github.com/vyomanaut-labs/Vyomanaut_V2.git
```

**Already cloned?** Just `cd ~\Vyomanaut_V2` and pull the latest:

```pwsh
cd ~
cd .\Vyomanaut_V2\
git pull
```

The CGO flags necessary for RocksDB:

```bash
export CGO_CFLAGS="-I$HOME/rocksdb/include"
export CGO_LDFLAGS="-L$HOME/rocksdb/lib -L$(brew --prefix)/lib -L$(brew --prefix snappy)/lib \
  -Wl,-rpath,$HOME/rocksdb/lib -Wl,-rpath,$(brew --prefix)/lib -Wl,-rpath,$(brew --prefix snappy)/lib \
  -lrocksdb -lstdc++ -lm -lz -lbz2 -lsnappy -llz4 -lzstd"
export DYLD_LIBRARY_PATH="$HOME/rocksdb/lib:$(brew --prefix)/lib:$(brew --prefix snappy)/lib:$DYLD_LIBRARY_PATH"
```

Then check it builds:

```bash
go vet ./...
go build ./...
```

> `ld: warning: duplicate -rpath` lines are normal noise from those flags. Ignore them.

### 4.2 Start Postgres — once, and leave it running

```bash
docker compose -f deployments/dev/docker-compose.yml down -v
docker compose -f deployments/dev/docker-compose.yml up -d postgres
```

> The database holds only bookkeeping — who the machines are, which piece went where, the
> ledger. It never sees the contents of anything.

### 4.3 Start the coordinator

Set the environment for ZeroTier:

```bash
export NETWORK_ID="b103a835d24e3e5f"   # your ZeroTier network ID
export MY_IP="$(sudo zerotier-cli listnetworks | grep "$NETWORK_ID" | awk '{print $NF}' | cut -d'/' -f1)"
echo "$MY_IP"
```

> **Always run `down.sh` first.** Leftover processes from a previous attempt holding the
> port are the most common cause of a failed restart.

```bash
scripts/demo/down.sh
rm -rf /tmp/vyomanaut-demo
```

Establish the network:

```pwsh
scripts/demo/up.sh --providers 0 --advertise-host "$MY_IP"
```

> `--providers 0` means the coordinator starts alone, leaving every slot free for a real
> machine to join. `--advertise-host` is what the others will dial — pass it explicitly,
> always. Without it the script guesses which network card to publish, and on a machine
> running ZeroTier alongside ordinary Wi-Fi that guess is a coin flip.

Save what it prints. **The admin key exists only on this machine and only for this run.**

Sanity check the output before continuing:

```bash
[up.sh] MICROSERVICE_URL = http://10.35.114.52:8080
```

> It must be your `10.x` ZeroTier address, not `127.0.0.1`.
> You should see **no** "onboarding local provider" lines at all with `--providers 0`.

### 4.4 Give everyone the address

Tell your teammates:

```bash
http://<your 10.x ZeroTier address>:8080
```

They can now start Part 4 of their own guide.

### 4.5 Open the console

New terminal for the TUI:

```bash
source /tmp/vyomanaut-demo/env
"$BIN_DIR/operator" watch --mode=demo --microservice-url="$MICROSERVICE_URL" --admin-api-key="$ADMIN_API_KEY"
```

Leave it running. `?` for the legend, `1`–`7` to focus a panel, arrows or `j`/`k` to scroll,
`q` to quit.

Now if someone fails to send the ping then:

```bash
ping 10.35.114.<number>
```

ping him back - this helps the peer detect itself back to the operator and becomes alive

Use it also when a provider skips a heartbeat.

---

## Part 5 — Bringing machines in

Bring them in **one at a time**, confirming each appears before starting the next.

When a teammate asks for their code, in another terminal:

```bash
source /tmp/vyomanaut-demo/env
"$BIN_DIR/operator" otp --mode=demo --otp-delivery-log="$OTP_LOG" "+919790000001"
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

```bash
export MSURL="http://10.35.114.52:8080"    # the operator's real address
export OWNER_DIR="$HOME/.vyomanaut-owner"
```

> The owner needs the `client` binary. Easiest: copy `/tmp/vyomanaut-demo/bin/client` from
> the operator's machine, or clone the repo and run `go build -o client ./cmd/client/`
> (no RocksDB flags needed for this one).

### 6.2 Register

Clear the previous data owner registration details

```bash
rm -r ~/.vyomanaut-owner
```

Then register fresh:

```bash
"$BIN_DIR/client" register --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR"
```

> **Write down the 24 words it shows.** They appear once. They are the only way back into
> this identity.
>
> **Also note the phone number you give it.** 6.7 needs it to prove the file comes back on
> a different device — it's easy to forget since nothing prints it back at you here.

### 6.3 Add funds and check

```bash
"$BIN_DIR/client" deposit --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR" --amount-paise=1000000
"$BIN_DIR/client" balance --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR"
```

### 6.4 Upload

Use a **plain text file**. `README.md` from the repo works well.

```bash
"$BIN_DIR/client" upload --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR" README.md
```

Save the file ID it prints.

> Why text: the point you are demonstrating is that the stored pieces look like noise. Text
> scores about 4.9 on the randomness scale and the stored pieces score about 7.999 — a
> visible gap. A video is already near 7.995 before you start, so the comparison shows
> nothing.

### 6.5 Show the two views side by side

Owner's view:

```bash
"$BIN_DIR/client" ls --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR"
```

Operator's view:

```bash
"$BIN_DIR/operator" shards --mode=demo --microservice-url="$MICROSERVICE_URL" --admin-api-key="$ADMIN_API_KEY" "<file_id>"
```

The owner sees names, sizes, cost. The operator sees piece IDs, which machine holds what,
and the filename as unreadable ciphertext. Putting these next to each other is the clearest
way to show where the trust boundary sits.

### 6.6 Get it back

```bash
"$BIN_DIR/client" retrieve --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR" -o out.md "<file_id>"
cmp README.md out.md && echo IDENTICAL
```

### 6.7 Get it back from a different device

This is the actual claim worth demonstrating, not 6.6: the file comes back on a machine
that has never seen this account before, using nothing but the phone number and the
passphrase from 6.2. No copied files, no shared keystore.

> Use a genuinely separate machine if you have a spare one for this. If not, a fresh
> `--data-dir` on the same machine is not a simplification — it behaves exactly like a
> new device, since every credential this needs lives on the server or in your head, not
> in that directory.

```bash
export NEWDEVICE_DIR="$HOME/.vyomanaut-newdevice"   # or the second machine's own path
"$BIN_DIR/client" recover --mode=demo --microservice-url="$MSURL" --data-dir="$NEWDEVICE_DIR" --phone="<the phone number used at 6.2>"
```

It sends an OTP and asks for the code — look it up the same way as Part 5, `operator otp`. Then
it asks for the passphrase chosen at 6.2. Neither needs to be typed as a flag; both are
prompted.

```bash
"$BIN_DIR/client" ls       --mode=demo --microservice-url="$MSURL" --data-dir="$NEWDEVICE_DIR"
"$BIN_DIR/client" retrieve --mode=demo --microservice-url="$MSURL" --data-dir="$NEWDEVICE_DIR" -o out2.md "<file_id>"
cmp README.md out2.md && echo IDENTICAL
```

> `recover` tells you plainly what this device can and cannot do once it finishes: `ls`,
> `retrieve`, `rm`, `balance`, and `deposit` all work from here. `upload` does not — a new
> file needs the original device's signing key, and there is no way in this system to issue
> a replacement one for an existing account. If the passphrase itself is lost too, not just
> the device, `--mnemonic="<24 words>"` on this same `recover` call is the only way back in.

---

## Part 7 — Killing a machine

Any machine can be stopped. There is no wrong one to pick.

**Abruptly** — have that teammate close their terminal or shut the lid.
**Politely** — have them run `provider depart` from their own guide.

Expect the network to notice within about three minutes. Watch the **Repair** panel go from
`queued: 0` to a job, then complete. Then check where the rebuilt piece landed:

```bash
"$BIN_DIR/operator" shards --mode=demo --microservice-url="$MICROSERVICE_URL" --admin-api-key="$ADMIN_API_KEY" "<file_id>"
```

Then retrieve the file again, with that machine still off, and compare. **Byte-identical
with a machine physically dead** is the whole claim, demonstrated rather than asserted.

While they are off, have them run `provider inspect` — their disk still holds encrypted
pieces, useless on their own. Two points in one moment.

---

## Part 8 — Deleting a file

```bash
"$BIN_DIR/client" rm --mode=demo --microservice-url="$MSURL" --data-dir="$OWNER_DIR" "<file_id>"
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

```bash
scripts/demo/down.sh
```

Teammates stop their own machines with Ctrl-C in their own windows — `down.sh` only touches
processes this machine started.

Between runs, on your machine:

```bash
scripts/demo/down.sh
rm -rf /tmp/vyomanaut-demo
```

> **Tell every teammate to delete their data folder too** before rejoining. Their guide
> covers it. This is the single most common cause of a machine failing to rejoin after you
> restart — the start script rebuilds the network from scratch, and their old membership is
> no longer recognised.

---

## Part 10 — When something goes wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `database is being accessed by other users` | Leftover processes from the last attempt | `down.sh` first, always |
| `microservice never became reachable` | Port 8080 still held | Same |
| The printed URL is `127.0.0.1` | `--advertise-host` not passed, autodetect picked the wrong card | 4.3 — pass your `10.x` ZeroTier address |
| "onboarding local provider" appears despite `--providers 0` | Old copy of the start script | `git pull` and try again |
| A teammate registers, then goes DEPARTED with `401 invalid token` on their side | They kept a data folder from before you restarted | They delete it and rejoin — their guide, Part 4 |
| A teammate is never asked for a code | Same cause | Same fix |
| Every number on the console looks wrong | `--mode=demo` missing | Add it |
| OTP prints usage instead of a code | Phone number placed before the flags | Flags first |
| `NETWORK_NOT_READY` on upload | Fewer than five machines at `ACTIVE` | Wait — the countdown is accurate |
| `INSUFFICIENT_PROVIDER_CAPACITY` | Machines registered but still in probation | Also just wait |
| A machine looks like it left but nobody touched it | That machine went to sleep | Their guide, sleep settings |
| `upload` refuses on a device that just ran `recover --phone` | Expected, not a bug — that device has no local keystore (6.7) | Upload from the original device, or a device that started as a copy of it |
| A provider's repair-download or vetting-gc requests get rejected | That provider's clock is off by more than two minutes (`NetworkProfile.AuthRequestFreshnessWindow`, ADR-036) | Have them resync their clock — their guide's own troubleshooting section |
| A provider's heartbeats get rejected with `400: "timestamp skew exceeds 5 minutes"`, and they eventually go `DEPARTED` without ever leaving | Same root cause, different (looser) threshold — heartbeat's own check is a separate, hardcoded 5 minutes (`internal/api/provider.go: heartbeatTimestampSkew`), not the 2-minute `AuthRequestFreshnessWindow` above | Their guide's own troubleshooting section — usually campus/lab Wi-Fi blocking outbound NTP |
| `rocksdb/c.h file not found` | Build flags not set in this terminal | 4.1 |
| A teammate is stuck at `REQUESTING_CONFIGURATION` / `ACCESS_DENIED` | You haven't ticked their checkbox in Central yet | Members tab — authorize them, they don't need to do anything |
| Two authorized machines never see each other in `zerotier-cli peers` | Both stuck relaying, or one daemon isn't actually running | Check `zerotier-cli info` on both — `TUNNELED` is fine, `OFFLINE` means restart that machine's service |
| `$MY_IP` comes back empty | `NETWORK_ID` doesn't match, or you're not authorized on your own network | Recheck 2.2 — `zerotier-cli listnetworks` should show `OK`, not blank |

> This demo runs over a private mesh network that handles the machine-to-machine
> connectivity for us. If anyone asks: the connectivity layer is ZeroTier's, the storage,
> repair, auditing and payment logic on top of it is ours.
