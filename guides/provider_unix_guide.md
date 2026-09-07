# Provider Guide — macOS

You are lending a Mac to the Vyomanaut demo network. Your machine stores encrypted pieces of
someone else's file and proves, on demand, that it still has them.

You need two things from the operator. Ask for them when you get there:

- the **coordinator address** — looks like `http://100.126.233.20:8080`
- a **6-digit code** — only the first time you join

> Your machine never sees a filename and never holds a readable copy of anything. What it
> stores looks like random noise, because it is.

---

## Part 1 — Setting up macOS

Do this once. Skip anything you already have.

### 1.1 Homebrew

```bash
brew --version
```

> If absent:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

> Follow the "Next steps" it prints at the end — on Apple Silicon it asks you to add
> Homebrew to your path. Do that, then open a new terminal.

### 1.2 Git

```bash
git --version
```

> macOS offers to install the developer tools if it's missing. Accept.

### 1.3 Go

```bash
go version
```

> Expect go1.26.2
> If absent, visit <https://go.dev/dl/> and install `go1.26.2.darwin-arm64.pkg`
> (or `darwin-amd64` on an Intel Mac)
> Open a new terminal afterwards

### 1.4 RocksDB

The storage engine on macOS needs this. Build it per `runbooks/macos.md` in the repository,
then keep the flags below handy — you need them in **every** terminal you build in.

```bash
brew install snappy lz4 zstd
```

> Then follow `runbooks/macos.md` to build RocksDB into `~/rocksdb`

### 1.5 Turn off sleep

> System Settings → Lock Screen → set the display and sleep options to **Never** while the
> demo is running

A machine that dozes off looks exactly like a machine that left the network. That matters
later, when leaving is something we test on purpose.

> You do **not** need Docker or a Postgres server. Those are the operator's job.

---

## Part 2 — Joining the private network

Every machine in this demo talks over one private network called a tailnet. Join it before
anything else, or nothing will connect.

### 2.1 Accept the invite

> The operator sends you a join link
> Open it, sign in, accept

### 2.2 Install Tailscale

```bash
brew install --cask tailscale
```

> Or download from <https://tailscale.com/download/mac>

### 2.3 Log in and register this machine

```bash
tailscale up
```

> A browser window opens. Sign in with the same account you accepted the invite on.
> Your machine now appears on the operator's device list.

### 2.4 Get your address

```bash
tailscale ip -4
```

> Expect something starting with `100.`
> **Write it down.** This is the single most important value in this guide.

### 2.5 If your network blocks the login

Common on college, office and hotel Wi-Fi.

```bash
tailscale status
```

- **The browser page won't load at all** — ask the operator for an auth key instead. They
  generate one from their admin console. Then:

  ```bash
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

All of these run from the `Vyomanaut_V2` folder. Set the values at the top first —
everything else refers to them.

```bash
# ── set once per terminal ────────────────────────────────────────────────
export MY_IP="100.105.176.94"               # yours, from `tailscale ip -4`
export MSURL="http://100.126.233.20:8080"   # the operator's, ask them

# ── RocksDB build flags, also once per terminal ──────────────────────────
export CGO_CFLAGS="-I$HOME/rocksdb/include"
export CGO_LDFLAGS="-L$HOME/rocksdb/lib -L$(brew --prefix)/lib -L$(brew --prefix snappy)/lib \
  -Wl,-rpath,$HOME/rocksdb/lib -Wl,-rpath,$(brew --prefix)/lib -Wl,-rpath,$(brew --prefix snappy)/lib \
  -lrocksdb -lstdc++ -lm -lz -lbz2 -lsnappy -llz4 -lzstd"
export DYLD_LIBRARY_PATH="$HOME/rocksdb/lib:$(brew --prefix)/lib:$(brew --prefix snappy)/lib:$DYLD_LIBRARY_PATH"

# ── join the network (this is the main one) ──────────────────────────────
scripts/demo/join.sh "$MSURL" --listen-port 30303 --advertise-addr "$MY_IP" --data-dir ~/.vyomanaut

# ── look at what you are storing (stop the daemon first) ─────────────────
.vyomanaut-bin/provider inspect --data-dir=~/.vyomanaut --hex
.vyomanaut-bin/provider inspect --data-dir=~/.vyomanaut --chunk <chunk_id>
.vyomanaut-bin/provider inspect --data-dir=~/.vyomanaut --hex --compare="<original file>"

# ── what you have earned ─────────────────────────────────────────────────
.vyomanaut-bin/provider earnings --microservice-url="$MSURL" --data-dir=~/.vyomanaut

# ── leave politely (tells the network first) ─────────────────────────────
.vyomanaut-bin/provider depart --microservice-url="$MSURL" --data-dir=~/.vyomanaut

# ── start over as a brand new machine ────────────────────────────────────
rm -rf ~/.vyomanaut
```

---

## Part 4 — Running it

Open a terminal. Work through this in order.

### 4.1 Get the code

```bash
cd ~
git clone https://github.com/vyomanaut-labs/Vyomanaut_V2.git
cd Vyomanaut_V2
```

> Already cloned? Just `cd ~/Vyomanaut_V2` and pull the latest:

```bash
git pull
```

### 4.2 Set the RocksDB flags

```bash
export CGO_CFLAGS="-I$HOME/rocksdb/include"
export CGO_LDFLAGS="-L$HOME/rocksdb/lib -L$(brew --prefix)/lib -L$(brew --prefix snappy)/lib \
  -Wl,-rpath,$HOME/rocksdb/lib -Wl,-rpath,$(brew --prefix)/lib -Wl,-rpath,$(brew --prefix snappy)/lib \
  -lrocksdb -lstdc++ -lm -lz -lbz2 -lsnappy -llz4 -lzstd"
export DYLD_LIBRARY_PATH="$HOME/rocksdb/lib:$(brew --prefix)/lib:$(brew --prefix snappy)/lib:$DYLD_LIBRARY_PATH"
```

> These do not survive closing the terminal. Set them again in any new one.

### 4.3 Check it builds

```bash
go vet ./...
go build ./...
```

> Both should finish quietly. Some `ld: warning: duplicate -rpath` and
> `ignoring duplicate libraries` lines are normal and harmless — they come from the flags
> above, not from a problem.

### 4.4 Set your two values

```bash
export MY_IP="$(tailscale ip -4)"
export MSURL="http://100.126.233.20:8080"   # the operator's real address
echo "$MY_IP"
```

> Check `$MY_IP` printed a `100.` address before continuing.

### 4.5 Fresh start check — do not skip this

**If the operator has restarted the coordinator since you last joined, delete your data
folder first:**

```bash
rm -rf ~/.vyomanaut
```

> Why: when the operator restarts, the network is rebuilt from scratch and your old
> membership is no longer recognised. Keeping the old folder makes the join script skip the
> code step and the daemon then gets rejected on every heartbeat with `401 invalid token`.
> Deleting the folder is the fix. When in doubt, delete it.

### 4.6 Join

```bash
scripts/demo/join.sh "$MSURL" --listen-port 30303 --advertise-addr "$MY_IP" --data-dir ~/.vyomanaut
```

The first run builds the provider, which takes a minute or two. Then it asks you three
things:

1. **Your phone number**, like `+919790000001` — the operator tells you which one to use
2. **How much storage to share, in GB** — enter **10** unless told otherwise
3. **A 6-digit code** — this is when you ask the operator. They read it off their screen.

Then the daemon starts and stays in the foreground.

**Leave this window open.** Closing it or pressing Ctrl-C takes your machine off the network.

### 4.7 Check the right things happened

You should see, in order:

```
[STARTUP][single] Peer ID: 12D3Koo...
[STARTUP][single] advertising 100.105.176.94:30303 to the network
[STARTUP][single] Vyomanaut provider daemon ready
```

> **Check the advertised address matches your own `100.` address.** If it doesn't, stop and
> tell the operator.

Then tell the operator you are up. They will confirm you appeared on their screen.

### 4.8 Nothing happens for about ten minutes

That is correct. New machines go through a probation period — the network stores test
pieces on your disk and challenges you to prove you still have them. Five successful proofs
and at least five minutes, then you are promoted.

You do not need to do anything during this time.

---

## Part 5 — Things you might be asked to do

### Look inside your own storage

The storage is locked while the daemon runs, so stop it first with Ctrl-C, then:

```bash
.vyomanaut-bin/provider inspect --data-dir=~/.vyomanaut --hex
```

You will see chunks of identical size and a hex dump whose text column is nothing but dots.
The "entropy" figure will read about **7.999** out of a maximum of 8.0 — meaning it is
statistically indistinguishable from random noise. Ordinary English text measures about 4.9.

Restart the daemon afterwards with the same join command. It remembers who you are.

### Leave on purpose

Politely, so the network can move your data first:

```bash
.vyomanaut-bin/provider depart --microservice-url="$MSURL" --data-dir=~/.vyomanaut
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
| `401` / `invalid token`, repeating | Your saved membership is from an older run of the network | 4.5 — delete the data folder and join again |
| Join script never asks for a phone number or code | Same cause: you still have an old data folder | 4.5 |
| `rocksdb/c.h file not found` | RocksDB flags not set in this terminal | 4.2 |
| `ld: warning: duplicate -rpath` | Harmless noise from the flags | Ignore it |
| `tailscale ip -4` prints nothing | Not on the tailnet yet | Part 2 — stop and tell the operator |
| `bind: address already in use` | A provider is already running here | Close the other window, or use `--listen-port 30304` |
| Registered, but the operator sees nothing connect | Usually the wrong advertised address | Recheck 4.4 and 4.7 — pass your `100.` address explicitly |
| `connection refused` to the coordinator | Coordinator down or wrong address | Recheck your `$MSURL`, then ask |
| Operator mentions `NETWORK_NOT_READY` | Not your problem — not enough machines yet | Wait |
| You look like you left, but you didn't touch anything | The machine went to sleep | 1.5 |

If you are stuck, send the operator: your Peer ID, your `100.` address, and the last five
lines of your terminal.
