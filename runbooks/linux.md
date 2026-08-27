# Runbook — Linux

**Status: unverified draft.** Written by translating the macOS runbook (tested, green)
to Linux's equivalents; not yet run end-to-end on the Ubuntu 26.04 VM. Report every
divergence from this document back so it can be corrected against reality rather than
trusted on faith. Versions referenced below are pinned in
[`scripts/versions.env`](../scripts/versions.env).

**The one thing most likely to trip you up:** your distro's packaged RocksDB is almost
certainly too old. Confirmed directly against Ubuntu 24.04's `librocksdb-dev` (8.9.1):
it fails to build against `grocksdb` with `could not determine what C.rocksdb_slice_t
refers to` — that C API type doesn't exist yet in 8.9.1. This repo needs RocksDB
10.10.1 specifically (`internal/storage/doc.go`'s own documented pin) — §2 below builds
it from source rather than relying on apt.

## 1. Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git ca-certificates \
  postgresql-client \
  libsnappy-dev liblz4-dev libzstd-dev zlib1g-dev libbz2-dev
```

- Go, matching `GO_VERSION` exactly. Ubuntu's own `apt` package is very likely to be
  the wrong version — install via the [official tarball](https://go.dev/dl/) instead:
  ```bash
  curl -LO https://go.dev/dl/go$(grep GO_VERSION scripts/versions.env | cut -d= -f2).linux-amd64.tar.gz
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go*.linux-amd64.tar.gz
  # add /usr/local/go/bin to PATH in your shell profile
  go version   # confirm it reports the pinned version
  ```
- Docker (Engine, not necessarily Desktop) — for the Postgres container only. If using
  plain Docker Engine rather than Docker Desktop, make sure your user is in the
  `docker` group (`sudo usermod -aG docker $USER`, then re-login) so `docker compose`
  doesn't need `sudo`.
- `golangci-lint`, matching `GOLANGCI_LINT_VERSION`:
  ```bash
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b $(go env GOPATH)/bin $(grep GOLANGCI_LINT_VERSION scripts/versions.env | cut -d= -f2)
  golangci-lint version   # confirm it matches the pin
  ```

## 2. RocksDB (one-time, until `ROCKSDB_VERSION` changes)

Build from source at the exact pinned tag — this is the same recipe
`deployments/docker/Dockerfile.ci` already uses and CI already trusts, so replicating
it locally keeps your machine's RocksDB identical to the one CI tests against:

```bash
git clone --depth 1 --branch v$(grep ROCKSDB_VERSION scripts/versions.env | cut -d= -f2) \
  https://github.com/facebook/rocksdb.git ~/rocksdb-src
cd ~/rocksdb-src
mkdir build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DROCKSDB_BUILD_SHARED=OFF \
  -DWITH_TESTS=OFF -DWITH_GFLAGS=OFF -DWITH_BENCHMARK_TOOLS=OFF -DWITH_TOOLS=OFF \
  -DWITH_MD_LIBRARY=OFF -DWITH_RUNTIME_DEBUG=OFF \
  -DWITH_SNAPPY=ON -DWITH_LZ4=ON -DWITH_ZLIB=ON -DWITH_LIBURING=OFF -DWITH_ZSTD=ON -DWITH_BZ2=OFF \
  -DPORTABLE=1 \
  -DCMAKE_INSTALL_PREFIX="$HOME/rocksdb"
cmake --build . -j"$(nproc)"
cmake --install .
```

**Alternative, if you'd rather not build RocksDB by hand:** the project's own CI image,
`ghcr.io/masamasaowl/vyomanaut-ci:rocksdb-10.10.1-pgclient1`, already has RocksDB
10.10.1 built and `CGO_CFLAGS`/`CGO_LDFLAGS` set correctly (see
`deployments/docker/Dockerfile.ci`). Running the whole test suite inside that container
(mounting the repo, `docker run --rm -it -v "$PWD":/repo -w /repo <image> bash`) sidesteps
§2 and most of §3 entirely — this is a genuine shortcut, not a lesser-tested path, since
CI itself runs inside this exact image today. The Design Council session that considered
Docker for this project rejected it for *running the demo* (provider processes must be
native, per the multi-host requirements) but never objected to using it for *build
environment* portability — this is exactly that second, uncontroversial use.

## 3. Per-session setup

**Step 0 — clear orphaned processes:**
```bash
pkill -x microservice 2>/dev/null
pkill -x provider 2>/dev/null
sleep 1
```

**Step 1 — fresh Postgres:**
```bash
docker compose -f deployments/dev/docker-compose.yml down -v
docker compose -f deployments/dev/docker-compose.yml up -d postgres
```

**Step 2 — schema + roles + environment:**
```bash
PGPASSWORD=devpass psql -h localhost -U vyomanaut_migrator -d vyomanaut_dev \
  -c "CREATE DATABASE vyomanaut_test OWNER vyomanaut_migrator;"

go run migrations/generator.go --profile=demo > /tmp/demo_schema.sql

PGPASSWORD=devpass psql -h localhost -U vyomanaut_migrator -d vyomanaut_test \
  -v ON_ERROR_STOP=1 -f /tmp/demo_schema.sql

PGPASSWORD=devpass psql -h localhost -U vyomanaut_migrator -d vyomanaut_test -c \
  "ALTER ROLE vyomanaut_app WITH LOGIN PASSWORD 'testpass';
   ALTER ROLE vyomanaut_gc WITH LOGIN PASSWORD 'testpass';"

export PGHOST=localhost PGPORT=5432 PGDATABASE=vyomanaut_test PGSSLMODE=disable
export PGUSER=vyomanaut_app PGPASSWORD=testpass
export PGMIGRATORUSER=vyomanaut_migrator PGMIGRATORPASSWORD=devpass

export CGO_CFLAGS="-I$HOME/rocksdb/include"
export CGO_LDFLAGS="-L$HOME/rocksdb/lib -lrocksdb -lstdc++ -lm -lz -lbz2 -lsnappy -llz4 -lzstd -lpthread -ldl"
export LD_LIBRARY_PATH="$HOME/rocksdb/lib:$LD_LIBRARY_PATH"
```

Note the two differences from macOS: `LD_LIBRARY_PATH` (not `DYLD_LIBRARY_PATH`), and
no `-Wl,-rpath` / `brew --prefix` entries — this build links `-lstdc++` directly
against the system's own libstdc++ rather than a Homebrew-provided one, and
`LD_LIBRARY_PATH` alone is sufficient without also needing rpath entries baked into the
linked binary (unlike the macOS recipe, which sets both for robustness).

## 4. Whole-repo compile + unit tests

```bash
go vet ./...
go build ./...
golangci-lint run
go test -race -count=1 -p 1 ./...
```

`-race` needs `gcc`, already installed via `build-essential` in §1.

## 5. Integration package compile check

```bash
go build -tags integration ./scripts/test/...
go vet -tags integration ./scripts/test/...
```

## 6. The integration suite

Identical commands to the macOS runbook §6 — copy that section verbatim; nothing in the
`go test` invocations themselves is platform-specific, only the environment that
precedes them (§3 above) differs.

## 7. Linux-specific notes

- `internal/storage/engine_rocksdb.go` carries `//go:build linux || darwin` — Linux
  uses the same RocksDB-backed storage engine as macOS, unlike Windows (BadgerDB, see
  the Windows runbook). This is also why Linux needs the full §2 RocksDB build and
  Windows does not.
- `build_part3.md`'s own standing risks note that `engine_badger.go` "cannot be
  exercised on Linux" — this is expected and by design (build-tag-gated to Windows
  only), not a gap to chase on this platform.
- If `go vet`/`go build` fails with a cgo error mentioning a missing or mismatched
  symbol from `librocksdb`, check `ldconfig -p | grep rocksdb` for a stray
  distro-packaged copy shadowing your `$HOME/rocksdb` build, and confirm
  `CGO_CFLAGS`/`CGO_LDFLAGS`/`LD_LIBRARY_PATH` from §3 are actually exported in your
  current shell (a new terminal tab loses them).
