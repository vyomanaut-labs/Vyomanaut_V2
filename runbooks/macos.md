# Runbook — macOS

**Status: tested, green.** This is the procedure Karma ran successfully before Session
17.6.3 began (M16 demo timeline, M17 CLI-binary-driven proof, and the high-risk
departure/repair/retrieval suite — see §5 below for the exact test list). Treat this
runbook as the reference; the Windows and Linux runbooks are unverified drafts to be
confirmed against this one as we go.

Versions referenced below are pinned in [`scripts/versions.env`](../scripts/versions.env)
— check that file if something here looks stale.

## 1. Prerequisites

- Xcode Command Line Tools (`xcode-select --install`) — provides `clang`, needed for
  CGO (RocksDB) and for `go test -race`.
- [Homebrew](https://brew.sh)
- Go, matching `GO_VERSION` in `scripts/versions.env` exactly:
  ```
  brew install go@1.26   # or your preferred Go version manager, pinned to the same version
  go version              # confirm it reports the pinned version before continuing
  ```
- Docker Desktop for Mac (for the Postgres container only — no application services run
  in Docker on this track; see the Design Council verdict on Docker in the M17-E
  session history for why).
- `psql` client: `brew install postgresql` (installs the client even if you don't run
  the server via Homebrew).
- `golangci-lint`, matching `GOLANGCI_LINT_VERSION`:
  ```
  brew install golangci-lint
  golangci-lint version   # confirm it matches the pin
  ```

## 2. RocksDB (one-time, until `ROCKSDB_VERSION` changes)

Homebrew's own `rocksdb` formula is **not** used — it does not reliably track the exact
version this repo requires. Build from source at the pinned tag instead:

```bash
git clone --depth 1 --branch v$(grep ROCKSDB_VERSION scripts/versions.env | cut -d= -f2) \
  https://github.com/facebook/rocksdb.git ~/rocksdb-src
cd ~/rocksdb-src
brew install snappy zstd lz4  # bzip2 and zlib ship with macOS already

mkdir build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DROCKSDB_BUILD_SHARED=OFF \
  -DWITH_TESTS=OFF -DWITH_GFLAGS=OFF -DWITH_BENCHMARK_TOOLS=OFF -DWITH_TOOLS=OFF \
  -DWITH_SNAPPY=ON -DWITH_LZ4=ON -DWITH_ZLIB=ON -DWITH_ZSTD=ON -DWITH_BZ2=OFF \
  -DPORTABLE=1 \
  -DCMAKE_INSTALL_PREFIX="$HOME/rocksdb"
cmake --build . -j"$(sysctl -n hw.ncpu)"
cmake --install .
```

This mirrors `deployments/docker/Dockerfile.ci`'s own build flags exactly, so what you
get locally matches what CI already trusts.

## 3. Per-session setup

**Step 0 — clear orphaned processes from an earlier, uncleanly-terminated run:**
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
export CGO_LDFLAGS="-L$HOME/rocksdb/lib -L$(brew --prefix)/lib -L$(brew --prefix snappy)/lib \
  -Wl,-rpath,$HOME/rocksdb/lib -Wl,-rpath,$(brew --prefix)/lib -Wl,-rpath,$(brew --prefix snappy)/lib \
  -lrocksdb -lstdc++ -lm -lz -lbz2 -lsnappy -llz4 -lzstd"
export DYLD_LIBRARY_PATH="$HOME/rocksdb/lib:$(brew --prefix)/lib:$(brew --prefix snappy)/lib:$DYLD_LIBRARY_PATH"
```

## 4. Whole-repo compile + unit tests

```bash
go vet ./...
go build ./...
golangci-lint run
go test -race -count=1 -p 1 ./...
```

`-race` needs a working C compiler — the Xcode CLT install in §1 covers this.

## 5. Integration package compile check

```bash
go build -tags integration ./scripts/test/...
go vet -tags integration ./scripts/test/...
```

## 6. The integration suite

Run in this order — later steps depend on earlier ones having exercised (and not
corrupted) shared fixtures/timing assumptions:

```bash
date
echo "STEP 5 — M16 DEMO TIMELINE + VIABILITY TESTS"
go test -tags integration -v -run '^TestDemoTimeline$' ./scripts/test/ -timeout 60m
date
go test -tags integration -v -run '^(TestViabilityASNCapMatchesRunningDemoProfile|TestViabilityRepairSucceedsWithTwoOfFiveOffline|TestViabilityActiveTransitionAtTenMinutes|TestViabilityDuplicateWebhookProducesExactlyOneEscrowRow)$' ./scripts/test/ -timeout 100m
date
go test -tags integration -v -run '^TestViabilityActiveTransitionAtTenMinutes$' ./scripts/test/ -timeout 28m
date

echo "STEP 6 — CLI-BINARY-DRIVEN PROOF (M17)"
go test -tags integration -v -run '^(TestDemoCLIFullLifecycle|TestDemoCLIRetrievedBytesIdenticalToUploaded|TestDemoCLIUploadFailsBeforeDeposit|TestDemoCLIReadinessReportsDemoMode)$' ./scripts/test/ -timeout 130m
date
go test -tags integration -v -run '^TestDepartureMidUploadLeavesNoHalfRegisteredFile$' ./scripts/test/ -timeout 40m
date
go test -tags integration -v -run '^TestReqD07FileRetrievableAfterProviderLossAndRepair$' ./scripts/test/ -timeout 40m
date
go test -tags integration -v -run '^TestDepartureAfterUploadFileStillRetrievable$' ./scripts/test/ -timeout 40m
date
go test -tags integration -v -run '^TestDepartureAfterUploadFileStillRetrievableGraceful$' ./scripts/test/ -timeout 40m
date

echo "STEP 7 — HIGH-RISK DEPARTURE / REPAIR / RETRIEVAL TESTS"
go test -tags integration -v -run '^TestReplacementProviderDepartsMidRepair$' ./scripts/test/ -timeout 45m
date
go test -tags integration -v -run '^TestDepartureMidRetrievalStillGathersK$' ./scripts/test/ -timeout 40m
date
go test -tags integration -v -run '^TestTwoConcurrentDeparturesAtEmergencyFloor$' ./scripts/test/ -timeout 50m
date
```

## 7. Known-good state

All of the above was green on Karma's Mac immediately before M17-E Session 17.6.3
began. If a fresh run of §4–§6 diverges from that, the divergence is the finding —
file it the same way F-17E-13 through F-17E-20 were filed, don't silently work around
it.

## 8. macOS-specific notes

- `DYLD_LIBRARY_PATH` is macOS's dynamic-linker search path — the Linux and Windows
  runbooks use different mechanisms entirely (`LD_LIBRARY_PATH`, and nothing at all on
  Windows respectively). Don't copy this block across platforms.
- Docker Desktop must be running before §3 Step 1; it does not autostart.
