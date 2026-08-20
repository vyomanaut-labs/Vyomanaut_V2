// cmd/operator is the network operator's CLI (ADR-084 D-1: consistent with
// the existing role-named binaries client/provider/microservice — the
// operator is the fourth role in Vyomanaut's own threat model). Global
// flags on every subcommand: --microservice-url (required by the
// subcommands that call the admin API), --admin-api-key (falls back to
// VYOMANAUT_ADMIN_API_KEY if unset — the flag always wins over the
// environment variable when both are given, mirroring cmd/client's own
// --mode precedence, MVP §5.3), --mode, --json.
//
// I-DEMO-1 (ADR-084 §D-2a), enforced structurally, not just asserted: this
// package has no import path, direct or transitive, to any decoding
// primitive (internal/crypto/aont, internal/erasure,
// internal/client/retrieve, internal/client/upload), and no database
// access of any kind (database/sql, github.com/lib/pq). Every fact this
// binary displays arrives over the admin HTTP API — see client.go. cmd/ is
// wiring only (IC §11): dispatch.go routes subcommands; shards.go and
// otp.go hold this session's thin per-subcommand orchestration. watch.go
// (Session 17.6.2) and audit.go/payout.go (Session 17.6.3) land later —
// their subcommand names are already routed in dispatch.go, to a real,
// disclosed placeholder rather than an unrecognised-subcommand error.
//
// [REF: ADR-084 D-1, D-2a; build_M17E.md Phase 17.6 Session 17.6.1; IC §11]
package main

import "os"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
