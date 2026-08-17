// cmd/client is the data owner CLI (MVP §8.3): register, recover, upload,
// retrieve, ls, rm, balance, deposit. Global flags on every subcommand:
// --mode (falls back to VYOMANAUT_MODE if unset — the flag always wins
// over the environment variable when both are given, MVP §5.3),
// --microservice-url (required), --data-dir, --json.
//
// cmd/ is wiring only (IC §11) — dispatch.go routes subcommands,
// account_cmds.go/transfer_cmds.go/manage_cmds.go hold the thin
// per-subcommand orchestration, and every actual encode/decode/sign/
// derive call is delegated to internal/client/*.
package main

import "os"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
