// Subcommand dispatch for cmd/client, over the eight MVP §8.3 names.
// cmd/ is wiring only (IC §11): this file parses flags and routes to the
// per-subcommand functions in account_cmds.go/transfer_cmds.go/
// manage_cmds.go (the latter two land in Sessions 17.1.2/17.1.3) — no
// testable behaviour lives here.
//
// [REF: MVP §8.3, MVP §5.3 (--mode flag precedence over VYOMANAUT_MODE)]
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// knownSubcommands is MVP §8.3's eight-name table, in that section's own
// order.
var knownSubcommands = []string{"register", "recover", "upload", "retrieve", "ls", "rm", "balance", "deposit"}

// globalFlags are MVP §8.3's four cmd/client-wide flags, common to every
// subcommand.
type globalFlags struct {
	mode            string
	microserviceURL string
	dataDir         string
	json            bool
}

// addGlobalFlags registers MVP §8.3's global flags on fs. --mode falls
// back to the VYOMANAUT_MODE environment variable when unset — the flag
// always wins when both are present (MVP §5.3); config.SelectProfile
// implements that precedence, this is just the flag's own description
// saying so accurately.
func addGlobalFlags(fs *flag.FlagSet, g *globalFlags) {
	fs.StringVar(&g.mode, "mode", "", "'demo' or 'prod'. Falls back to VYOMANAUT_MODE if unset; this flag always wins over the environment variable when both are given (MVP §5.3).")
	fs.StringVar(&g.microserviceURL, "microservice-url", "", "Required. HTTPS base URL of the coordination microservice.")
	home, _ := os.UserHomeDir()
	fs.StringVar(&g.dataDir, "data-dir", filepath.Join(home, ".vyomanaut"), "Persistent data directory.")
	fs.BoolVar(&g.json, "json", false, "Emit machine-readable JSON on stdout instead of human-readable text.")
}

var errMicroserviceURLRequired = fmt.Errorf("--microservice-url is required")

// exitUsage is the conventional Unix CLI exit code for a usage error (bad
// flags, missing subcommand) — the same value Go's own flag package uses
// internally for flag.ExitOnError. exitUsage is the only cmd/client exit
// code that needed a name: 0 and 1 are mnd's own default-ignored numbers,
// and every "return 1" in this package already reads unambiguously as
// "runtime failure" at its call site.
const exitUsage = 2

func validateGlobalFlags(g globalFlags) error {
	if g.microserviceURL == "" {
		return errMicroserviceURLRequired
	}
	return nil
}

// fprint/fprintln/fprintf wrap the fmt.Fprint family for errOut/out, the
// two io.Writers every dispatchX function in this package writes to (in
// the live binary, os.Stdout/os.Stderr; in tests, a bytes.Buffer — see
// transfer_cmds.go's own header note). Neither stream realistically fails
// to write in this CLI's operating envelope, and cmd/ is wiring only (IC
// §11) with no meaningful recovery path for a broken output stream anyway
// — centralising the discard here means every call site states that
// judgment once, not at each of this package's ~80 print calls. Any call
// site that DOES need the write error (see promptLine below) keeps calling
// fmt.Fprint directly instead.
func fprintln(w io.Writer, a ...any) {
	_, _ = fmt.Fprintln(w, a...)
}

func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func printUsage(errOut io.Writer) {
	fprintln(errOut, "usage: cmd/client <subcommand> [flags]")
	fprintln(errOut, "subcommands:")
	for _, name := range knownSubcommands {
		fprintf(errOut, "  %s\n", name)
	}
	fprintln(errOut, "global flags (accepted by every subcommand): --mode --microservice-url --data-dir --json")
}

// run is main's entire logic, factored out so it's testable without
// exercising os.Exit/os.Args directly — main() is a two-line wrapper
// around this.
func run(args []string, stdin io.Reader, out, errOut io.Writer) int {
	if len(args) < 1 {
		printUsage(errOut)
		return exitUsage
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "register":
		return dispatchRegister(rest, stdin, out, errOut)
	case "recover":
		return dispatchRecover(rest, stdin, out, errOut)
	case "upload":
		return dispatchUpload(rest, stdin, out, errOut)
	case "retrieve":
		return dispatchRetrieve(rest, stdin, out, errOut)
	case "ls":
		return dispatchLs(rest, stdin, out, errOut)
	case "rm":
		return dispatchRm(rest, stdin, out, errOut)
	case "balance":
		return dispatchBalance(rest, stdin, out, errOut)
	case "deposit":
		return dispatchDeposit(rest, stdin, out, errOut)
	default:
		printUsage(errOut)
		return exitUsage
	}
}
