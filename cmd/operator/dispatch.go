// Subcommand dispatch for cmd/operator, over the five ADR-084 §D-1 names.
// cmd/ is wiring only (IC §11): this file parses the shared global flags
// and routes to each subcommand's own file — no testable behaviour lives
// here beyond routing itself (dispatch_test.go).
//
// [REF: ADR-084 D-1; build_M17E.md Phase 17.6 Session 17.6.1]
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// knownSubcommands is ADR-084 §D-1's five-name table, in that section's own
// order (watch, shards, otp, audit, payout).
var knownSubcommands = []string{"watch", "shards", "otp", "audit", "payout"}

// globalFlags are the four flags every subcommand accepts (Session 17.6.1
// TASK item 1). Not every subcommand needs every field to be non-empty —
// `otp` never talks to the admin API at all, for instance — but the flag
// surface itself is uniform, so a wrapper script or shell alias can pass
// the same four flags to any subcommand without it being rejected as
// unknown.
type globalFlags struct {
	microserviceURL string
	adminAPIKey     string
	mode            string
	json            bool
}

// addGlobalFlags registers the four global flags on fs. --admin-api-key
// falls back to VYOMANAUT_ADMIN_API_KEY when unset — the flag always wins
// when both are present, the same precedence MVP §5.3 establishes for
// cmd/client's --mode; resolveAdminAPIKey below implements it. Callers that
// require it non-empty should call resolveAdminAPIKey after fs.Parse.
func addGlobalFlags(fs *flag.FlagSet, g *globalFlags) {
	fs.StringVar(&g.microserviceURL, "microservice-url", "", "HTTPS base URL of the coordination microservice.")
	fs.StringVar(&g.adminAPIKey, "admin-api-key", "", "Admin API key (X-Admin-API-Key header). Falls back to VYOMANAUT_ADMIN_API_KEY if unset; this flag always wins over the environment variable when both are given.")
	fs.StringVar(&g.mode, "mode", "", "'demo' or 'prod'. Falls back to VYOMANAUT_MODE if unset.")
	fs.BoolVar(&g.json, "json", false, "Emit machine-readable JSON on stdout instead of human-readable text.")
}

// resolveAdminAPIKey applies the flag-wins-over-env precedence described on
// globalFlags.adminAPIKey above.
func resolveAdminAPIKey(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("VYOMANAUT_ADMIN_API_KEY")
}

// exitUsage is the conventional Unix CLI exit code for a usage error,
// matching cmd/client's and cmd/provider's own constant of the same name
// and value.
const exitUsage = 2

var errMicroserviceURLRequired = fmt.Errorf("--microservice-url is required")
var errAdminAPIKeyRequired = fmt.Errorf("--admin-api-key is required (or set VYOMANAUT_ADMIN_API_KEY)")

// validateGlobalFlags checks the two fields a call against the admin API
// actually needs. Subcommands that never call the admin API (`otp`) do not
// call this — see otp.go's own flag handling.
func validateGlobalFlags(g globalFlags) error {
	if g.microserviceURL == "" {
		return errMicroserviceURLRequired
	}
	if g.adminAPIKey == "" {
		return errAdminAPIKeyRequired
	}
	return nil
}

// fprint/fprintln/fprintf wrap the fmt.Fprint family, matching cmd/client's
// and cmd/provider's own identical helpers — this CLI's operating envelope
// has no meaningful recovery path for a broken output stream either (IC
// §11: cmd/ is wiring only).
func fprintln(w io.Writer, a ...any) {
	_, _ = fmt.Fprintln(w, a...)
}

func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func printUsage(errOut io.Writer) {
	fprintln(errOut, "usage: operator <subcommand> [flags]")
	fprintln(errOut, "subcommands:")
	for _, name := range knownSubcommands {
		fprintf(errOut, "  %s\n", name)
	}
	fprintln(errOut, "global flags (accepted by every subcommand): --microservice-url --admin-api-key --mode --json")
}

// run is main's entire logic, factored out so it's testable without
// exercising os.Exit/os.Args directly — the same shape as cmd/client's own
// run(args, stdin, out, errOut), minus stdin: no subcommand this package
// builds prompts for interactive input.
func run(args []string, out, errOut io.Writer) int {
	if len(args) < 1 {
		printUsage(errOut)
		return exitUsage
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "shards":
		return dispatchShards(rest, out, errOut)
	case "otp":
		return dispatchOtp(rest, out, errOut)
	case "watch":
		// M17-E Session 17.6.2: watch.go now implements this for real —
		// see that file's own header. Necessary one-line edit to this
		// file's own switch statement: it is not in Session 17.6.2's
		// FILES list, but leaving this arm pointed at the placeholder
		// would make that whole session's deliverable unreachable from
		// the CLI (flagged in that session's own report).
		return dispatchWatch(rest, out, errOut)
	case "audit":
		return notYetImplemented(errOut, "audit", "17.6.3")
	case "payout":
		return notYetImplemented(errOut, "payout", "17.6.3")
	default:
		printUsage(errOut)
		return exitUsage
	}
}

// notYetImplemented is the placeholder for subcommand names ADR-084 §D-1
// commits to but this session's own FILES list does not build — the same
// honest-placeholder judgment router.go's stub501 already establishes for
// not-yet-built server endpoints, applied here to not-yet-built CLI
// subcommands instead of a route that silently doesn't exist.
func notYetImplemented(errOut io.Writer, name, session string) int {
	fprintf(errOut, "vyomanaut operator %s: not yet implemented (Session %s)\n", name, session)
	return 1
}
