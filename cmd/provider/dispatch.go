// Package main — command dispatch (M17-E Session 17.4.1, ADR-084 D-1, D-7).
//
// cmd/provider grew a fourth requirement this session that main.go's single
// flag.Parse()-then-run shape could not satisfy: a person volunteering a
// desktop (requirement 2) needs an onboarding flow the daemon itself does
// not yet have, and the local-storage-inspection / earnings / graceful-
// departure surfaces (requirements 5, 10, 7) are separate concerns from the
// daemon loop too. This file is ONLY the router between five subcommand
// names and their handlers — IC §11's "cmd/ is wiring only" applies to this
// file exactly as much as it does to main.go.
//
// BACKWARD COMPATIBILITY, NON-NEGOTIABLE: every existing invocation of this
// binary — scripts/test/demo_timeline_test.go's own exec.Command chief
// among them — passes bare flags with NO subcommand name
// ("provider --mode=demo --sim-count=7 ..."). resolveSubcommand below must
// keep treating that shape, and the zero-argument shape, as "run" forever;
// this is asserted directly by TestBareFlagInvocationDispatchesToRun and
// TestNoArgsDispatchesToRun (dispatch_test.go), and by this session's own
// NO_REGRESSION VERIFY step re-running TestDemoTimeline unmodified.
//
// [REF: ADR-084 D-1, D-7; build_M17E.md Phase 17.4 Session 17.4.1; IC §11]
package main

import (
	"fmt"
	"io"
	"os"
)

// The five subcommand names (MVP §8.3, as amended — Session 17.8.3).
// Declared once, here, as the SOLE quoted literal for each — dispatch's own
// switch and resolveSubcommand's fallback both reference these constants,
// never a second inline string, so there is exactly one place that could
// ever misspell one of them.
const (
	subcommandOnboard  = "onboard"
	subcommandRun      = "run"
	subcommandInspect  = "inspect"
	subcommandEarnings = "earnings"
	subcommandDepart   = "depart"
)

func main() {
	cmd, rest := resolveSubcommand(os.Args[1:])
	os.Exit(dispatch(cmd, rest))
}

// resolveSubcommand decides which subcommand main() routes to, given the
// process argv tail (os.Args[1:], or an arbitrary slice in tests). Two
// cases fall through to "run" rather than being treated as an unknown
// subcommand name:
//
//   - no arguments at all
//   - the first argument looks like a flag (leads with '-'), meaning this
//     is the pre-Session-17.4.1 invocation shape: bare flags, no
//     subcommand word
//
// Anything else is read as a subcommand name, with the remaining arguments
// passed through unchanged as that subcommand's own argv.
func resolveSubcommand(args []string) (cmd string, rest []string) {
	if len(args) == 0 {
		return subcommandRun, nil
	}
	if len(args[0]) > 0 && args[0][0] == '-' {
		return subcommandRun, args
	}
	return args[0], args[1:]
}

// dispatch routes to the named subcommand's handler and returns the process
// exit code main() should use. Kept separate from main() itself so routing
// is directly testable without a subprocess
// (TestUnknownProviderSubcommandExitsTwo and friends call this directly).
func dispatch(cmd string, args []string) int {
	switch cmd {
	case subcommandRun:
		runCmd(args)
		return 0
	case subcommandOnboard:
		return onboardCmd(args)
	case subcommandDepart:
		return departCmd(args)
	case subcommandInspect:
		return inspectCmd(args)
	case subcommandEarnings:
		return earningsCmd(args)
	default:
		fmt.Fprintf(os.Stderr, "vyomanaut provider: unknown subcommand %q\n\n", cmd)
		printUsage(os.Stderr)
		return 2
	}
}

// printUsage writes the top-level usage line to w.
func printUsage(w io.Writer) {
	fmt.Fprintf(w, "usage: provider <%s|%s|%s|%s|%s> [flags]\n",
		subcommandOnboard, subcommandRun, subcommandInspect, subcommandEarnings, subcommandDepart)
}
