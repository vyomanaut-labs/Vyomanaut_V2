// Package main — `operator watch` (M17-E Session 17.6.2, ADR-084 §D-2).
//
// The subcommand entry point: parses the shared global flags, then either
// runs the interactive Bubble Tea console (alternate screen, resize
// handling, q to quit — task item 1) or, with --json, performs exactly one
// fetch cycle and prints the resulting watchSnapshot to stdout before
// exiting (task item 5) — no terminal, no Program, no alternate screen,
// so this path is itself script- and test-friendly.
//
// [REF: ADR-084 D-2; build_M17E.md Phase 17.6 Session 17.6.2]
package main

import (
	"encoding/json"
	"flag"
	"io"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

func dispatchWatch(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("operator watch", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	g.adminAPIKey = resolveAdminAPIKey(g.adminAPIKey)
	if err := validateGlobalFlags(g); err != nil {
		fprintln(errOut, err)
		return exitUsage
	}

	profile := config.SelectProfile(g.mode)
	client := newAdminClient(g.microserviceURL, g.adminAPIKey)

	// --json: one snapshot, then exit — task item 5's own wording, so
	// Session 17.8.2 can assert on the console's view without a terminal.
	if g.json {
		return runWatchJSONSnapshot(client, out, errOut)
	}

	program := tea.NewProgram(newWatchModel(client, profile), tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		fprintf(errOut, "vyomanaut operator watch: %v\n", err)
		return 1
	}
	return 0
}

// runWatchJSONSnapshot performs the exact same fan-out fetch the
// interactive console's first tick would (fetchCmd, model.go) but calls it
// directly and synchronously — there is no running tea.Program here to
// dispatch a fetchResultMsg into, so this reads the tea.Cmd's own return
// value instead of going through Update at all.
func runWatchJSONSnapshot(client *adminClient, out, errOut io.Writer) int {
	result := fetchCmd(client)()
	msg, ok := result.(fetchResultMsg)
	if !ok {
		fprintln(errOut, "vyomanaut operator watch: internal error: unexpected fetch result type")
		return 1
	}

	snap := watchSnapshot{
		Timestamp:     msg.at,
		Readiness:     msg.readiness,
		Providers:     msg.providers,
		RepairQueue:   msg.repairQueue,
		AuditStats:    msg.auditStats,
		VettingStatus: msg.vettingStatus,
		FetchErrors:   msg.errs,
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		fprintf(errOut, "vyomanaut operator watch: %v\n", err)
		return 1
	}
	return 0
}
