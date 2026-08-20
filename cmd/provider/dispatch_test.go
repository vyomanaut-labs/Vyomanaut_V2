package main

import "testing"

// TestDispatchRouting is a thin wrapper so `go test -run TestDispatchRouting`
// matches every test below — same pattern main_test.go's TestProviderStartup
// and TestSimCount already use for the same reason (also independently
// runnable directly; nothing here is duplicated logic, just
// t.Run(name, existingTestFunc)).
func TestDispatchRouting(t *testing.T) {
	t.Run("TestBareFlagInvocationDispatchesToRun", TestBareFlagInvocationDispatchesToRun)
	t.Run("TestNoArgsDispatchesToRun", TestNoArgsDispatchesToRun)
	t.Run("TestUnknownProviderSubcommandExitsTwo", TestUnknownProviderSubcommandExitsTwo)
}

// TestBareFlagInvocationDispatchesToRun verifies the pre-Session-17.4.1
// invocation shape — flags with no subcommand word — still dispatches to
// "run" with every argument passed through unchanged. This is the exact
// shape scripts/test/demo_timeline_test.go's exec.Command uses
// ("--mode=demo", "--microservice-url=...", ...); breaking it breaks every
// integration test in the repository.
func TestBareFlagInvocationDispatchesToRun(t *testing.T) {
	args := []string{"--mode=demo", "--microservice-url=http://127.0.0.1:8080"}
	cmd, rest := resolveSubcommand(args)
	if cmd != subcommandRun {
		t.Fatalf("resolveSubcommand(%v) cmd = %q, want %q", args, cmd, subcommandRun)
	}
	if len(rest) != len(args) {
		t.Fatalf("resolveSubcommand(%v) rest = %v, want the original args unchanged", args, rest)
	}
	for i := range args {
		if rest[i] != args[i] {
			t.Fatalf("resolveSubcommand(%v) rest[%d] = %q, want %q", args, i, rest[i], args[i])
		}
	}
}

// TestNoArgsDispatchesToRun verifies zero arguments also dispatches to
// "run" — a bare `provider` invocation with no flags at all.
func TestNoArgsDispatchesToRun(t *testing.T) {
	cmd, rest := resolveSubcommand(nil)
	if cmd != subcommandRun {
		t.Fatalf("resolveSubcommand(nil) cmd = %q, want %q", cmd, subcommandRun)
	}
	if len(rest) != 0 {
		t.Fatalf("resolveSubcommand(nil) rest = %v, want empty", rest)
	}
}

// TestUnknownProviderSubcommandExitsTwo verifies an unrecognized subcommand
// name returns exit code 2 (conventional Go CLI usage-error code) rather
// than silently falling through to "run" or panicking.
func TestUnknownProviderSubcommandExitsTwo(t *testing.T) {
	got := dispatch("nonsense", nil)
	if got != 2 {
		t.Fatalf("dispatch(%q, nil) = %d, want 2", "nonsense", got)
	}
}
