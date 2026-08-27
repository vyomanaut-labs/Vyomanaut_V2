// Tests for dispatch.go (M17-E Session 17.6.1).
//
// Tests:
//   - TestUnknownSubcommandExitsUsage
//   - TestNoArgsPrintsUsage
//   - TestAdminAPIKeyFlagWinsOverEnv
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnknownSubcommandExitsUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"bogus"}, &out, &errOut)
	if code != exitUsage {
		t.Fatalf("run([bogus]) exit code = %d, want %d", code, exitUsage)
	}
}

func TestNoArgsPrintsUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, &out, &errOut)
	if code != exitUsage {
		t.Fatalf("run(nil) exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "usage:") {
		t.Errorf("stderr does not contain usage text: %s", errOut.String())
	}
}

// TestNotYetBuiltSubcommandsReturnHonestPlaceholder is retired as of
// Session 17.6.3: "watch" left this list in Session 17.6.2, and "audit"/
// "payout" — this session's own deliverables — are real now (audit.go,
// payout.go) and get their own tests in audit_test.go/payout_test.go
// instead. Session 17.6.1's notYetImplemented helper remains in
// dispatch.go for ADR-084 §D-1 names not yet built by a future milestone,
// but no subcommand currently routes to it.

// TestAdminAPIKeyFlagWinsOverEnv confirms resolveAdminAPIKey's precedence
// (the flag always wins over VYOMANAUT_ADMIN_API_KEY when both are given)
// — the same precedence rule MVP §5.3 establishes for cmd/client's --mode.
func TestAdminAPIKeyFlagWinsOverEnv(t *testing.T) {
	t.Setenv("VYOMANAUT_ADMIN_API_KEY", "from-env")
	if got := resolveAdminAPIKey("from-flag"); got != "from-flag" {
		t.Errorf("resolveAdminAPIKey(%q) = %q, want %q (flag wins)", "from-flag", got, "from-flag")
	}
	if got := resolveAdminAPIKey(""); got != "from-env" {
		t.Errorf("resolveAdminAPIKey(\"\") = %q, want %q (env fallback)", got, "from-env")
	}
}
