// Tests for dispatch.go (M17-E Session 17.6.1).
//
// Tests:
//   - TestUnknownSubcommandExitsUsage
//   - TestNoArgsPrintsUsage
//   - TestNotYetBuiltSubcommandsReturnHonestPlaceholder
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

// TestNotYetBuiltSubcommandsReturnHonestPlaceholder confirms watch/audit/
// payout — named in ADR-084 §D-1 but not built until Sessions 17.6.2/
// 17.6.3 — are routed to a real, disclosed placeholder rather than falling
// through to the unknown-subcommand branch (which would look identical to
// a typo, not a not-yet-built feature).
func TestNotYetBuiltSubcommandsReturnHonestPlaceholder(t *testing.T) {
	for _, sub := range []string{"watch", "audit", "payout"} {
		t.Run(sub, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run([]string{sub}, &out, &errOut)
			if code == exitUsage {
				t.Errorf("run([%s]) exit code = %d (usage error), want a distinct not-yet-implemented code", sub, code)
			}
			if !strings.Contains(errOut.String(), "not yet implemented") {
				t.Errorf("run([%s]) stderr = %q, want it to say not yet implemented", sub, errOut.String())
			}
		})
	}
}

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
