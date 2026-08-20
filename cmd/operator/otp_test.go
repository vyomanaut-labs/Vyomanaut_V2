// Tests for otp.go (M17-E Session 17.6.1).
//
// Tests:
//   - TestOtpRefusesOutsideDemoMode
//   - TestOtpReturnsMostRecentCodeForPhone
//   - TestMostRecentCodeForPhoneSkipsMalformedLines
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeDeliveryLog writes lines (already-formatted log lines, no trailing
// newline needed per entry) to a fresh temp file and returns its path.
func writeDeliveryLog(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "otp-delivery.log")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write delivery log: %v", err)
	}
	return path
}

// TestOtpRefusesOutsideDemoMode confirms the same demo-mode-only gate
// cmd/microservice/main.go's own --otp-delivery-log flag enforces fatally
// at startup (ADR-084 §D-3) — a file-backed OTP gateway has no legitimate
// production use, and this command must refuse rather than silently work.
func TestOtpRefusesOutsideDemoMode(t *testing.T) {
	logPath := writeDeliveryLog(t, "2026-08-19T11:04:22Z  +919876500001  418362")

	var out, errOut bytes.Buffer
	code := dispatchOtp([]string{
		"--mode=prod",
		"--otp-delivery-log=" + logPath,
		"+919876500001",
	}, &out, &errOut)

	if code == 0 {
		t.Fatalf("dispatchOtp in --mode=prod: exit code = 0, want non-zero (refused). stdout = %s", out.String())
	}
	if !strings.Contains(errOut.String(), "demo mode") {
		t.Errorf("stderr does not mention demo mode: %s", errOut.String())
	}
	if out.String() != "" {
		t.Errorf("stdout = %q, want empty (no code should ever be printed outside demo mode)", out.String())
	}
}

// TestOtpReturnsMostRecentCodeForPhone writes a log with several entries —
// including two for the same phone number, oldest first, matching
// FileOtpSender's own append-only write order — and confirms the LAST
// (most recent) code for that phone is what's returned, not the first.
func TestOtpReturnsMostRecentCodeForPhone(t *testing.T) {
	logPath := writeDeliveryLog(t,
		"2026-08-19T11:00:00Z  +919876500002  111111", // different phone
		"2026-08-19T11:04:22Z  +919876500001  418362", // first code for our phone
		"2026-08-19T11:09:50Z  +919876500001  927104", // resend: the most recent one
	)

	var out, errOut bytes.Buffer
	code := dispatchOtp([]string{
		"--mode=demo",
		"--otp-delivery-log=" + logPath,
		"+919876500001",
	}, &out, &errOut)

	if code != 0 {
		t.Fatalf("dispatchOtp exit code = %d, want 0, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "927104") {
		t.Errorf("stdout = %q, want it to contain the most recent code 927104", out.String())
	}
	if strings.Contains(out.String(), "418362") {
		t.Errorf("stdout = %q, contains the STALE code 418362 — must return only the most recent", out.String())
	}
}

// TestMostRecentCodeForPhoneSkipsMalformedLines confirms a line that
// doesn't split into exactly otpLogFields fields (a foreign or corrupted
// line) is skipped rather than aborting the whole scan or being
// misinterpreted.
func TestMostRecentCodeForPhoneSkipsMalformedLines(t *testing.T) {
	logPath := writeDeliveryLog(t,
		"this line has way too many fields to be valid at all",
		"2026-08-19T11:04:22Z  +919876500001  418362",
	)

	code, sentAt, err := mostRecentCodeForPhone(logPath, "+919876500001")
	if err != nil {
		t.Fatalf("mostRecentCodeForPhone: %v", err)
	}
	if code != "418362" {
		t.Errorf("code = %q, want 418362", code)
	}
	if sentAt != "2026-08-19T11:04:22Z" {
		t.Errorf("sentAt = %q, want 2026-08-19T11:04:22Z", sentAt)
	}
}
