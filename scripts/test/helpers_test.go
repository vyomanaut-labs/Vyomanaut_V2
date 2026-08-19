//go:build integration

// Shared helpers for CLI-binary-driven tests (demo_cli_test.go). Everything
// in demo_timeline_test.go that spins up real infrastructure (liveDB,
// resetDemoDatabase, buildBinaries, startMicroservice, startProviders,
// pollAllProvidersActive, pollReadiness, recoverOTPCode) is reused
// unchanged — this file adds only what's new for driving the compiled
// cmd/client binary itself: building it, and two invocation styles
// (interactive, for register's live phone/OTP round-trip; non-interactive
// --json, for everything else).
//
// [REF: build.md M17 Session 17.2.1, ADR-064]
package test

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// buildClientBinary builds cmd/client, mirroring buildBinaries' own
// pattern exactly (same repo-root discovery, same t.TempDir() output
// location) rather than duplicating a second convention.
func buildClientBinary(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	repoRoot := findRepoRoot(t)
	clientPath := filepath.Join(binDir, "client")

	cmd := exec.Command("go", "build", "-o", clientPath, "./cmd/client/")
	cmd.Dir = repoRoot
	cmd.Env = os.Environ()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/client/: %v\n%s", err, output)
	}
	return clientPath
}

// cliPhoneNumber generates a random E.164-looking test phone number under
// a +9197 prefix — deliberately distinct from startProviders' +91987653
// prefix and registerOwner's own +9199 prefix (demo_timeline_test.go), so
// CLI-driven test owners can never collide with either.
func cliPhoneNumber(t *testing.T, suffix uint32) string {
	t.Helper()
	return fmt.Sprintf("+9197%08d", suffix%100_000_000)
}

func randSuffix(t *testing.T) uint32 {
	t.Helper()
	var b [4]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return binary.BigEndian.Uint32(b[:])
}

// ── non-interactive: everything except register's live OTP round-trip ────

// runClientJSON runs the compiled cmd/client binary once and returns its
// stdout/stderr, requiring --json among args so output is parseable
// (dispatch_test.go/account_cmds_test.go's own tests establish that
// convention; this helper just enforces it's actually present). Fails the
// test immediately on a non-zero exit unless wantErr is true (used by
// TestDemoCLIUploadFailsBeforeDeposit, which needs to inspect a failure).
func runClientJSON(t *testing.T, ctx context.Context, clientBin string, args []string, wantErr bool) (stdout, stderr string) {
	t.Helper()
	hasJSON := false
	for _, a := range args {
		if a == "--json" {
			hasJSON = true
		}
	}
	if !hasJSON {
		t.Fatalf("runClientJSON: args %v missing --json — every non-interactive assertion in this file parses JSON, never screen-scrapes", args)
	}

	cmd := exec.CommandContext(ctx, clientBin, args...)
	// Root-cause fix, not a workaround: config.SelectProfile defaults to
	// prod (internal/config/select.go's own deliberate, safe-by-default
	// behavior) whenever neither --mode nor VYOMANAUT_MODE is set — and
	// this file never set either, on any call site. That silently ran
	// every CLI invocation in this file against the prod profile (real
	// Argon2 cost, SkipMnemonicConfirm=false, ...), not demo. Setting it
	// here once, centrally, means no individual call site can forget it
	// again — the earlier alternative (adding --mode=demo to every
	// runClientJSON/startInteractiveClient call) fixes today's call
	// sites but not the next one someone adds.
	cmd.Env = append(os.Environ(), "VYOMANAUT_MODE=demo")
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stdout, stderr = outBuf.String(), errBuf.String()

	if wantErr && err == nil {
		t.Fatalf("cmd/client %v: expected a non-zero exit, got success\nstdout: %s\nstderr: %s", args, stdout, stderr)
	}
	if !wantErr && err != nil {
		t.Fatalf("cmd/client %v: %v\nstdout: %s\nstderr: %s", args, err, stdout, stderr)
	}
	return stdout, stderr
}

// lastJSONLine finds the last complete, standalone JSON value in stdout
// and decodes it into out.
//
// This is deliberately not "split on newlines, take the last non-empty
// one" (an earlier version of this function did exactly that, and a live
// TestDemoCLIFullLifecycle run caught why it's wrong): promptLine
// (account_cmds.go) correctly writes an interactive prompt's label with
// no trailing newline, so the cursor stays on the same line for a
// response — proper CLI behavior, not a bug. register's final --json
// payload is written right after its last prompt is answered, with
// nothing separating them on a newline basis, so "Enter the 6-digit
// code: " and the JSON object end up looking like one "line" to a
// newline-splitter. This instead scans backward for every '{' or '['
// (every plausible start of a JSON value — cmd/client's own JSON shapes
// are either top-level objects like registerOutput or top-level arrays
// like ls's []jsonEntry) and tries each from the end of the string
// forward, taking the first candidate that parses as one complete,
// self-contained JSON value with nothing trailing. That last condition
// is what makes this safe even if the payload itself contains nested
// objects: a candidate starting at an inner '{' would have unmatched
// trailing bytes left over (e.g. an extra '}') and fail to parse as a
// complete value on its own, so the search correctly continues past it
// to the real, outer start.
func lastJSONLine(t *testing.T, stdout string, out any) {
	t.Helper()
	trimmed := strings.TrimRight(stdout, "\n")

	var starts []int
	for i, r := range trimmed {
		if r == '{' || r == '[' {
			starts = append(starts, i)
		}
	}
	for i := len(starts) - 1; i >= 0; i-- {
		candidate := trimmed[starts[i]:]
		if !json.Valid([]byte(candidate)) {
			continue
		}
		if err := json.Unmarshal([]byte(candidate), out); err == nil {
			return
		}
		// Syntactically valid JSON, but doesn't match out's type (e.g. an
		// object found where an array-typed target was expected) — keep
		// searching earlier candidates instead of failing on the first
		// valid-but-wrong-shaped match.
	}
	t.Fatalf("no valid, complete JSON value found anywhere in stdout\nfull stdout:\n%s", stdout)
}

// pollOwnerBalancePositive repeatedly invokes the balance subcommand,
// returning as soon as balance_paise > 0 or once timeout has elapsed
// (returning whatever the last observed balance_paise was either way — it
// does not call t.Fatalf/t.Errorf itself, since a caller may still want to
// proceed to other assertions, e.g. rm, even if balance never went
// positive).
//
// [Added, M17 CLI debugging session, fourth pass] mv_owner_escrow_balance
// (DM §7) is refreshed on a background cadence
// (NetworkProfile.BackgroundViewRefreshInterval — see
// cmd/microservice/background_loops.go's runBackgroundViewRefreshLoop),
// not synchronously on deposit. A single balance check immediately after
// deposit genuinely raced that cadence live: a real run's microservice
// log showed InitiateEscrow's deposit and this test's own balance check
// landing within the same one-second window, one full refresh tick before
// the next scheduled 5s-interval tick could run — an inherent property of
// time.NewTicker firing on a fixed schedule from when it started, not
// re-triggered by the write that just happened. This was never a dead or
// broken refresh loop (a diagnostic pass instrumented every tick and
// confirmed 3/3 views refreshing successfully throughout, every run) —
// the bug was this test asserting synchronous consistency against a
// design that explicitly documents itself as eventually consistent
// (build_part2.md's owner-balance TASK text: "≤60s stale" in production).
// Polling here — instead of shrinking BackgroundViewRefreshInterval
// further — treats the actual documented contract as correct and fixes
// the test to match it, the same pattern this file's own
// pollReadiness/pollAllProvidersActive/pollGCDelivered/pollDeparted/
// pollRepairCompleted (demo_timeline_test.go) already established for
// every other eventually-consistent condition in this suite.
func pollOwnerBalancePositive(t *testing.T, ctx context.Context, clientBin, msBaseURL, dataDir string, timeout time.Duration) int64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastBalance int64
	for {
		stdout, _ := runClientJSON(t, ctx, clientBin, []string{
			"balance", "--microservice-url=" + msBaseURL, "--data-dir=" + dataDir, "--json",
			"--passphrase=" + cliTestPassphrase,
		}, false)
		var balanceResult struct {
			BalancePaise int64 `json:"balance_paise"`
		}
		lastJSONLine(t, stdout, &balanceResult)
		lastBalance = balanceResult.BalancePaise
		if lastBalance > 0 || time.Now().After(deadline) {
			return lastBalance
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestLastJSONLine is a regression test for a real bug a live
// TestDemoCLIFullLifecycle run caught: the original implementation split
// stdout on newlines and took the last non-empty line, which broke the
// moment a --json payload landed right after a no-trailing-newline prompt
// (register's actual, correct behavior) on what looked like one "line".
func TestLastJSONLine(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
	}{
		{
			name:   "JSON on its own line (the common case)",
			stdout: "2026/08/18 [STARTUP] ...\nOTP sent.\nEnter the 6-digit code: \n{\"owner_id\":\"abc\",\"registered\":true}\n",
		},
		{
			name: "JSON glued to a no-trailing-newline prompt — the live failure this test pins",
			stdout: "2026/08/18 [STARTUP] ...\n" +
				"OTP sent. In demo mode there is no real SMS integration — look up the 6-digit code from the otp_codes table.\n" +
				"Enter the 6-digit code: {\"owner_id\":\"ae843cf3-29b0-41f6-a51f-6f0e573765f3\",\"registered\":true}\n",
		},
		{
			name:   "trailing whitespace after the newline",
			stdout: "{\"owner_id\":\"abc\",\"registered\":true}\n  \n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var decoded struct {
				OwnerID    string `json:"owner_id"`
				Registered bool   `json:"registered"`
			}
			lastJSONLine(t, c.stdout, &decoded)
			if decoded.Registered != true || decoded.OwnerID == "" {
				t.Fatalf("decoded %+v from stdout %q", decoded, c.stdout)
			}
		})
	}
}

// TestLastJSONLineHandlesArrayPayloads confirms ls's top-level-array
// shape (unlike register/upload/retrieve/balance/deposit's top-level
// objects) is also found correctly — '[' is a valid JSON-value start too.
func TestLastJSONLineHandlesArrayPayloads(t *testing.T) {
	stdout := "some preceding text with no newline{\"decoy\": true}\n[{\"file_id\":\"abc\"},{\"file_id\":\"def\"}]\n"
	var decoded []struct {
		FileID string `json:"file_id"`
	}
	lastJSONLine(t, stdout, &decoded)
	if len(decoded) != 2 || decoded[0].FileID != "abc" || decoded[1].FileID != "def" {
		t.Fatalf("decoded %+v from stdout %q", decoded, stdout)
	}
}

// ── interactive: register's live phone/OTP round-trip ──────────────────
//
// register cannot be driven via runClientJSON: the OTP code doesn't exist
// anywhere (not even in Postgres) until SendOTP has already run inside
// this same process invocation, so it can never be pre-supplied as a
// flag — this is the real, live shape of the flow, not a test
// simplification. This helper drives the actual interactive prompts,
// reading stdout for known prompt text and writing responses to stdin,
// exactly as a human operator would (register's own design note: in demo
// mode, the operator reads the code from otp_codes directly — this helper
// does that via recoverOTPCode, the same helper demo_timeline_test.go's
// own OTP-driven flows already use).

type interactiveClient struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	buf    *syncBuffer
	waitCh chan error
}

// syncBuffer is a concurrency-safe growable buffer: one goroutine appends
// to it as stdout arrives, the test goroutine polls it for prompt text.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startInteractiveClient(t *testing.T, ctx context.Context, clientBin string, args []string) *interactiveClient {
	t.Helper()
	cmd := exec.CommandContext(ctx, clientBin, args...)
	cmd.Env = append(os.Environ(), "VYOMANAUT_MODE=demo") // see runClientJSON's own note on why this is set here, not per call site
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	buf := &syncBuffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf // prompts land on stdout per account_cmds.go; merging keeps one timeline to wait on
	if err := cmd.Start(); err != nil {
		t.Fatalf("start cmd/client: %v", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	return &interactiveClient{cmd: cmd, stdin: stdin, buf: buf, waitCh: waitCh}
}

// waitForPromptContaining polls the accumulated output for substr,
// failing the test if it doesn't appear within timeout.
func (ic *interactiveClient) waitForPromptContaining(t *testing.T, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if strings.Contains(ic.buf.String(), substr) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for prompt containing %q; output so far:\n%s", substr, ic.buf.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (ic *interactiveClient) send(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(ic.stdin, line+"\n"); err != nil {
		t.Fatalf("write to cmd/client stdin: %v", err)
	}
}

// finish closes stdin and waits for exit, returning the full accumulated
// output for lastJSONLine to decode.
func (ic *interactiveClient) finish(t *testing.T, timeout time.Duration) (stdout string, exitErr error) {
	t.Helper()
	_ = ic.stdin.Close()
	select {
	case err := <-ic.waitCh:
		return ic.buf.String(), err
	case <-time.After(timeout):
		_ = ic.cmd.Process.Kill()
		t.Fatalf("cmd/client register did not exit within %s; output so far:\n%s", timeout, ic.buf.String())
		return "", nil
	}
}

// runClientRegisterInteractive drives `cmd/client register --json` through
// its live phone/OTP round-trip and returns the decoded owner_id.
// SkipMnemonicConfirm is true in demo mode (config.DemoProfile), so no
// mnemonic-confirmation prompt ever appears — only phone, OTP code, and
// passphrase.
func runClientRegisterInteractive(t *testing.T, ctx context.Context, db *sql.DB, clientBin, microserviceURL, dataDir, phone, passphrase string) (ownerID string) {
	t.Helper()
	ic := startInteractiveClient(t, ctx, clientBin, []string{
		"register",
		"--microservice-url=" + microserviceURL,
		"--data-dir=" + dataDir,
		"--json",
		"--phone=" + phone,
		"--passphrase=" + passphrase,
	})

	ic.waitForPromptContaining(t, "OTP sent", 30*time.Second)
	code := recoverOTPCode(t, ctx, db, phone)
	ic.waitForPromptContaining(t, "Enter the 6-digit code", 10*time.Second)
	ic.send(t, code)

	stdout, err := ic.finish(t, 30*time.Second)
	if err != nil {
		t.Fatalf("cmd/client register: %v\noutput:\n%s", err, stdout)
	}

	var result struct {
		OwnerID    string `json:"owner_id"`
		Registered bool   `json:"registered"`
	}
	lastJSONLine(t, stdout, &result)
	if !result.Registered || result.OwnerID == "" {
		t.Fatalf("register did not report success: %+v\nfull output:\n%s", result, stdout)
	}
	return result.OwnerID
}