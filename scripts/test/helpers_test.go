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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/retrieve"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/upload"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// pollContextAlive fails the test immediately, with an unambiguous
// diagnosis, the moment a poll loop's PARENT ctx has already expired or
// been canceled. [F-17E-12] Every poll* helper in this package computes
// its own local `deadline := time.Now().Add(timeout)` from a `timeout`
// parameter that is entirely independent of `ctx`'s own (often much
// shorter, and fixed at the calling test's start) deadline. Once ctx
// dies -- most commonly because an earlier step in the same test (e.g.
// pollReadiness, pollAllProvidersActive) consumed more of the test's
// outer context.WithTimeout budget than the remaining steps have room
// for -- db.QueryRowContext(ctx, ...) and http.NewRequestWithContext(ctx,
// ...) both fail immediately on every subsequent iteration. Without this
// check, that failure is indistinguishable from "condition not yet true"
// to the loop, which just sleeps and retries -- uselessly, since every
// following query fails the same way -- until ITS OWN local `timeout`
// elapses, which can be many minutes later than when ctx actually died.
// That gap has twice this session been long enough, summed across a
// test's several sequential polls, to run the whole test past the
// external `go test -timeout` watchdog -- the one failure mode that
// skips t.Cleanup entirely and leaks the test's spawned
// microservice/provider child processes (see this session's handoff,
// section 3). Calling this at the top of every poll iteration turns
// that silent, slow-motion budget exhaustion into an immediate,
// correctly-attributed t.Fatalf instead.
func pollContextAlive(t *testing.T, ctx context.Context, what string) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Fatalf("%s: the calling test's own context ended before the condition was met (%v) -- this is a test-budget problem (an earlier step in this test consumed more of its outer context.WithTimeout than later steps had room for), not evidence the condition itself would never have become true; widen the test's outer ctx or shorten an earlier step's poll budget", what, err)
	}
}

// TestMain reaps daemons orphaned by an earlier, uncleanly-terminated
// invocation of this same test binary before running any test in this
// one. See reapOrphanedDaemons and the F-17E-14 note just below it for
// why this is necessary and what it guards against.
func TestMain(m *testing.M) {
	reapOrphanedDaemons()
	os.Exit(m.Run())
}

// ---- cross-invocation daemon registry -----------------------------------
//
// [F-17E-14] startMicroservice/startMicroserviceWithFlags/startProviders
// spawn real, long-lived daemon processes whose t.Cleanup is the only
// thing that ever kills them. t.Cleanup does not run when go test's own
// -timeout watchdog fires (an unhandled panic on a goroutine that is not
// the test's own goroutine, confirmed live this session) or when someone
// Ctrl-Cs a stuck run. Either way the daemon is orphaned: it keeps
// running its own background loops (departure detection, repair
// dispatch, vetting GC) indefinitely, and this harness always recreates
// the *same* fixed-name vyomanaut_test database on the same fixed port
// for reproducibility -- so the orphan's own *sql.DB pool simply
// reconnects the moment the next `docker compose up` brings Postgres
// back, and it starts racing every subsequent, unrelated test's own
// legitimate microservice for the same repair_jobs rows. That exact race
// is confirmed (clean_demo_tests_2.txt, this session) to be the cause of
// every "0x02 NOT_AUTHORISED" repair failure investigated so far: 4
// distinct microservice peer IDs were rejected as unauthorised across
// that run, and none of the 4 ever printed a legitimate
// [STARTUP]/advertising line anywhere in that run's own log -- they
// predated it entirely.
//
// This registry survives across separate `go test` invocations (unlike
// t.TempDir(), which Go deletes when each test ends): every spawned
// daemon is appended here the moment it starts, and TestMain reaps
// whatever a *previous*, uncleanly-terminated invocation left behind
// before this invocation starts any new one of its own. A PID alone is
// not a safe kill target (PIDs recycle) -- each entry also records the
// daemon's exact, randomly-named t.TempDir() binary path, and reap
// re-verifies that a live process at the recorded PID still has that
// *exact* path as its command line (via `ps -o args=`) before killing
// it, so a coincidental PID reuse by an unrelated process can't be
// mistaken for one of ours.
//
// Scope: only the two real daemons (microservice, provider) are tracked.
// cmd/client invocations (startInteractiveClient, runClientJSON) are
// short-lived one-shot or interactive processes with no background
// loops and no registered P2P identity for a provider to ever accept or
// reject -- an orphaned one just sits idle, harmless, and out of scope
// for the bug this registry exists to prevent.
var (
	daemonRegistryPath = filepath.Join(os.TempDir(), "vyomanaut-integration-daemons.registry")
	daemonRegistryMu   sync.Mutex
)

type registeredDaemon struct {
	PID     int    `json:"pid"`
	BinPath string `json:"bin_path"`
	Kind    string `json:"kind"`
}

// registerDaemon durably records a just-started daemon so a future
// invocation's TestMain can find and kill it if this invocation's own
// t.Cleanup never gets the chance to. Called immediately after a
// successful cmd.Start(), before anything else that could fail.
func registerDaemon(pid int, binPath, kind string) {
	daemonRegistryMu.Lock()
	defer daemonRegistryMu.Unlock()
	f, err := os.OpenFile(daemonRegistryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		// Best-effort: a registry write failure must never fail the
		// actual test or block starting the daemon it's trying to guard.
		fmt.Printf("[F-17E-14] warning: could not open daemon registry %s: %v\n", daemonRegistryPath, err)
		return
	}
	defer f.Close()
	line, err := json.Marshal(registeredDaemon{PID: pid, BinPath: binPath, Kind: kind})
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
}

// deregisterDaemon removes a daemon's entry once it has actually been
// killed (either by this invocation's own cleanup, or by reap finding it
// still alive from a previous one), so the registry doesn't grow
// unboundedly across a long, healthy session.
func deregisterDaemon(pid int) {
	daemonRegistryMu.Lock()
	defer daemonRegistryMu.Unlock()
	raw, err := os.ReadFile(daemonRegistryPath)
	if err != nil {
		return // nothing to rewrite -- common case, file doesn't exist yet
	}
	var kept []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var d registeredDaemon
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			continue // drop unparsable lines rather than fail the whole registry
		}
		if d.PID != pid {
			kept = append(kept, line)
		}
	}
	content := ""
	if len(kept) > 0 {
		content = strings.Join(kept, "\n") + "\n"
	}
	_ = os.WriteFile(daemonRegistryPath, []byte(content), 0o644)
}

// processStillMatches reports whether pid is currently a live process
// whose command line is exactly binPath — the identity check that makes
// reaping a possibly-recycled PID safe. The actual liveness+identity
// mechanism is platform-specific (daemon_process_unix.go /
// daemon_process_windows.go); this wrapper only owns the shared
// pid <= 0 guard.
func processStillMatches(pid int, binPath string) bool {
	if pid <= 0 {
		return false
	}
	return processMatchesOS(pid, binPath)
}

// reapOrphanedDaemons runs once, from TestMain, before this invocation
// starts any daemon of its own. It kills anything a previous, uncleanly-
// terminated invocation left behind, printing exactly what it killed so
// this is never a silent, unverifiable mechanism -- if it fires, you'll
// see it in go test -v's own output.
func reapOrphanedDaemons() {
	daemonRegistryMu.Lock()
	defer daemonRegistryMu.Unlock()
	raw, err := os.ReadFile(daemonRegistryPath)
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var d registeredDaemon
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			continue
		}
		if processStillMatches(d.PID, d.BinPath) {
			fmt.Printf("[F-17E-14] reaping orphaned %s from an earlier, uncleanly-terminated test run: pid=%d bin=%s\n", d.Kind, d.PID, d.BinPath)
			killProcessGroupOS(d.PID) // whole process tree (see setNewProcessGroup at spawn time)
		}
	}
	// Whatever was in the registry has now either been freshly killed
	// above or was already dead -- either way this invocation starts
	// with a clean slate.
	_ = os.Remove(daemonRegistryPath)
}

// killDaemonProcessGroup is what every daemon's t.Cleanup calls instead
// of cmd.Process.Kill() directly: it kills the whole process tree (see
// setNewProcessGroup in startMicroservice/startMicroserviceWithFlags/
// startProviders) and always deregisters, whether or not the kill itself
// found anything still alive to kill, so a daemon that already exited on
// its own doesn't leave a stale registry entry behind for a future run to
// trip over.
func killDaemonProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	killProcessGroupOS(pid)
	_ = cmd.Wait()
	deregisterDaemon(pid)
}

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

// ═══════════════════════════════════════════════════════════════════════
// M17-E Session 17.7.2 additions (ADR-084 §D-4 matrix, F-D-1)
// ═══════════════════════════════════════════════════════════════════════

// startMicroserviceWithFlags mirrors demo_timeline_test.go's own
// startMicroservice construction — same random-key generation, same env
// var set, same stable log-directory-with-on-failure-dump cleanup, same
// waitForHTTP readiness wait — with exactly one addition: extraArgs are
// passed as command-line flags to the spawned binary.
//
// This duplicates startMicroservice's body rather than adding a variadic
// parameter to it, because startMicroservice itself lives in
// demo_timeline_test.go, which is NOT in this session's own FILES list
// (scripts/test/demo_departure_test.go, scripts/test/helpers_test.go
// (extend) only) — the same judgment call buildClientBinary already made
// for buildBinaries (this file's own header comment). Session 17.7.2 needs
// this specifically because startMicroservice invokes the binary with NO
// arguments at all; --departure-threshold can only reach the process as a
// flag here, not as an environment variable alone, because this session's
// own VERIFY block checks for the literal flag text, and because a flag is
// what an operator running a real demo would actually type — matching
// that, not just satisfying the check, is the point (ADR-084 §D-4's own
// framing: this is a real operator-facing flag, not merely an env var).
func startMicroserviceWithFlags(t *testing.T, ctx context.Context, binPath string, extraArgs ...string) *liveMicroservice {
	t.Helper()

	adminKey := randomHex(t, 32)
	signingSeed := randomHex(t, ed25519SeedSize)
	clusterSeed := randomBase64Seed(t)
	port := freePort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	cmd := exec.CommandContext(ctx, binPath, extraArgs...)
	setNewProcessGroup(cmd) // F-17E-14: see startMicroservice's own note (demo_timeline_test.go)
	cmd.Env = append(os.Environ(),
		"VYOMANAUT_MODE=demo",
		"PGHOST="+envOr("PGHOST", "localhost"),
		"PGPORT="+envOr("PGPORT", "5432"),
		"PGUSER="+envOr("PGUSER", "vyomanaut_app"),
		"PGPASSWORD="+os.Getenv("PGPASSWORD"),
		"PGDATABASE="+envOr("PGDATABASE", "vyomanaut_test"),
		"PGSSLMODE="+envOr("PGSSLMODE", "disable"),
		"PGMIGRATORUSER="+envOr("PGMIGRATORUSER", "vyomanaut_migrator"),
		"PGMIGRATORPASSWORD="+os.Getenv("PGMIGRATORPASSWORD"),
		"VYOMANAUT_ADMIN_API_KEY="+adminKey,
		"VYOMANAUT_MICROSERVICE_SIGNING_SEED="+signingSeed,
		"VYOMANAUT_CLUSTER_MASTER_SEED="+clusterSeed,
		fmt.Sprintf("VYOMANAUT_HTTP_LISTEN_ADDR=:%d", port),
	)

	logDir, err := os.MkdirTemp("", "vyomanaut-microservice-departure-log-")
	if err != nil {
		t.Fatalf("create microservice log dir: %v", err)
	}
	logPath := filepath.Join(logDir, "microservice.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create microservice log file: %v", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		t.Fatalf("start microservice: %v", err)
	}
	registerDaemon(cmd.Process.Pid, binPath, "microservice") // F-17E-14
	t.Cleanup(func() {
		killDaemonProcessGroup(cmd)
		_ = logFile.Close()
		if t.Failed() {
			if content, readErr := os.ReadFile(logPath); readErr == nil {
				t.Logf("microservice log (%s):\n%s", logPath, content)
			} else {
				t.Logf("could not read microservice log at %s: %v", logPath, readErr)
			}
		}
		_ = os.RemoveAll(logDir)
	})

	ms := &liveMicroservice{baseURL: baseURL, adminAPIKey: adminKey, signingSeed: signingSeed, clusterSeed: clusterSeed, logPath: logPath}
	waitForHTTP(t, baseURL+"/api/v1/admin/readiness", 30*time.Second)
	return ms
}

// ed25519SeedSize duplicates ed25519.SeedSize's value locally so this file
// does not need its own "crypto/ed25519" import solely for one constant
// already available transitively — matching this codebase's established
// discipline (see cmd/microservice/keys.go's own header note) of naming
// exactly why a small duplication was chosen over a new import; here the
// reason is that ed25519.SeedSize is always 32, a stable, documented Go
// stdlib constant, not something at risk of silent drift.
const ed25519SeedSize = 32

// ── upload/retrieve, tracked (F-D-1: every departure case in this phase
// ends in a byte-identity assertion, which needs the SAME masterSecret and
// plaintext used at upload time available again at retrieve time —
// uploadTestFileAllowingError (demo_timeline_test.go) generates and
// discards its own masterSecret internally, so this file adds its own
// tracked variant rather than editing that one, again respecting this
// session's own FILES list) ──────────────────────────────────────────────

// uploadTestFileTracked performs a real upload via internal/client/upload's
// SDK — same construction as demo_timeline_test.go's own
// uploadTestFileAllowingError — but returns the masterSecret and plaintext
// used, so a later retrieveTestFileTracked call in the same test can prove
// byte identity end to end.
func uploadTestFileTracked(t *testing.T, ctx context.Context, ms *liveMicroservice, owner *liveOwner, sizeBytes int) (fileID uuid.UUID, masterSecret [32]byte, plaintext []byte) {
	t.Helper()

	profile := config.SelectProfile("demo")
	engine, err := erasure.NewEngine(profile)
	if err != nil {
		t.Fatalf("erasure.NewEngine: %v", err)
	}

	clientPort := freePort(t)
	host, err := p2p.NewHost(p2p.HostConfig{
		PrivateKey: owner.signingKey,
		ListenAddr: fmt.Sprintf("0.0.0.0:%d", clientPort),
	})
	if err != nil {
		t.Fatalf("p2p.NewHost (client, upload): %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })

	orch := upload.NewOrchestrator(ms.baseURL, owner.token, http.DefaultClient, host, engine, profile, owner.signingKey, t.TempDir())

	if _, err := cryptorand.Read(masterSecret[:]); err != nil {
		t.Fatalf("rand.Read masterSecret: %v", err)
	}
	plaintext = make([]byte, sizeBytes)
	if _, err := cryptorand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read plaintext: %v", err)
	}

	fileID, err = orch.UploadFile(ctx, masterSecret, owner.ownerID, plaintext)
	if err != nil {
		t.Fatalf("UploadFile: %v", err)
	}
	return fileID, masterSecret, plaintext
}

// uploadTestFileTrackedAllowingError is uploadTestFileTracked's core, for
// callers (departAtMidUpload) that need to race a kill against the upload
// itself and so cannot let a mid-flight failure call t.Fatalf from inside
// a background goroutine (the documented reason a background goroutine
// must never call t.Fatal — it does not stop the test, only that
// goroutine). masterSecret/plaintext are still returned on error (whatever
// was generated before the attempt), so a caller can still assert what it
// needs to regardless of outcome.
func uploadTestFileTrackedAllowingError(ctx context.Context, ms *liveMicroservice, owner *liveOwner, host p2p.Host, engine *erasure.Engine, sizeBytes int) (fileID uuid.UUID, masterSecret [32]byte, plaintext []byte, err error) {
	profile := config.SelectProfile("demo")
	orch := upload.NewOrchestrator(ms.baseURL, owner.token, http.DefaultClient, host, engine, profile, owner.signingKey, os.TempDir())

	if _, rerr := cryptorand.Read(masterSecret[:]); rerr != nil {
		return uuid.UUID{}, masterSecret, nil, fmt.Errorf("rand.Read masterSecret: %w", rerr)
	}
	plaintext = make([]byte, sizeBytes)
	if _, rerr := cryptorand.Read(plaintext); rerr != nil {
		return uuid.UUID{}, masterSecret, plaintext, fmt.Errorf("rand.Read plaintext: %w", rerr)
	}

	fileID, err = orch.UploadFile(ctx, masterSecret, owner.ownerID, plaintext)
	return fileID, masterSecret, plaintext, err
}

// retrieveTestFileTracked performs a real retrieve via
// internal/client/retrieve's SDK and returns the decoded plaintext,
// failing the test on error — this file's retrieve-side counterpart to
// uploadTestFileTracked/demo_timeline_test.go's own upload-side helpers.
// No prior test in this codebase drove a real retrieve at all (F-D-1's own
// finding: TestViabilityRepairSucceedsWithTwoOfFiveOffline ends at
// pollRepairCompleted, never retrieves) — this is the first.
func retrieveTestFileTracked(t *testing.T, ctx context.Context, ms *liveMicroservice, owner *liveOwner, masterSecret [32]byte, fileID uuid.UUID) []byte {
	t.Helper()

	profile := config.SelectProfile("demo")
	engine, err := erasure.NewEngine(profile)
	if err != nil {
		t.Fatalf("erasure.NewEngine (retrieve): %v", err)
	}

	clientPort := freePort(t)
	host, err := p2p.NewHost(p2p.HostConfig{
		PrivateKey: owner.signingKey,
		ListenAddr: fmt.Sprintf("0.0.0.0:%d", clientPort),
	})
	if err != nil {
		t.Fatalf("p2p.NewHost (client, retrieve): %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })

	orch := retrieve.NewOrchestrator(ms.baseURL, owner.token, http.DefaultClient, host, engine, profile)
	plaintext, err := orch.RetrieveFile(ctx, masterSecret, owner.ownerID, fileID)
	if err != nil {
		t.Fatalf("RetrieveFile: %v", err)
	}
	return plaintext
}

// ── mapping a chunk_assignments holder back to its --sim-only-index, so
// departAt can kill/depart the SPECIFIC provider actually holding a given
// file's data, not an arbitrary one ─────────────────────────────────────

// providerIndexForID maps a provider_id back to its 0..testSimCount-1
// --sim-only-index, by parsing it out of that provider's own
// startProviders-assigned phone number (+91987653{4-digit index} —
// demo_timeline_test.go's own startProviders comment documents this exact
// pattern). Fails the test if providerID does not look like one of this
// run's own simulated providers.
func providerIndexForID(t *testing.T, ctx context.Context, db *sql.DB, providerID uuid.UUID) int {
	t.Helper()
	var phone string
	if err := db.QueryRowContext(ctx, `SELECT phone_number FROM providers WHERE provider_id = $1`, providerID).Scan(&phone); err != nil {
		t.Fatalf("providerIndexForID: query phone_number for %s: %v", providerID, err)
	}
	const prefix = "+91987653"
	if !strings.HasPrefix(phone, prefix) || len(phone) != len(prefix)+4 {
		t.Fatalf("providerIndexForID: phone_number %q for provider %s does not match this suite's own +91987653NNNN sim-provider pattern", phone, providerID)
	}
	var index int
	if _, err := fmt.Sscanf(phone[len(prefix):], "%04d", &index); err != nil {
		t.Fatalf("providerIndexForID: parse index from phone_number %q: %v", phone, err)
	}
	return index
}

// firstRealChunkHolderIndex returns the --sim-only-index of a provider
// currently holding a real (non-vetting) shard for fileID — used to pick
// WHICH provider to depart for POST_UPLOAD/MID_REPAIR/MID_RETRIEVE phases,
// where the departed provider must actually matter to the file (departing
// an uninvolved provider would prove nothing).
func firstRealChunkHolderIndex(t *testing.T, ctx context.Context, db *sql.DB, fileID uuid.UUID) int {
	t.Helper()
	var providerID uuid.UUID
	err := db.QueryRowContext(ctx, `
		SELECT ca.provider_id
		FROM chunk_assignments ca
		JOIN segments s ON s.segment_id = ca.segment_id
		WHERE s.file_id = $1 AND ca.is_vetting_chunk = FALSE AND ca.status = 'ACTIVE'
		LIMIT 1`, fileID).Scan(&providerID)
	if err != nil {
		t.Fatalf("firstRealChunkHolderIndex: no ACTIVE real chunk holder found for file %s: %v", fileID, err)
	}
	return providerIndexForID(t, ctx, db, providerID)
}

// realChunkHolderIndices returns count DISTINCT --sim-only-index values
// currently holding a real (non-vetting), ACTIVE shard of fileID — Session
// 17.7.3's own BURST phase needs multiple, genuinely distinct holders in
// one query, since a provider's chunk_assignments row does not change the
// instant it is SIGKILLed (see departAtBurst's own doc comment on why two
// separate firstRealChunkHolderIndex calls would risk returning the same
// provider twice).
func realChunkHolderIndices(t *testing.T, ctx context.Context, db *sql.DB, fileID uuid.UUID, count int) []int {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT ca.provider_id
		FROM chunk_assignments ca
		JOIN segments s ON s.segment_id = ca.segment_id
		WHERE s.file_id = $1 AND ca.is_vetting_chunk = FALSE AND ca.status = 'ACTIVE'
		LIMIT $2`, fileID, count)
	if err != nil {
		t.Fatalf("realChunkHolderIndices: query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var indices []int
	for rows.Next() {
		var providerID uuid.UUID
		if err := rows.Scan(&providerID); err != nil {
			t.Fatalf("realChunkHolderIndices: scan: %v", err)
		}
		indices = append(indices, providerIndexForID(t, ctx, db, providerID))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("realChunkHolderIndices: iterate: %v", err)
	}
	if len(indices) < count {
		t.Fatalf("realChunkHolderIndices: found only %d distinct real chunk holder(s) for file %s, want %d", len(indices), fileID, count)
	}
	return indices
}

// providerIDForIndex is providerIndexForID's own inverse — given a
// --sim-only-index, returns that provider's provider_id via the same
// +91987653NNNN phone convention. Session 17.7.3's MID_REPAIR phase needs
// this to identify the ORIGINAL holder's provider_id before departing it,
// so the subsequent replacement-assignment poll can exclude it by ID.
func providerIDForIndex(t *testing.T, ctx context.Context, db *sql.DB, index int) uuid.UUID {
	t.Helper()
	phone := fmt.Sprintf("+91987653%04d", index)
	var providerID uuid.UUID
	if err := db.QueryRowContext(ctx, `SELECT provider_id FROM providers WHERE phone_number = $1`, phone).Scan(&providerID); err != nil {
		t.Fatalf("providerIDForIndex: query provider_id for index %d (phone %s): %v", index, phone, err)
	}
	return providerID
}

// pollProviderRegistered polls until index's own providers row actually
// exists (its INSERT — internal/api/provider.go's HandleRegister — has
// committed), returning its provider_id once it does.
//
// [Fixed — test-harness bug, discovered live via
// TestDepartureDuringVettingProducesNoRepairJobs] startProviders
// (demo_timeline_test.go) returns as soon as it has called cmd.Start() for
// every --sim-only-index process — it does NOT wait for any of them to
// actually finish their own startup sequence (parse flags, generate/load
// keys, start the P2P listener, THEN make the real registration HTTP
// call) and register. A caller that departs a provider immediately after
// startProviders returns, with no synchronization in between, races that
// startup sequence and can lose it — killing the OS process before its
// own providers row was ever created, which pollDeparted below then waits
// out for its own full timeout, finding nothing, since there is nothing
// to find. This is exactly what removing the (semantically wrong, for
// this exact scenario) pollReadiness pre-flight check exposed: it used to
// accidentally provide enough incidental delay for registration to
// complete first. This function is the correct, minimal, deliberate
// synchronization phaseVetting actually needs — wait for the target's own
// row to exist, nothing more — rather than an accidental side effect of
// an unrelated call.
func pollProviderRegistered(t *testing.T, ctx context.Context, db *sql.DB, index int, timeout time.Duration) uuid.UUID {
	t.Helper()
	phone := fmt.Sprintf("+91987653%04d", index)
	deadline := time.Now().Add(timeout)
	for {
		pollContextAlive(t, ctx, "pollProviderRegistered")
		var providerID uuid.UUID
		err := db.QueryRowContext(ctx, `SELECT provider_id FROM providers WHERE phone_number = $1`, phone).Scan(&providerID)
		if err == nil {
			return providerID
		}
		if time.Now().After(deadline) {
			t.Fatalf("pollProviderRegistered: provider index %d (phone %s) never registered within %s: %v", index, phone, timeout, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// chunkHeldByProviderForFile returns the raw chunk_id bytes of one real,
// ACTIVE shard of fileID held by providerID — Session 17.7.3's MID_REPAIR
// phase needs this specific chunk_id to poll for its own replacement's
// assignment afterward (pollReplacementAssignment).
func chunkHeldByProviderForFile(t *testing.T, ctx context.Context, db *sql.DB, fileID, providerID uuid.UUID) []byte {
	t.Helper()
	var chunkID []byte
	err := db.QueryRowContext(ctx, `
		SELECT ca.chunk_id
		FROM chunk_assignments ca
		JOIN segments s ON s.segment_id = ca.segment_id
		WHERE s.file_id = $1 AND ca.provider_id = $2 AND ca.is_vetting_chunk = FALSE AND ca.status = 'ACTIVE'
		LIMIT 1`, fileID, providerID).Scan(&chunkID)
	if err != nil {
		t.Fatalf("chunkHeldByProviderForFile: no ACTIVE real chunk found for provider %s on file %s: %v", providerID, fileID, err)
	}
	return chunkID
}

// pollReplacementAssignment polls for a chunk_assignments row for chunkID
// held by a provider OTHER than excludeProviderID, in REPAIRING or ACTIVE
// status — this is Session 17.7.3's MID_REPAIR race's own detection
// signal: preRegisterChunkAssignment (internal/repair/executor.go) writes
// this row BEFORE uploadShard is attempted, confirmed by reading that
// function's own call order directly, not inferred.
func pollReplacementAssignment(t *testing.T, ctx context.Context, db *sql.DB, chunkID []byte, excludeProviderID uuid.UUID, timeout time.Duration) uuid.UUID {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		pollContextAlive(t, ctx, "pollReplacementAssignment")
		var providerID uuid.UUID
		err := db.QueryRowContext(ctx, `
			SELECT provider_id FROM chunk_assignments
			WHERE chunk_id = $1 AND provider_id != $2 AND status IN ('REPAIRING', 'ACTIVE')
			ORDER BY created_at DESC LIMIT 1`, chunkID, excludeProviderID).Scan(&providerID)
		if err == nil {
			return providerID
		}
		if time.Now().After(deadline) {
			// [Fixed — failure_reason surfaced, live verification, M17-E
			// Phase 17.7] A bare "sql: no rows in result set" here doesn't
			// distinguish "no repair job was ever enqueued for this chunk"
			// (a departure-detection problem) from "one exists and is
			// still QUEUED/IN_PROGRESS" (a timing problem) from "one
			// exists and reached FAILED" (an execution problem, with its
			// own failure_reason) — see formatRepairJobsForChunk.
			t.Fatalf("pollReplacementAssignment: no replacement chunk_assignments row appeared for chunk %x within %s: %v\n%s",
				chunkID, timeout, err, formatRepairJobsForChunk(ctx, db, chunkID))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// formatRepairJobsForChunk queries every repair_jobs row for chunkID (any
// status, not just FAILED) and formats them for a t.Fatalf message. See
// formatFailedRepairJobs (demo_timeline_test.go) for the sibling helper
// used when repair_jobs.status = 'FAILED' is already known; this one is
// for callers like pollReplacementAssignment that only ever observe the
// downstream chunk_assignments side and so don't yet know whether a
// repair_jobs row exists at all, let alone its status.
func formatRepairJobsForChunk(ctx context.Context, db *sql.DB, chunkID []byte) string {
	rows, err := db.QueryContext(ctx, `
		SELECT status, trigger_type, provider_id, failure_reason, created_at, started_at, completed_at
		FROM repair_jobs
		WHERE chunk_id = $1
		ORDER BY created_at`, chunkID)
	if err != nil {
		return fmt.Sprintf("  (failed to query repair_jobs for chunk %x: %v)", chunkID, err)
	}
	defer func() { _ = rows.Close() }()

	var sb strings.Builder
	for rows.Next() {
		var status, triggerType string
		var providerID, failureReason sql.NullString
		var createdAt time.Time
		var startedAt, completedAt sql.NullTime
		if err := rows.Scan(&status, &triggerType, &providerID, &failureReason, &createdAt, &startedAt, &completedAt); err != nil {
			fmt.Fprintf(&sb, "  (scan error: %v)\n", err)
			continue
		}
		provider := "(none)"
		if providerID.Valid {
			provider = providerID.String
		}
		reason := "(none)"
		if failureReason.Valid {
			reason = failureReason.String
		}
		fmt.Fprintf(&sb, "  status=%s trigger=%s provider=%s created=%s started=%v completed=%v reason=%s\n",
			status, triggerType, provider, createdAt.Format(time.RFC3339), startedAt, completedAt, reason)
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintf(&sb, "  (row iteration error: %v)\n", err)
	}
	if sb.Len() == 0 {
		return fmt.Sprintf("  (no repair_jobs row exists at all for chunk %x — never enqueued)", chunkID)
	}
	return "repair_jobs for this chunk:\n" + sb.String()
}

// retrieveTestFileTrackedAllowingError is retrieveTestFileTracked's core,
// for callers (departAtMidRetrieve) that need to race a kill against the
// retrieve itself and so cannot let a mid-flight failure call t.Fatalf
// from inside a background goroutine — the same reason
// uploadTestFileTrackedAllowingError exists on the upload side.
func retrieveTestFileTrackedAllowingError(ctx context.Context, ms *liveMicroservice, owner *liveOwner, host p2p.Host, engine *erasure.Engine, masterSecret [32]byte, fileID uuid.UUID) ([]byte, error) {
	profile := config.SelectProfile("demo")
	orch := retrieve.NewOrchestrator(ms.baseURL, owner.token, http.DefaultClient, host, engine, profile)
	return orch.RetrieveFile(ctx, masterSecret, owner.ownerID, fileID)
}

// ── graceful departure: `provider depart`, a separate one-shot CLI
// invocation reusing the daemon's own --data-dir identity (cmd/provider/
// depart.go's own header note on why this always verifies) ─────────────

// providerSimDataDir reproduces cmd/provider's own IC §10 naming
// convention exactly (runSimulation's doc comment, main.go:
// "{instance_id} zero-padded to 4 digits") — the ONLY way a separate
// `provider depart` invocation can reload the SAME identity keys the
// long-running --sim-only-index daemon for that index is using.
func providerSimDataDir(simDataDir string, index int) string {
	return filepath.Join(simDataDir, fmt.Sprintf("%04d", index))
}

// gracefulDepartProvider runs `provider depart` as a one-shot process
// against the running daemon's own --data-dir (providerSimDataDir),
// failing the test if it does not exit 0. Returns combined stdout+stderr
// for callers that want to log or parse it (departCmd's own output
// includes status/escrow_release/repair_jobs_queued, cmd/provider/
// depart.go).
func gracefulDepartProvider(t *testing.T, ctx context.Context, providerBinPath, microserviceURL, simDataDir string, index int) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, providerBinPath, "depart",
		"--microservice-url="+microserviceURL,
		"--data-dir="+providerSimDataDir(simDataDir, index),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("provider depart (index %d): %v\n%s", index, err, output)
	}
	return string(output)
}
