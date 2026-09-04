package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/upload"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/humanize"
)

// TestUploadPrintsFileIDOnStdoutOnly proves stdout carries only the
// file_id (TASK step 1: "Prints file_id to stdout. Percentage progress to
// stderr, keeping stdout parseable") — checked at the one function that
// actually writes to stdout for a successful upload, in both output modes.
func TestUploadPrintsFileIDOnStdoutOnly(t *testing.T) {
	fileID := uuid.New()

	var humanOut bytes.Buffer
	printUploadResult(false, fileID, &humanOut)
	if got := strings.TrimSpace(humanOut.String()); got != fileID.String() {
		t.Fatalf("human-mode stdout = %q, want exactly %q", got, fileID.String())
	}

	var jsonOut bytes.Buffer
	printUploadResult(true, fileID, &jsonOut)
	var decoded struct {
		FileID string `json:"file_id"`
	}
	if err := json.Unmarshal(jsonOut.Bytes(), &decoded); err != nil {
		t.Fatalf("--json stdout is not valid JSON: %v (%q)", err, jsonOut.String())
	}
	if decoded.FileID != fileID.String() {
		t.Fatalf("--json stdout file_id = %q, want %q", decoded.FileID, fileID.String())
	}
	// Nothing else on stdout in either mode — no progress text, no prose.
	if strings.Contains(humanOut.String(), "%") || strings.Contains(jsonOut.String(), "%") {
		t.Fatalf("stdout contains what looks like progress output; progress must go to stderr only")
	}
}

// TestRetrieveDefaultsToPointerFilename covers TASK step 2's "-o out.
// Default filename from the pointer file" across all three cases:
// explicit -o wins; a pointer-supplied display name is used when present;
// the file_id is the fallback when neither is available (today's actual
// behavior, since upload never populates a display name in practice — see
// defaultRetrieveOutputPath's own doc comment).
func TestRetrieveDefaultsToPointerFilename(t *testing.T) {
	fileID := uuid.New()

	if got := defaultRetrieveOutputPath("my-output.bin", fileID, "ignored.txt"); got != "my-output.bin" {
		t.Errorf("-o should win outright, got %q", got)
	}
	if got := defaultRetrieveOutputPath("", fileID, "original-name.pdf"); got != "original-name.pdf" {
		t.Errorf("should default to the pointer file's display name when present, got %q", got)
	}
	if got := defaultRetrieveOutputPath("", fileID, ""); got != fileID.String() {
		t.Errorf("should fall back to file_id when neither -o nor a pointer display name is available, got %q", got)
	}
}

// TestInsufficientEscrowRendersIC14CodeAndPointsAtDeposit covers TASK step
// 4's explicit requirement: ErrInsufficientEscrow renders IC §14's copy
// and points at `deposit`.
func TestInsufficientEscrowRendersIC14CodeAndPointsAtDeposit(t *testing.T) {
	wrapped := fmt.Errorf("upload: requestAssignment: %w", upload.ErrInsufficientEscrow)
	got := renderTransferError(wrapped)

	wantHeadline := copyTable["INSUFFICIENT_ESCROW_BALANCE"].headline
	if !strings.Contains(got, wantHeadline) {
		t.Errorf("rendered copy = %q, want it to contain IC §14's INSUFFICIENT_ESCROW_BALANCE headline %q", got, wantHeadline)
	}
	if !strings.Contains(strings.ToLower(got), "deposit") {
		t.Errorf("rendered copy = %q, want a pointer to `deposit`", got)
	}
}

// TestWithTransferErrorCodeSurvivesToJSONOutput is a regression test for a
// real bug a live TestDemoCLIUploadFailsBeforeDeposit run caught: --json
// mode got error_code="" instead of INSUFFICIENT_ESCROW_BALANCE, because
// printCLIError's --json path always called the generic errorCodeOf,
// which has no knowledge of upload.ErrInsufficientEscrow (a local
// sentinel, never a server error_code) — only renderTransferError (the
// human-readable path) mapped it correctly. withTransferErrorCode is the
// fix; this pins both that the code now comes through AND that the
// original sentinel is still detectable via errors.Is on the wrapped
// value (the human-readable path depends on that still working).
func TestWithTransferErrorCodeSurvivesToJSONOutput(t *testing.T) {
	original := fmt.Errorf("upload: requestAssignment: %w", upload.ErrInsufficientEscrow)
	wrapped := withTransferErrorCode(original)

	if !errors.Is(wrapped, upload.ErrInsufficientEscrow) {
		t.Fatal("errors.Is(wrapped, upload.ErrInsufficientEscrow) = false — wrapping must preserve this for renderTransferError's own switch to keep matching")
	}

	jsonOut := renderErrorJSON(wrapped)
	var decoded jsonErrorOutput
	if err := json.Unmarshal([]byte(jsonOut), &decoded); err != nil {
		t.Fatalf("renderErrorJSON output is not valid JSON: %v (%q)", err, jsonOut)
	}
	if decoded.ErrorCode != "INSUFFICIENT_ESCROW_BALANCE" {
		t.Errorf("error_code = %q, want INSUFFICIENT_ESCROW_BALANCE", decoded.ErrorCode)
	}

	// NETWORK_NOT_READY is the other of the two sentinels this function
	// maps; confirm it too rather than assuming the switch's second arm
	// works because the first one does.
	wrappedReady := withTransferErrorCode(fmt.Errorf("upload: requestAssignment: %w", upload.ErrNetworkNotReady))
	jsonReady := renderErrorJSON(wrappedReady)
	var decodedReady jsonErrorOutput
	if err := json.Unmarshal([]byte(jsonReady), &decodedReady); err != nil {
		t.Fatalf("renderErrorJSON output is not valid JSON: %v (%q)", err, jsonReady)
	}
	if decodedReady.ErrorCode != "NETWORK_NOT_READY" {
		t.Errorf("error_code = %q, want NETWORK_NOT_READY", decodedReady.ErrorCode)
	}
}

// TestCanaryMismatchIsErrorsIsCryptoSentinel confirms D-10's fix end to
// end from cmd/client's own vantage point: errors.Is against
// crypto.ErrCanaryMismatch succeeds above the client boundary (not
// retrieve's own package-local sentinel — see retrieve/orchestrator.go's
// note on why that one is no longer what decode.go actually returns), and
// renderTransferError's canary branch — which relies on exactly that
// errors.Is check — fires correctly.
func TestCanaryMismatchIsErrorsIsCryptoSentinel(t *testing.T) {
	// Simulates the real error chain: decode.go wraps crypto.
	// ErrCanaryMismatch, then RetrieveFile wraps that again.
	wrapped := fmt.Errorf("retrieve: RetrieveFile: segment %d: %w",
		0, fmt.Errorf("retrieve: %w", crypto.ErrCanaryMismatch))

	if !errors.Is(wrapped, crypto.ErrCanaryMismatch) {
		t.Fatalf("errors.Is(err, crypto.ErrCanaryMismatch) = false through the full wrap chain, want true")
	}

	got := renderTransferError(wrapped)
	if !strings.Contains(strings.ToLower(got), "corrupt") {
		t.Errorf("renderTransferError(canary mismatch) = %q, want the canary-specific copy, not the generic fallback", got)
	}
}

// TestUploadProgressBarIsExactlyOneColumnPerCell — the bar redraws in place
// with \r, so a bar whose rune count drifted would leave debris from the
// previous frame on screen. Both block characters are single-column, so the
// rune count must equal uploadProgressBarWidth at every ratio.
func TestUploadProgressBarIsExactlyOneColumnPerCell(t *testing.T) {
	cases := []struct{ acked, total int }{
		{0, 10}, {1, 10}, {5, 10}, {10, 10},
		{0, 0},   // no total yet — session state not written
		{15, 10}, // defensive: more acked than total must still not overflow
		{-1, 10},
	}
	for _, c := range cases {
		got := len([]rune(uploadProgressBar(c.acked, c.total)))
		if got != uploadProgressBarWidth {
			t.Errorf("uploadProgressBar(%d,%d) is %d runes, want %d", c.acked, c.total, got, uploadProgressBarWidth)
		}
	}
}

// TestUploadProgressBarTracksTheRatio confirms the bar is a presentation of
// real acked-shard data, not decoration: empty at zero, full at completion.
func TestUploadProgressBarTracksTheRatio(t *testing.T) {
	empty := uploadProgressBar(0, 10)
	if strings.ContainsRune(empty, '\u2588') {
		t.Errorf("a zero-progress bar should have no filled cells: %q", empty)
	}
	full := uploadProgressBar(10, 10)
	if strings.ContainsRune(full, '\u2591') {
		t.Errorf("a complete bar should have no empty cells: %q", full)
	}
}

// TestRetrieveThroughputRefusesMeaninglessRates — a tiny file retrieved in
// microseconds would otherwise print an enormous MB/s that says nothing
// about the network. Reporting "rate n/a" is the honest output.
func TestRetrieveThroughputRefusesMeaninglessRates(t *testing.T) {
	if got := retrieveThroughput(0, time.Second); got != "rate n/a" {
		t.Errorf("zero bytes should report no rate, got %q", got)
	}
	if got := retrieveThroughput(100, 0); got != "rate n/a" {
		t.Errorf("zero elapsed should report no rate, got %q", got)
	}
	if got := retrieveThroughput(10*humanize.BytesPerMB, 2*time.Second); got != "5.0 MB/s" {
		t.Errorf("10 MB in 2s should read 5.0 MB/s, got %q", got)
	}
}

// TestRetrievedLineShowsMBNotRawBytes pins the M18 Session 18.2
// unit-legibility change: dispatchRetrieve's human-readable success line
// must show a humanize.FormatMB figure, never a bare byte count with the
// word "bytes" — the exact regression this guards against is
// formatRetrievedLine's format string reverting to "%d bytes" (its pre-M18
// form). The --json path's Bytes field is untouched by this change
// (dispatchRetrieve marshals len(plaintext) directly there, never through
// formatRetrievedLine), so this test only exercises the human-readable
// helper.
//
// 3328987 bytes is the real demo photo's size (M18 Stage 1 live run) —
// chosen so this test ties to an actual captured figure, not an arbitrary
// round number.
func TestRetrievedLineShowsMBNotRawBytes(t *testing.T) {
	const demoPhotoBytes = 3328987
	want := "Retrieved 3.17 MB to /tmp/out.jpg"
	if got := formatRetrievedLine(demoPhotoBytes, "/tmp/out.jpg"); got != want {
		t.Errorf("formatRetrievedLine(%d, ...) = %q, want %q", demoPhotoBytes, got, want)
	}
	if strings.Contains(formatRetrievedLine(demoPhotoBytes, "/tmp/out.jpg"), "bytes") {
		t.Error(`formatRetrievedLine output contains the literal word "bytes" — it must show MB only, via humanize.FormatMB`)
	}
}
