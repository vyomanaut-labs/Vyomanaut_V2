package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/upload"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
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
