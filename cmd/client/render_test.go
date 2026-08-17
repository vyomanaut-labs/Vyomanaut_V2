package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestPrintCLIErrorEmitsJSONUnderJSONMode is a regression test for a real
// bug found while writing scripts/test/demo_cli_test.go (M17 Session
// 17.2.1): every dispatchX error path called renderError/renderTransferError
// directly, which always produces human-readable prose — --json mode never
// actually emitted JSON on failure, only on success. A CLI-driven
// integration test parsing --json output on a deliberately-failing call
// (TestDemoCLIUploadFailsBeforeDeposit) would have silently failed to
// parse stderr as JSON. printCLIError is the fix; this test pins the
// contract so it can't regress silently again.
func TestPrintCLIErrorEmitsJSONUnderJSONMode(t *testing.T) {
	testErr := errors.New("boom")
	humanCalled := false
	humanRender := func(err error) string { humanCalled = true; return "human: " + err.Error() }

	var jsonOut bytes.Buffer
	printCLIError(&jsonOut, true, testErr, humanRender)
	if humanCalled {
		t.Error("humanRender was called under --json mode; it must not be")
	}
	var decoded jsonErrorOutput
	if err := json.Unmarshal(jsonOut.Bytes(), &decoded); err != nil {
		t.Fatalf("--json mode output is not valid JSON: %v (%q)", err, jsonOut.String())
	}
	if decoded.Message == "" {
		t.Error("decoded JSON error has an empty message")
	}

	var humanOut bytes.Buffer
	humanCalled = false
	printCLIError(&humanOut, false, testErr, humanRender)
	if !humanCalled {
		t.Error("humanRender was not called in human-readable mode")
	}
	if !strings.Contains(humanOut.String(), "boom") {
		t.Errorf("human-mode output = %q, want it to contain the underlying error text", humanOut.String())
	}
	// Human mode must never emit something that looks like the JSON shape —
	// proves the two modes are actually distinct, not one masquerading as
	// the other.
	if strings.HasPrefix(strings.TrimSpace(humanOut.String()), "{") {
		t.Errorf("human-mode output looks like JSON: %q", humanOut.String())
	}
}
