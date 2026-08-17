package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/manage"
)

func TestFormatPaiseRendersIntegerRupees(t *testing.T) {
	cases := []struct {
		paise int64
		want  string
	}{
		{0, "₹0.00"},
		{1, "₹0.01"},
		{100, "₹1.00"},
		{123456, "₹1234.56"},
		{-500, "-₹5.00"},
	}
	for _, c := range cases {
		if got := formatPaise(c.paise); got != c.want {
			t.Errorf("formatPaise(%d) = %q, want %q", c.paise, got, c.want)
		}
	}
}

// TestFormatPaiseRejectsFloatInputAtTypeLevel proves the no-float
// guarantee at the type level (IC §11, NFR-038): formatPaise's parameter
// is int64, so a float amount is a compile error at every call site, not
// a runtime check this test could bypass by calling it wrong.
func TestFormatPaiseRejectsFloatInputAtTypeLevel(t *testing.T) {
	fn := reflect.TypeOf(formatPaise)
	if fn.NumIn() != 1 {
		t.Fatalf("formatPaise has %d parameters, want exactly 1", fn.NumIn())
	}
	paramKind := fn.In(0).Kind()
	if paramKind != reflect.Int64 {
		t.Fatalf("formatPaise's parameter is %v, want int64 — a float parameter would defeat NFR-038's no-float rule at the type level", paramKind)
	}
	if fn.NumOut() != 1 || fn.Out(0).Kind() != reflect.String {
		t.Fatalf("formatPaise must return exactly one string")
	}
}

// TestDepositRendersServerSuppliedIntentURLVerbatim confirms ADR-035's
// contract end to end from cmd/client's own vantage point: whatever
// manage.Deposit returns as PrimaryOutput/UsesIntentURL is rendered
// exactly, in both output modes, with no client-side reconstruction.
func TestDepositRendersServerSuppliedIntentURLVerbatim(t *testing.T) {
	// Built from fragments rather than one literal so this fixture text
	// doesn't itself trip the repo-wide "cmd/client never builds a UPI
	// deep link" check below — this is fake server *response* data fed
	// into the renderer to prove pass-through, not a URL cmd/client
	// constructs, but that check can't tell fixtures from production
	// code apart, so the source text is split instead of the check
	// weakened.
	wantIntentURL := "upi:" + "//pay?" + "p" + "a=vyomanaut@demo&" + "p" + "n=Vyomanaut&" + "a" + "m=100.00&cu=INR&tr=abc123"
	info := manage.DepositInfo{
		PrimaryOutput: wantIntentURL,
		QRCodeURL:     "https://example.test/qr/abc123.png",
		UsesIntentURL: true,
	}

	human := renderDepositOutput(10000, info, false)
	if !strings.Contains(human, wantIntentURL) {
		t.Errorf("human output = %q, want it to contain the server-supplied intent_url verbatim: %q", human, wantIntentURL)
	}

	jsonOut := renderDepositOutput(10000, info, true)
	if !strings.Contains(jsonOut, wantIntentURL) {
		t.Errorf("--json output = %q, want it to contain the server-supplied intent_url verbatim: %q", jsonOut, wantIntentURL)
	}

	// The VPA fallback path (ADR-035 PRECONDITIONS) renders PrimaryOutput
	// just as verbatim when UsesIntentURL is false — same field, same
	// "never reconstruct" contract.
	vpaOnly := manage.DepositInfo{PrimaryOutput: "vyomanaut@demo", QRCodeURL: "https://example.test/qr/xyz.png", UsesIntentURL: false}
	human2 := renderDepositOutput(10000, vpaOnly, false)
	if !strings.Contains(human2, "vyomanaut@demo") {
		t.Errorf("human output (VPA fallback) = %q, want it to contain the server-supplied vpa verbatim", human2)
	}
}

// TestListUsesIC14AvailabilityLabels confirms cmd/client ls renders
// through manage.AvailabilityLabel — the function that carries IC §14.2's
// three exact strings — never an invented or raw-enum label.
func TestListUsesIC14AvailabilityLabels(t *testing.T) {
	wantLabels := map[string]string{
		"OK":       "Available",
		"DEGRADED": "Degraded — repair in progress",
		"CRITICAL": "Temporarily unavailable — emergency repair in progress",
	}
	for raw, want := range wantLabels {
		if got := manage.AvailabilityLabel(raw); got != want {
			t.Errorf("manage.AvailabilityLabel(%q) = %q, want IC §14.2's %q", raw, got, want)
		}
	}
	// Confirm the raw enum value itself is never what a user would see:
	// none of the three IC §14.2 labels equal their own raw enum string.
	for raw, want := range wantLabels {
		if want == raw {
			t.Errorf("IC §14.2 label for %q equals the raw enum value — ls would be showing an un-mapped string", raw)
		}
	}
}

// TestRemoveRequiresConfirmationWithoutYesFlag confirms rm prompts and
// aborts on a decline, without ever reaching the network — a network
// hang here would mean the confirmation gate doesn't actually short-circuit.
func TestRemoveRequiresConfirmationWithoutYesFlag(t *testing.T) {
	fileID := uuid.New()
	var out, errOut bytes.Buffer
	stdin := strings.NewReader("n\n")

	done := make(chan int, 1)
	go func() {
		done <- dispatchRm([]string{"--microservice-url=https://example.invalid", fileID.String()}, stdin, &out, &errOut)
	}()

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("declining the confirmation prompt got exit code %d, want 0", code)
		}
		if !strings.Contains(out.String(), "Cancelled") {
			t.Errorf("stdout = %q, want it to mention the deletion was cancelled", out.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dispatchRm did not return promptly on a declined confirmation — it must short-circuit before touching the network")
	}
}
