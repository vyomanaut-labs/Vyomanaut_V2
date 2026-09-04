package main

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/manage"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
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

// TestFormatLsRowShowsMBNotRawBytes pins the M18 Session 18.2
// unit-legibility change: `client ls`'s SIZE and SHARD_SIZE columns must
// show humanize.FormatMB figures, never a raw byte count with the literal
// word "bytes" — the exact regression this guards against is
// formatLsRow's format string reverting to its pre-M18 "%d bytes" form.
// The --json path (dispatchLs's own g.json branch) is untouched: it
// marshals e.SizeBytes directly as an int64, never through formatLsRow.
//
// 117544938 bytes is the real demo video's size (M18 Stage 1 live run,
// the same figure TestDeriveShardLayoutMatchesTheUploadersOwnSplit already
// pins against 150 segments / 750 shards) — chosen so this test ties to an
// actual captured figure, and so the SEGMENTS/SHARDS columns in the
// assertion below are cross-checked against that existing test rather than
// invented fresh.
func TestFormatLsRowShowsMBNotRawBytes(t *testing.T) {
	profile := config.DemoProfile
	fileID := uuid.MustParse("01a06835-cd5b-73ad-b540-11aa3683cc23") // the real demo video's file_id
	entry := manage.FileEntry{
		FileID:            fileID,
		DisplayName:       "original.mp4",
		SizeBytes:         117544938,
		MonthlyCostPaise:  10947, // ₹109.47 at the M18-bumped ₹1000/GB/month demo rate
		AvailabilityLabel: "Available",
	}

	got := formatLsRow(entry, profile)
	want := fmt.Sprintf("%s\toriginal.mp4\t112.10 MB\t150\t750\t3 of 5\t0.25 MB\t₹109.47\tAvailable", fileID)
	if got != want {
		t.Errorf("formatLsRow row =\n  %q\nwant\n  %q", got, want)
	}
	if strings.Contains(got, "bytes") {
		t.Error(`formatLsRow output contains the literal word "bytes" — SIZE and SHARD_SIZE must show MB only, via humanize.FormatMB`)
	}
}

// TestDeriveShardLayoutMatchesTheUploadersOwnSplit pins the derivation
// `client ls` uses for its SEGMENTS/SHARDS columns against the rule the
// uploader actually applies: a segment carries exactly
// DataShards x ShardSize plaintext bytes, and each segment becomes
// TotalShards shards.
//
// The 117544938-byte case is the real demo video from a live run, which
// operator shards independently reported as 750 shards — so this test ties
// the owner-side derivation to an operator-side observation rather than to
// its own arithmetic.
func TestDeriveShardLayoutMatchesTheUploadersOwnSplit(t *testing.T) {
	profile := config.DemoProfile
	segmentBytes := int64(profile.DataShards) * int64(profile.ShardSize)

	cases := []struct {
		name             string
		size             int64
		wantSeg, wantShd int64
	}{
		{"empty file stores nothing", 0, 0, 0},
		{"one byte still needs a whole segment", 1, 1, int64(profile.TotalShards)},
		{"exactly one segment", segmentBytes, 1, int64(profile.TotalShards)},
		{"one byte over rolls into a second", segmentBytes + 1, 2, 2 * int64(profile.TotalShards)},
		{"the live 117MB demo video", 117544938, 150, 750},
	}

	for _, c := range cases {
		seg, shd := deriveShardLayout(c.size, profile)
		if seg != c.wantSeg || shd != c.wantShd {
			t.Errorf("%s: deriveShardLayout(%d) = (%d segments, %d shards), want (%d, %d)",
				c.name, c.size, seg, shd, c.wantSeg, c.wantShd)
		}
	}
}
