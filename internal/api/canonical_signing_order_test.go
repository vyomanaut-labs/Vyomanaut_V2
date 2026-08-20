// Package api is declared in doc.go.
// Tests for the canonical signing-object key ordering invariant (IC §3.1's
// "sorted keys" rule, cross-referenced as the canonical convention for every
// Ed25519 signing input in this package via IC §3.2).
//
// [M11 audit remediation, Finding 1] These tests are deliberately NOT
// self-referential: every expected byte sequence below is hand-derived
// directly from IC §3.1/§3.2's alphabetical-sorted-key rule, never produced
// by calling canonicalSigningObject or any canonicalXxxSigningInput function
// itself. A test that generates its own expected value via the function
// under test cannot catch a contract-conformance bug (only a regression) —
// see this file's sibling TestHeartbeatReturnsMicroserviceCountersignature
// in provider_test.go, which is exactly that kind of self-referential test
// and is left in place as a regression guard, not a conformance check.
//
// [Rechecked against current code — M16 superseded the file.go half of this
// finding] The audit's original Finding 1b targeted
// canonicalFileRegisterSigningInput (file.go), a JSON-canonical, sorted-key
// scheme. That function no longer exists: an M16 fix (see file.go's header,
// "[Corrected, F-16-1] owner_sig verification") replaced it wholesale with
// ownerSigSigningInput, a fixed-layout byte-concatenation scheme, because
// internal/crypto's own package doc forbids JSON serialisation for signing
// inputs entirely — a stricter fix than sorting the JSON keys correctly
// would have been. A fixed byte layout has no "alphabetical key order" to
// get wrong, so the bug class Finding 1b was written against does not apply
// to file.go anymore, and no test for it belongs in this file. (That
// function already has its own dedicated, non-self-referential layout test
// — TestOwnerSigSigningInputMatchesDocumentedLayout in file_test.go, added
// by the same M16 fix.) The two tests below now cover only Finding 1a
// (provider.go's canonicalMicroserviceSigningInput) plus the structural fix
// and regression guards, which are unaffected by the M16 change and still
// apply exactly as originally written.
package api

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// ── Finding 1a: canonicalMicroserviceSigningInput (provider.go) ────────────

func TestCanonicalMicroserviceSigningInput_AlphabeticalOrder(t *testing.T) {
	receivedAt := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	providerID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	got := canonicalMicroserviceSigningInput(receivedAt, providerID)

	// Hand-derived directly from IC §3.1's sorted-key rule: "provider_id" <
	// "received_at" alphabetically ('p' < 'r'), regardless of what order the
	// OAS HeartbeatResponse.microservice_sig description's illustrative
	// example happens to show the fields in (that example is itself
	// internally inconsistent — it shows received_at first while also
	// stating "(sorted keys)" two words later).
	want := `{"provider_id":"11111111-1111-1111-1111-111111111111","received_at":"2026-08-10T12:00:00Z"}`

	if string(got) != want {
		t.Errorf("canonicalMicroserviceSigningInput() = %s, want %s (alphabetical: provider_id before received_at)", got, want)
	}
}

// ── Structural fix: canonicalSigningObject sorts internally ────────────────

func TestCanonicalSigningObject_SortsRegardlessOfCallerOrder(t *testing.T) {
	// Deliberately passed out of order, mimicking exactly the kind of
	// mistake Finding 1 identified at two call sites: canonicalSigningObject
	// must now be robust to a caller that gets the order wrong, closing the
	// whole bug class rather than just today's two known instances.
	got := canonicalSigningObject(
		signingField{"zulu", `"z"`},
		signingField{"alpha", `"a"`},
		signingField{"mike", `"m"`},
	)
	want := `{"alpha":"a","mike":"m","zulu":"z"}`

	if string(got) != want {
		t.Errorf("canonicalSigningObject() with out-of-order input = %s, want %s (must sort internally)", got, want)
	}
}

// ── Regression guards: the five call sites the audit confirmed were already
// correct must remain byte-identical after the structural sort fix ─────────

func TestCanonicalRegisterSigningInput_AlreadyAlphabetical(t *testing.T) {
	asn := "AS12345"
	req := providerRegisterRequestBody{
		ASN:               &asn,
		City:              "Mumbai",
		DeclaredStorageGB: 100,
		Ed25519PublicKey:  "deadbeef",
		InitialMultiaddrs: []string{"/ip4/1.2.3.4/tcp/9000"},
		Region:            "APAC",
	}
	got := canonicalRegisterSigningInput(req)
	// Hand-derived alphabetical order: asn < city < declared_storage_gb <
	// ed25519_public_key < initial_multiaddrs < region.
	want := `{"asn":"AS12345","city":"Mumbai","declared_storage_gb":100,` +
		`"ed25519_public_key":"deadbeef","initial_multiaddrs":["/ip4/1.2.3.4/tcp/9000"],"region":"APAC"}`
	if string(got) != want {
		t.Errorf("canonicalRegisterSigningInput() = %s, want %s", got, want)
	}
}

func TestCanonicalHeartbeatSigningInputAPI_AlreadyAlphabetical(t *testing.T) {
	got := canonicalHeartbeatSigningInputAPI([]string{"/ip4/1.2.3.4/tcp/9000"}, "2026-08-10T12:00:00Z")
	// current_multiaddrs < timestamp.
	want := `{"current_multiaddrs":["/ip4/1.2.3.4/tcp/9000"],"timestamp":"2026-08-10T12:00:00Z"}`
	if string(got) != want {
		t.Errorf("canonicalHeartbeatSigningInputAPI() = %s, want %s", got, want)
	}
}

func TestCanonicalDowntimeSigningInput_AlreadyAlphabetical(t *testing.T) {
	reason := "scheduled maintenance"
	req := providerDowntimeRequestBody{
		PromisedReturnAt: "2026-08-11T00:00:00Z",
		Reason:           &reason,
	}
	got := canonicalDowntimeSigningInput(req)
	// promised_return_at < reason.
	want := `{"promised_return_at":"2026-08-11T00:00:00Z","reason":"scheduled maintenance"}`
	if string(got) != want {
		t.Errorf("canonicalDowntimeSigningInput() = %s, want %s", got, want)
	}
}

func TestCanonicalDepartSigningInput_AlreadyAlphabetical(t *testing.T) {
	departAt := "2026-08-12T00:00:00Z"
	got := canonicalDepartSigningInput(providerDepartRequestBody{DepartAt: &departAt})
	want := `{"depart_at":"2026-08-12T00:00:00Z"}`
	if string(got) != want {
		t.Errorf("canonicalDepartSigningInput() with depart_at = %s, want %s", got, want)
	}

	gotEmpty := canonicalDepartSigningInput(providerDepartRequestBody{})
	wantEmpty := `{}`
	if string(gotEmpty) != wantEmpty {
		t.Errorf("canonicalDepartSigningInput() without depart_at = %s, want %s", gotEmpty, wantEmpty)
	}
}
