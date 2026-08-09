// Package api is declared in doc.go.
// Tests for provider.go: Sessions 11.6.1-11.6.6.

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	localcrypto "github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
	"github.com/masamasaowl/Vyomanaut_V2/internal/payment"
)

// ── Shared fixtures ────────────────────────────────────────────────────────

func seedPendingProviderRegistration(t *testing.T, db *sql.DB, subject uuid.UUID, phone string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO pending_registrations (subject, phone_number, expires_at) VALUES ($1, $2, NOW() + interval '1 hour')`,
		subject, phone)
	if err != nil {
		t.Fatalf("seed pending_registrations: %v", err)
	}
}

func insertTestProviderDirect(t *testing.T, db *sql.DB, pub ed25519.PublicKey, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(`
		INSERT INTO providers (phone_number, ed25519_public_key, declared_storage_gb, city, region, asn, status)
		VALUES ($1, $2, 100, 'Mumbai', 'Mumbai', 'AS12345', $3)
		RETURNING provider_id`,
		randPhoneForOwner(), []byte(pub), status,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert test provider: %v", err)
	}
	return id
}

func insertTestOwnerDirect(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}
	var id uuid.UUID
	err = db.QueryRow(`INSERT INTO owners (phone_number, ed25519_public_key) VALUES ($1, $2) RETURNING owner_id`,
		randPhoneForOwner(), []byte(pub)).Scan(&id)
	if err != nil {
		t.Fatalf("insert test owner: %v", err)
	}
	return id
}

func insertTestFileDirect(t *testing.T, db *sql.DB, ownerID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(`
		INSERT INTO files (owner_id, pointer_ciphertext, pointer_nonce, pointer_tag, original_size_bytes)
		VALUES ($1, $2, $3, $4, 1048576)
		RETURNING file_id`,
		ownerID, []byte("ciphertext"), make([]byte, 12), make([]byte, 16),
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert test file: %v", err)
	}
	return id
}

func insertTestSegmentDirect(t *testing.T, db *sql.DB, fileID uuid.UUID, idx int) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(`INSERT INTO segments (file_id, segment_index) VALUES ($1, $2) RETURNING segment_id`, fileID, idx).Scan(&id)
	if err != nil {
		t.Fatalf("insert test segment: %v", err)
	}
	return id
}

func randChunkID(t *testing.T) [32]byte {
	t.Helper()
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("rand chunk id: %v", err)
	}
	return id
}

func insertChunkAssignmentDirect(t *testing.T, db *sql.DB, providerID uuid.UUID, segmentID *uuid.UUID, shardIdx *int, status string) [32]byte {
	t.Helper()
	chunkID := randChunkID(t)
	vetting := segmentID == nil
	_, err := db.Exec(`
		INSERT INTO chunk_assignments (chunk_id, is_vetting_chunk, segment_id, shard_index, provider_id, status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		chunkID[:], vetting, segmentID, shardIdx, providerID, status)
	if err != nil {
		t.Fatalf("insert chunk assignment: %v", err)
	}
	return chunkID
}

// refreshEscrowBalance refreshes mv_provider_escrow_balance using a
// privileged openVerifyDB connection (vyomanaut_migrator), not the
// vyomanaut_app connection tests otherwise use: vyomanaut_app does not own
// this materialized view (ADR-032 — MV refresh is a vyomanaut_migrator-only
// operation), so REFRESH on the app connection fails with "must be owner of
// materialized view". Mirrors internal/repair's own
// refreshProviderScoresForAssignment(t, verify) helper.
func refreshEscrowBalance(t *testing.T) {
	t.Helper()
	verify := openVerifyDB(t)
	if _, err := verify.Exec(`REFRESH MATERIALIZED VIEW mv_provider_escrow_balance`); err != nil {
		t.Fatalf("refresh mv_provider_escrow_balance: %v", err)
	}
}

func insertEscrowDeposit(t *testing.T, db *sql.DB, providerID uuid.UUID, amountPaise int64, idemKey string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO escrow_events (provider_id, event_type, amount_paise, idempotency_key) VALUES ($1, 'DEPOSIT', $2, $3)`,
		providerID, amountPaise, idemKey)
	if err != nil {
		t.Fatalf("insert escrow deposit: %v", err)
	}
}

func insertAuditPeriod(t *testing.T, db *sql.DB, providerID uuid.UUID, start, end time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(`INSERT INTO audit_periods (provider_id, period_start, period_end) VALUES ($1, $2, $3) RETURNING id`,
		providerID, start, end).Scan(&id)
	if err != nil {
		t.Fatalf("insert audit period: %v", err)
	}
	return id
}

func insertAuditReceipt(t *testing.T, db *sql.DB, providerID uuid.UUID, fileID *uuid.UUID, chunkID [32]byte, auditResult string, challengeTS time.Time) uuid.UUID {
	t.Helper()
	var nonce [33]byte
	_, _ = rand.Read(nonce[:])
	var id uuid.UUID
	var err error
	switch auditResult {
	case "PASS", "FAIL":
		// audit_receipts_response_consistency requires response_hash and
		// provider_sig set (non-null) for PASS/FAIL rows.
		var responseHash [32]byte
		var providerSig [64]byte
		_, _ = rand.Read(responseHash[:])
		_, _ = rand.Read(providerSig[:])
		err = db.QueryRow(`
			INSERT INTO audit_receipts (chunk_id, file_id, provider_id, challenge_nonce, server_challenge_ts,
			                             audit_result, response_hash, response_latency_ms, provider_sig)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 120, $8)
			RETURNING receipt_id`,
			chunkID[:], fileID, providerID, nonce[:], challengeTS, auditResult, responseHash[:], providerSig[:],
		).Scan(&id)
	default:
		err = db.QueryRow(`
			INSERT INTO audit_receipts (chunk_id, file_id, provider_id, challenge_nonce, server_challenge_ts, audit_result)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING receipt_id`,
			chunkID[:], fileID, providerID, nonce[:], challengeTS, sql.NullString{String: auditResult, Valid: auditResult != ""},
		).Scan(&id)
	}
	if err != nil {
		t.Fatalf("insert audit receipt: %v", err)
	}
	return id
}

func signRegisterRequest(t *testing.T, priv ed25519.PrivateKey, req providerRegisterRequestBody) providerRegisterRequestBody {
	t.Helper()
	sig := localcrypto.SignBytes(priv, canonicalRegisterSigningInput(req))
	req.ProviderSig = hex.EncodeToString(sig[:])
	return req
}

func signHeartbeatRequest(t *testing.T, priv ed25519.PrivateKey, req providerHeartbeatRequestBody) providerHeartbeatRequestBody {
	t.Helper()
	sig := localcrypto.SignBytes(priv, canonicalHeartbeatSigningInputAPI(req.CurrentMultiaddrs, req.Timestamp))
	req.ProviderSig = hex.EncodeToString(sig[:])
	return req
}

func signDowntimeRequest(t *testing.T, priv ed25519.PrivateKey, req providerDowntimeRequestBody) providerDowntimeRequestBody {
	t.Helper()
	sig := localcrypto.SignBytes(priv, canonicalDowntimeSigningInput(req))
	req.ProviderSig = hex.EncodeToString(sig[:])
	return req
}

func signDepartRequest(t *testing.T, priv ed25519.PrivateKey, req providerDepartRequestBody) providerDepartRequestBody {
	t.Helper()
	sig := localcrypto.SignBytes(priv, canonicalDepartSigningInput(req))
	req.ProviderSig = hex.EncodeToString(sig[:])
	return req
}

func decodeJSON[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode JSON: %v (body: %s)", err, body)
	}
	return v
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.1 — Provider Register
// ═══════════════════════════════════════════════════════════════════════

func TestProviderRegisterReturnsPendingOnboarding(t *testing.T) {
	db := openTestDB(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	phone := randPhoneForOwner()
	subject := RegistrationSubjectForPhone(phone)
	seedPendingProviderRegistration(t, db, subject, phone)

	asn := "AS12345"
	req := providerRegisterRequestBody{
		Ed25519PublicKey:  hex.EncodeToString(pub),
		DeclaredStorageGB: 100,
		City:              "Mumbai",
		Region:            "Mumbai",
		ASN:               &asn,
		InitialMultiaddrs: []string{"/ip4/203.0.113.1/udp/4001/quic-v1/p2p/12D3KooWtest1"},
	}
	req = signRegisterRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/register", bytes.NewReader(body)),
		VerifiedClaims{Subject: subject, Role: ""})
	w := httptest.NewRecorder()

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewProviderRegisterHandler(db, msPriv, config.ProductionProfile)
	h.HandleRegister(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerRegisterResponseBody](t, w.Body.Bytes())
	if resp.Status != "PENDING_ONBOARDING" {
		t.Fatalf("status = %q, want PENDING_ONBOARDING", resp.Status)
	}
	if resp.Token == "" {
		t.Fatal("expected a non-empty token")
	}
}

func TestProviderRegisterSetsProfileDrivenCooling(t *testing.T) {
	tests := []struct {
		name    string
		profile config.NetworkProfile
	}{
		{"prod_24h", config.ProductionProfile},
		{"demo_instant", config.DemoProfile},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestDB(t)
			pub, priv, _ := ed25519.GenerateKey(nil)
			phone := randPhoneForOwner()
			subject := RegistrationSubjectForPhone(phone)
			seedPendingProviderRegistration(t, db, subject, phone)

			req := providerRegisterRequestBody{
				Ed25519PublicKey:  hex.EncodeToString(pub),
				DeclaredStorageGB: 100,
				City:              "Mumbai",
				Region:            "Mumbai",
				InitialMultiaddrs: []string{"/ip4/203.0.113.1/udp/4001/quic-v1/p2p/12D3KooWtest2"},
			}
			if tc.profile.Mode != "demo" {
				asn := "AS55555"
				req.ASN = &asn
			}
			req = signRegisterRequest(t, priv, req)
			body, _ := json.Marshal(req)

			r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/register", bytes.NewReader(body)),
				VerifiedClaims{Subject: subject, Role: ""})
			w := httptest.NewRecorder()

			before := time.Now().UTC()
			_, msPriv, _ := ed25519.GenerateKey(nil)
			h := NewProviderRegisterHandler(db, msPriv, tc.profile)
			h.HandleRegister(w, r)
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
			}
			resp := decodeJSON[providerRegisterResponseBody](t, w.Body.Bytes())

			wantEarliest := before.Add(tc.profile.RazorpayCoolingPeriod)
			wantLatest := time.Now().UTC().Add(tc.profile.RazorpayCoolingPeriod).Add(2 * time.Second)
			if resp.RazorpayCoolingUntil.Before(wantEarliest) || resp.RazorpayCoolingUntil.After(wantLatest) {
				t.Fatalf("razorpay_cooling_until = %v, want within [%v, %v]", resp.RazorpayCoolingUntil, wantEarliest, wantLatest)
			}
		})
	}
}

func TestProviderRegisterDemoModeAutoAssignsASN(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	phone := randPhoneForOwner()
	subject := RegistrationSubjectForPhone(phone)
	seedPendingProviderRegistration(t, db, subject, phone)

	req := providerRegisterRequestBody{
		Ed25519PublicKey:  hex.EncodeToString(pub),
		DeclaredStorageGB: 100,
		City:              "Mumbai",
		Region:            "Mumbai",
		InitialMultiaddrs: []string{"/ip4/203.0.113.1/udp/4001/quic-v1/p2p/12D3KooWtest3"},
		// DemoASN intentionally omitted (nil) -> must auto-assign.
	}
	req = signRegisterRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/register", bytes.NewReader(body)),
		VerifiedClaims{Subject: subject, Role: ""})
	w := httptest.NewRecorder()

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewProviderRegisterHandler(db, msPriv, config.DemoProfile)
	h.HandleRegister(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerRegisterResponseBody](t, w.Body.Bytes())

	var asn string
	if err := db.QueryRow(`SELECT asn FROM providers WHERE provider_id = $1`, resp.ProviderID).Scan(&asn); err != nil {
		t.Fatalf("query asn: %v", err)
	}
	if !demoASNPattern.MatchString(asn) {
		t.Fatalf("asn = %q, want a match for ^SIM-AS\\d+$", asn)
	}
}

func TestProviderRegisterProdModeIgnoresDemoAsn(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	phone := randPhoneForOwner()
	subject := RegistrationSubjectForPhone(phone)
	seedPendingProviderRegistration(t, db, subject, phone)

	realASN := "AS99999"
	demoASN := "SIM-AS3"
	req := providerRegisterRequestBody{
		Ed25519PublicKey:  hex.EncodeToString(pub),
		DeclaredStorageGB: 100,
		City:              "Mumbai",
		Region:            "Mumbai",
		ASN:               &realASN,
		DemoASN:           &demoASN,
		InitialMultiaddrs: []string{"/ip4/203.0.113.1/udp/4001/quic-v1/p2p/12D3KooWtest4"},
	}
	req = signRegisterRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/register", bytes.NewReader(body)),
		VerifiedClaims{Subject: subject, Role: ""})
	w := httptest.NewRecorder()

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewProviderRegisterHandler(db, msPriv, config.ProductionProfile)
	h.HandleRegister(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerRegisterResponseBody](t, w.Body.Bytes())

	var storedASN string
	if err := db.QueryRow(`SELECT asn FROM providers WHERE provider_id = $1`, resp.ProviderID).Scan(&storedASN); err != nil {
		t.Fatalf("query asn: %v", err)
	}
	if storedASN != realASN {
		t.Fatalf("asn = %q, want %q (demo_asn must be ignored in production)", storedASN, realASN)
	}
}

func TestProviderRegisterInvalidSignatureRejected(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil) // deliberately never sign with the matching private key
	phone := randPhoneForOwner()
	subject := RegistrationSubjectForPhone(phone)
	seedPendingProviderRegistration(t, db, subject, phone)

	asn := "AS12345"
	req := providerRegisterRequestBody{
		Ed25519PublicKey:  hex.EncodeToString(pub),
		DeclaredStorageGB: 100,
		City:              "Mumbai",
		Region:            "Mumbai",
		ASN:               &asn,
		InitialMultiaddrs: []string{"/ip4/203.0.113.1/udp/4001/quic-v1/p2p/12D3KooWtest5"},
		ProviderSig:       hex.EncodeToString(make([]byte, 64)), // all-zero, definitely invalid
	}
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/register", bytes.NewReader(body)),
		VerifiedClaims{Subject: subject, Role: ""})
	w := httptest.NewRecorder()

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewProviderRegisterHandler(db, msPriv, config.ProductionProfile)
	h.HandleRegister(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", w.Code, w.Body.String())
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.2 — Provider Heartbeat
// ═══════════════════════════════════════════════════════════════════════

func TestHeartbeatUpdatesMultiaddrsAndTimestamp(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "VETTING")

	req := providerHeartbeatRequestBody{
		ProviderID:        providerID,
		CurrentMultiaddrs: []string{"/ip4/198.51.100.7/udp/4001/quic-v1/p2p/12D3KooWheartbeat"},
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		DaemonVersion:     "v1.0.0",
	}
	req = signHeartbeatRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/heartbeat", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewProviderHeartbeatHandler(db, msPriv)
	h.HandleHeartbeat(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var multiaddrsJSON []byte
	var lastHeartbeat sql.NullTime
	if err := db.QueryRow(`SELECT last_known_multiaddrs, last_heartbeat_ts FROM providers WHERE provider_id = $1`, providerID).
		Scan(&multiaddrsJSON, &lastHeartbeat); err != nil {
		t.Fatalf("query provider: %v", err)
	}
	if !lastHeartbeat.Valid {
		t.Fatal("last_heartbeat_ts was not set")
	}
	var storedAddrs []string
	_ = json.Unmarshal(multiaddrsJSON, &storedAddrs)
	if len(storedAddrs) != 1 || storedAddrs[0] != req.CurrentMultiaddrs[0] {
		t.Fatalf("last_known_multiaddrs = %v, want %v", storedAddrs, req.CurrentMultiaddrs)
	}

	var status string
	if err := db.QueryRow(`SELECT status FROM providers WHERE provider_id = $1`, providerID).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "VETTING" {
		t.Fatalf("status = %q, want VETTING unchanged", status)
	}
}

func TestHeartbeatClearsMultiaddrStale(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "PENDING_ONBOARDING")
	future := time.Now().Add(1 * time.Hour)
	if _, err := db.Exec(`UPDATE providers SET multiaddr_stale = TRUE, promised_return_at = $2 WHERE provider_id = $1`,
		providerID, future); err != nil {
		t.Fatalf("seed stale state: %v", err)
	}

	req := providerHeartbeatRequestBody{
		ProviderID:        providerID,
		CurrentMultiaddrs: []string{"/ip4/198.51.100.8/udp/4001/quic-v1/p2p/12D3KooWheartbeat2"},
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
	}
	req = signHeartbeatRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/heartbeat", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewProviderHeartbeatHandler(db, msPriv)
	h.HandleHeartbeat(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var stale bool
	var status string
	var promisedReturn sql.NullTime
	if err := db.QueryRow(`SELECT multiaddr_stale, status, promised_return_at FROM providers WHERE provider_id = $1`, providerID).
		Scan(&stale, &status, &promisedReturn); err != nil {
		t.Fatalf("query provider: %v", err)
	}
	if stale {
		t.Fatal("multiaddr_stale still TRUE after heartbeat")
	}
	if status != "VETTING" {
		t.Fatalf("status = %q, want VETTING (first-heartbeat transition from PENDING_ONBOARDING)", status)
	}
	if promisedReturn.Valid {
		t.Fatal("promised_return_at still set after heartbeat; must be cleared on return")
	}
}

func TestHeartbeatRejectsSkewBeyondFiveMinutes(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "VETTING")

	req := providerHeartbeatRequestBody{
		ProviderID:        providerID,
		CurrentMultiaddrs: []string{"/ip4/198.51.100.9/udp/4001/quic-v1/p2p/12D3KooWheartbeat3"},
		Timestamp:         time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339),
	}
	req = signHeartbeatRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/heartbeat", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewProviderHeartbeatHandler(db, msPriv)
	h.HandleHeartbeat(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
}

func TestHeartbeatReturnsMicroserviceCountersignature(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "VETTING")

	req := providerHeartbeatRequestBody{
		ProviderID:        providerID,
		CurrentMultiaddrs: []string{"/ip4/198.51.100.10/udp/4001/quic-v1/p2p/12D3KooWheartbeat4"},
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
	}
	req = signHeartbeatRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/heartbeat", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	msPub, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewProviderHeartbeatHandler(db, msPriv)
	h.HandleHeartbeat(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerHeartbeatResponseBody](t, w.Body.Bytes())

	sigArr, ok := decodeProviderSig(resp.MicroserviceSig)
	if !ok {
		t.Fatal("microservice_sig did not decode as 128 hex chars")
	}
	var pubArr [32]byte
	copy(pubArr[:], msPub)
	if !localcrypto.VerifyBytes(pubArr, canonicalMicroserviceSigningInput(resp.ReceivedAt, providerID), sigArr) {
		t.Fatal("microservice_sig did not verify against canonicalMicroserviceSigningInput")
	}
}

func TestHeartbeatRejectsDepartedProvider(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "DEPARTED")

	req := providerHeartbeatRequestBody{
		ProviderID:        providerID,
		CurrentMultiaddrs: []string{"/ip4/198.51.100.11/udp/4001/quic-v1/p2p/12D3KooWheartbeat5"},
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
	}
	req = signHeartbeatRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/heartbeat", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	_, msPriv, _ := ed25519.GenerateKey(nil)
	h := NewProviderHeartbeatHandler(db, msPriv)
	h.HandleHeartbeat(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (FR-036), body = %s", w.Code, w.Body.String())
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.3 — Provider Status
// ═══════════════════════════════════════════════════════════════════════

func TestProviderStatusIncludesVettingFieldsWhenVetting(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "VETTING")
	firstAssignment := time.Now().Add(-48 * time.Hour)
	if _, err := db.Exec(`UPDATE providers SET first_chunk_assignment_at = $2 WHERE provider_id = $1`, providerID, firstAssignment); err != nil {
		t.Fatalf("seed first_chunk_assignment_at: %v", err)
	}

	r := withClaims(httptest.NewRequest(http.MethodGet, "/api/v1/provider/"+providerID.String()+"/status", nil),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	r.SetPathValue("provider_id", providerID.String())
	w := httptest.NewRecorder()

	h := NewProviderStatusHandler(db, config.ProductionProfile, nil)
	h.HandleStatus(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerStatusResponseBody](t, w.Body.Bytes())

	if resp.VettingChunkCap == nil || *resp.VettingChunkCap != 100*vettingChunksPerGB {
		t.Fatalf("vetting_chunk_cap = %v, want %d", resp.VettingChunkCap, 100*vettingChunksPerGB)
	}
	if resp.VettingChunksAssigned == nil {
		t.Fatal("vetting_chunks_assigned is nil, want a value when status=VETTING")
	}
	if resp.VettingEligibleAt == nil {
		t.Fatal("vetting_eligible_at is nil, want a value when status=VETTING")
	}
	wantEligible := firstAssignment.Add(config.ProductionProfile.VettingMinDuration)
	if resp.VettingEligibleAt.Sub(wantEligible).Abs() > time.Second {
		t.Fatalf("vetting_eligible_at = %v, want ~%v", resp.VettingEligibleAt, wantEligible)
	}
}

func TestProviderStatusOmitsVettingFieldsWhenActive(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	r := withClaims(httptest.NewRequest(http.MethodGet, "/api/v1/provider/"+providerID.String()+"/status", nil),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	r.SetPathValue("provider_id", providerID.String())
	w := httptest.NewRecorder()

	h := NewProviderStatusHandler(db, config.ProductionProfile, nil)
	h.HandleStatus(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerStatusResponseBody](t, w.Body.Bytes())

	if resp.VettingChunkCap != nil || resp.VettingChunksAssigned != nil || resp.VettingEligibleAt != nil {
		t.Fatalf("expected all three VETTING-only fields nil for status=ACTIVE, got cap=%v assigned=%v eligible=%v",
			resp.VettingChunkCap, resp.VettingChunksAssigned, resp.VettingEligibleAt)
	}
	// vetting_gc_pending is the one field gated on ACTIVE, not VETTING (OAS's
	// own per-field description, overriding build.md's summary sentence).
	if resp.VettingGCPending == nil {
		t.Fatal("vetting_gc_pending is nil, want non-nil (false) for status=ACTIVE")
	}
}

func TestProviderStatusNetworkModeReflectsProfile(t *testing.T) {
	tests := []struct {
		profile config.NetworkProfile
		want    string
	}{
		{config.ProductionProfile, "prod"},
		{config.DemoProfile, "demo"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			db := openTestDB(t)
			pub, _, _ := ed25519.GenerateKey(nil)
			providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

			r := withClaims(httptest.NewRequest(http.MethodGet, "/api/v1/provider/"+providerID.String()+"/status", nil),
				VerifiedClaims{Subject: providerID, Role: "provider"})
			r.SetPathValue("provider_id", providerID.String())
			w := httptest.NewRecorder()

			h := NewProviderStatusHandler(db, tc.profile, nil)
			h.HandleStatus(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
			}
			resp := decodeJSON[providerStatusResponseBody](t, w.Body.Bytes())
			if resp.NetworkMode != tc.want {
				t.Fatalf("network_mode = %q, want %q", resp.NetworkMode, tc.want)
			}
		})
	}
}

func TestProviderStatusRejectsMismatchedProvider(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	otherID := uuid.New()

	r := withClaims(httptest.NewRequest(http.MethodGet, "/api/v1/provider/"+providerID.String()+"/status", nil),
		VerifiedClaims{Subject: otherID, Role: "provider"})
	r.SetPathValue("provider_id", providerID.String())
	w := httptest.NewRecorder()

	h := NewProviderStatusHandler(db, config.ProductionProfile, nil)
	h.HandleStatus(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body.String())
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.4 — Provider Receipts
// ═══════════════════════════════════════════════════════════════════════

func TestProviderReceiptsAccessibleWhenDeparted(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "DEPARTED")
	chunkID := randChunkID(t)
	insertAuditReceipt(t, db, providerID, nil, chunkID, "PASS", time.Now())

	r := withClaims(httptest.NewRequest(http.MethodGet, "/api/v1/provider/receipts", nil),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderReceiptsHandler(db)
	h.HandleReceipts(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (FR-058: available even after DEPARTED), body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerReceiptsResponseBody](t, w.Body.Bytes())
	if len(resp.Receipts) != 1 {
		t.Fatalf("len(receipts) = %d, want 1", len(resp.Receipts))
	}
}

func TestProviderReceiptsFiltersByChunkAndResult(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	chunkA := randChunkID(t)
	chunkB := randChunkID(t)
	insertAuditReceipt(t, db, providerID, nil, chunkA, "PASS", time.Now().Add(-2*time.Hour))
	insertAuditReceipt(t, db, providerID, nil, chunkB, "FAIL", time.Now().Add(-1*time.Hour))

	q := fmt.Sprintf("/api/v1/provider/receipts?chunk_id=%s&result=PASS", hex.EncodeToString(chunkA[:]))
	r := withClaims(httptest.NewRequest(http.MethodGet, q, nil), VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderReceiptsHandler(db)
	h.HandleReceipts(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerReceiptsResponseBody](t, w.Body.Bytes())
	if len(resp.Receipts) != 1 {
		t.Fatalf("len(receipts) = %d, want 1 (filtered by chunk_id+result)", len(resp.Receipts))
	}
	if resp.Receipts[0].ChunkID != hex.EncodeToString(chunkA[:]) {
		t.Fatalf("chunk_id = %s, want %s", resp.Receipts[0].ChunkID, hex.EncodeToString(chunkA[:]))
	}
	if resp.Receipts[0].AuditResult == nil || *resp.Receipts[0].AuditResult != "PASS" {
		t.Fatalf("audit_result = %v, want PASS", resp.Receipts[0].AuditResult)
	}
}

func TestProviderReceiptsFileIDNullableForVettingChunks(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "VETTING")
	chunkID := randChunkID(t)
	insertAuditReceipt(t, db, providerID, nil, chunkID, "PASS", time.Now()) // file_id nil: vetting chunk audit

	r := withClaims(httptest.NewRequest(http.MethodGet, "/api/v1/provider/receipts", nil),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderReceiptsHandler(db)
	h.HandleReceipts(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerReceiptsResponseBody](t, w.Body.Bytes())
	if len(resp.Receipts) != 1 {
		t.Fatalf("len(receipts) = %d, want 1", len(resp.Receipts))
	}
	if resp.Receipts[0].FileID != nil {
		t.Fatalf("file_id = %v, want nil for a vetting-chunk receipt", resp.Receipts[0].FileID)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.5 — Provider Downtime
// ═══════════════════════════════════════════════════════════════════════

func TestDowntimePostAccepts0To72Hours(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	req := providerDowntimeRequestBody{PromisedReturnAt: time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)}
	req = signDowntimeRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/downtime", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDowntimeHandler(db, config.ProductionProfile)
	h.HandleAnnounce(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerDowntimeResponseBody](t, w.Body.Bytes())
	if !resp.Active {
		t.Fatal("active = false, want true")
	}
}

func TestDowntimePostRejectsPastTimestamp(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	req := providerDowntimeRequestBody{PromisedReturnAt: time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)}
	req = signDowntimeRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/downtime", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDowntimeHandler(db, config.ProductionProfile)
	h.HandleAnnounce(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", w.Code, w.Body.String())
	}
}

func TestDowntimePostRejectsSecondWindow(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	h := NewProviderDowntimeHandler(db, config.ProductionProfile)

	first := providerDowntimeRequestBody{PromisedReturnAt: time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)}
	first = signDowntimeRequest(t, priv, first)
	body1, _ := json.Marshal(first)
	r1 := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/downtime", bytes.NewReader(body1)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w1 := httptest.NewRecorder()
	h.HandleAnnounce(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, body = %s", w1.Code, w1.Body.String())
	}

	second := providerDowntimeRequestBody{PromisedReturnAt: time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339)}
	second = signDowntimeRequest(t, priv, second)
	body2, _ := json.Marshal(second)
	r2 := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/downtime", bytes.NewReader(body2)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w2 := httptest.NewRecorder()
	h.HandleAnnounce(w2, r2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("second request: status = %d, want 409, body = %s", w2.Code, w2.Body.String())
	}
}

func TestDowntimePostRejectsDepartedProvider(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "DEPARTED")

	req := providerDowntimeRequestBody{PromisedReturnAt: time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)}
	req = signDowntimeRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/downtime", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDowntimeHandler(db, config.ProductionProfile)
	h.HandleAnnounce(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 PROVIDER_DEPARTED, body = %s", w.Code, w.Body.String())
	}
}

func TestDowntimeGetLogicNotYetRoutedPendingOAS(t *testing.T) {
	db := openTestDB(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")
	future := time.Now().Add(1 * time.Hour)
	if _, err := db.Exec(`UPDATE providers SET promised_return_at = $2 WHERE provider_id = $1`, providerID, future); err != nil {
		t.Fatalf("seed promised_return_at: %v", err)
	}

	// Called directly — this handler method is intentionally NOT reachable
	// via router.go's mux (no GET path exists in openapi.yaml yet).
	r := withClaims(httptest.NewRequest(http.MethodGet, "/api/v1/provider/downtime", nil),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDowntimeHandler(db, config.ProductionProfile)
	h.HandleGetActive(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerDowntimeResponseBody](t, w.Body.Bytes())
	if !resp.Active {
		t.Fatal("active = false, want true given a seeded future promised_return_at")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.6 — Provider Depart
// ═══════════════════════════════════════════════════════════════════════

func TestProviderDepartImmediateWhenDepartAtOmitted(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	req := providerDepartRequestBody{} // depart_at omitted
	req = signDepartRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/depart", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDepartHandler(db, config.DemoProfile, payment.NewMockProvider(db))
	h.HandleDepart(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerDepartResponseBody](t, w.Body.Bytes())
	if resp.Status != "DEPARTED" {
		t.Fatalf("status = %q, want DEPARTED", resp.Status)
	}

	var dbStatus string
	var departedAt sql.NullTime
	if err := db.QueryRow(`SELECT status, departed_at FROM providers WHERE provider_id = $1`, providerID).
		Scan(&dbStatus, &departedAt); err != nil {
		t.Fatalf("query provider: %v", err)
	}
	if dbStatus != "DEPARTED" || !departedAt.Valid {
		t.Fatalf("db status = %q departed_at.Valid = %v, want DEPARTED + set", dbStatus, departedAt.Valid)
	}
}

func TestProviderDepartQueuesRepairForAllRealChunks(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	ownerID := insertTestOwnerDirect(t, db)
	fileID := insertTestFileDirect(t, db, ownerID)
	segmentID := insertTestSegmentDirect(t, db, fileID, 0)
	idx0, idx1 := 0, 1
	insertChunkAssignmentDirect(t, db, providerID, &segmentID, &idx0, "ACTIVE")
	insertChunkAssignmentDirect(t, db, providerID, &segmentID, &idx1, "ACTIVE")
	insertChunkAssignmentDirect(t, db, providerID, nil, nil, "ACTIVE") // vetting chunk: must be excluded

	req := providerDepartRequestBody{}
	req = signDepartRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/depart", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDepartHandler(db, config.DemoProfile, payment.NewMockProvider(db))
	h.HandleDepart(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerDepartResponseBody](t, w.Body.Bytes())
	if resp.RepairJobsQueued != 2 {
		t.Fatalf("repair_jobs_queued = %d, want 2 (vetting chunk excluded)", resp.RepairJobsQueued)
	}

	var jobCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM repair_jobs WHERE provider_id = $1 AND trigger_type = 'ANNOUNCED_DEPARTURE'`, providerID).
		Scan(&jobCount); err != nil {
		t.Fatalf("query repair_jobs: %v", err)
	}
	if jobCount != 2 {
		t.Fatalf("repair_jobs rows with trigger_type=ANNOUNCED_DEPARTURE = %d, want 2", jobCount)
	}
}

func TestProviderDepartReleasesProratedEscrow(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	periodStart := time.Now().Add(-15 * 24 * time.Hour)
	periodEnd := time.Now().Add(15 * 24 * time.Hour) // ~50% of the window elapsed
	insertAuditPeriod(t, db, providerID, periodStart, periodEnd)
	insertEscrowDeposit(t, db, providerID, 100000, uuid.New().String())
	refreshEscrowBalance(t)

	req := providerDepartRequestBody{}
	req = signDepartRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/depart", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDepartHandler(db, config.DemoProfile, payment.NewMockProvider(db))
	h.HandleDepart(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON[providerDepartResponseBody](t, w.Body.Bytes())

	if resp.EscrowReleasePaise < 45000 || resp.EscrowReleasePaise > 55000 {
		t.Fatalf("escrow_release_paise = %d, want ~50000 (50%% of 100000)", resp.EscrowReleasePaise)
	}

	var releaseCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM escrow_events WHERE provider_id = $1 AND event_type = 'RELEASE'`, providerID).
		Scan(&releaseCount); err != nil {
		t.Fatalf("query escrow_events: %v", err)
	}
	if releaseCount != 1 {
		t.Fatalf("RELEASE rows = %d, want 1", releaseCount)
	}
}

func TestProviderDepartUsesUnifiedReleaseIdempotencyKey(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	periodStart := time.Now().Add(-10 * 24 * time.Hour)
	periodEnd := time.Now().Add(20 * 24 * time.Hour)
	auditPeriodID := insertAuditPeriod(t, db, providerID, periodStart, periodEnd)
	insertEscrowDeposit(t, db, providerID, 100000, uuid.New().String())
	refreshEscrowBalance(t)

	departAt := time.Now().Add(1 * time.Minute).UTC().Format(time.RFC3339)
	req := providerDepartRequestBody{DepartAt: &departAt}
	req = signDepartRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/depart", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDepartHandler(db, config.DemoProfile, payment.NewMockProvider(db))
	h.HandleDepart(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	// [M10 corrections review Finding #8] the departure release path and
	// ComputeMonthlyRelease must derive the SAME idempotency key for a
	// release against the same (providerID, auditPeriodID) pair — a
	// client-supplied depart_at can no longer influence this formula, since
	// ComputeMonthlyRelease has no such input to agree with.
	wantKey := payment.ReleaseIdempotencyKey(providerID, auditPeriodID)

	var storedKey string
	if err := db.QueryRow(`SELECT idempotency_key FROM escrow_events WHERE provider_id = $1 AND event_type = 'RELEASE'`, providerID).
		Scan(&storedKey); err != nil {
		t.Fatalf("query escrow_events: %v", err)
	}
	if storedKey != wantKey {
		t.Fatalf("idempotency_key = %q, want %q (payment.ReleaseIdempotencyKey(providerID, auditPeriodID) — "+
			"the same formula ComputeMonthlyRelease uses for this exact audit period)", storedKey, wantKey)
	}
}

// TestProviderDepartMarksReleaseComputedPreventingReselection is the
// regression test for the second half of Finding #8 (M10 corrections
// review): HandleDepart previously never set audit_periods.release_computed
// on the period it released against, so ComputeMonthlyRelease's
// pendingReleaseCandidates query (WHERE release_computed = FALSE) would
// keep re-selecting this same, now-departed provider's audit period on
// every future cycle, indefinitely.
func TestProviderDepartMarksReleaseComputedPreventingReselection(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	periodStart := time.Now().Add(-10 * 24 * time.Hour)
	periodEnd := time.Now().Add(20 * 24 * time.Hour)
	auditPeriodID := insertAuditPeriod(t, db, providerID, periodStart, periodEnd)
	insertEscrowDeposit(t, db, providerID, 100000, uuid.New().String())
	refreshEscrowBalance(t)

	req := providerDepartRequestBody{}
	req = signDepartRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/depart", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDepartHandler(db, config.DemoProfile, payment.NewMockProvider(db))
	h.HandleDepart(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var releaseComputed bool
	if err := db.QueryRow(`SELECT release_computed FROM audit_periods WHERE id = $1`, auditPeriodID).Scan(&releaseComputed); err != nil {
		t.Fatalf("query audit_periods: %v", err)
	}
	if !releaseComputed {
		t.Error("release_computed = false after HandleDepart, want true (otherwise ComputeMonthlyRelease " +
			"re-selects this departed provider's audit period on every future cycle, forever)")
	}
}

// TestProviderDepartRaceWithMonthlyReleaseIsIdempotent is the regression
// test for the race Finding #8 describes: if ComputeMonthlyRelease already
// released against this exact audit period (e.g. a scheduler race, or a
// retry) before HandleDepart runs, HandleDepart's own release attempt must
// be a no-op — not a duplicate RELEASE row, and not a user-facing error —
// because both paths now derive the identical idempotency key and rely on
// the SAME mechanism InsertEscrowEvent's callers already use for retries:
// the database's UNIQUE(idempotency_key) constraint, not application
// logic, is what prevents the duplicate.
func TestProviderDepartRaceWithMonthlyReleaseIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "ACTIVE")

	periodStart := time.Now().Add(-10 * 24 * time.Hour)
	periodEnd := time.Now().Add(20 * 24 * time.Hour)
	auditPeriodID := insertAuditPeriod(t, db, providerID, periodStart, periodEnd)
	insertEscrowDeposit(t, db, providerID, 100000, uuid.New().String())
	refreshEscrowBalance(t)

	// Simulate ComputeMonthlyRelease having already won this exact race,
	// inserting a RELEASE row under the SAME key HandleDepart will now
	// independently derive for the same (providerID, auditPeriodID) pair.
	racingKey := payment.ReleaseIdempotencyKey(providerID, auditPeriodID)
	if err := payment.InsertEscrowEvent(context.Background(), db, providerID, payment.EscrowRelease, 30000, racingKey, &auditPeriodID); err != nil {
		t.Fatalf("seed racing RELEASE: %v", err)
	}

	req := providerDepartRequestBody{}
	req = signDepartRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/depart", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDepartHandler(db, config.DemoProfile, payment.NewMockProvider(db))
	h.HandleDepart(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s (a raced release must be an idempotent no-op, not a user-facing error)",
			w.Code, w.Body.String())
	}

	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM escrow_events WHERE provider_id = $1 AND event_type = 'RELEASE'`, providerID).
		Scan(&rows); err != nil {
		t.Fatalf("count escrow_events: %v", err)
	}
	if rows != 1 {
		t.Errorf("RELEASE rows after the race = %d, want exactly 1 (the DB's UNIQUE(idempotency_key) "+
			"constraint, not application logic, must be what prevents a second row)", rows)
	}
}

func TestProviderDepartRejectsAlreadyDeparted(t *testing.T) {
	db := openTestDB(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	providerID := insertTestProviderDirect(t, db, pub, "DEPARTED")

	req := providerDepartRequestBody{}
	req = signDepartRequest(t, priv, req)
	body, _ := json.Marshal(req)

	r := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/provider/depart", bytes.NewReader(body)),
		VerifiedClaims{Subject: providerID, Role: "provider"})
	w := httptest.NewRecorder()

	h := NewProviderDepartHandler(db, config.DemoProfile, payment.NewMockProvider(db))
	h.HandleDepart(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body.String())
	}
}
