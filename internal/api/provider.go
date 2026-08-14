// Package api is declared in doc.go.
// This file implements build.md Milestone 11 Phase 11.6's six provider REST
// endpoints: register (11.6.1), heartbeat (11.6.2), status (11.6.3),
// receipts (11.6.4), downtime (11.6.5), and depart (11.6.6).
//
// [Decision — signing input construction] Every provider_sig / microservice_sig
// in this file is built as a hand-constructed, fixed-field-order byte
// sequence via canonicalSigningObject below — never via encoding/json.Marshal
// on a struct or map — per IC §3.2's SIGNING_INPUT_RULE (internal/crypto's
// own doc comment: "JSON serialisation MUST NOT be used for signing inputs").
// This mirrors internal/p2p/heartbeat.go's canonicalHeartbeatSigningInput,
// which this file's heartbeat handler must byte-for-byte match (it is the
// verifier for that exact function's output).
//
// [Decision — provider_sig encoding] hex, not base64: this matches OAS's
// Ed25519Signature schema (pattern `^[0-9a-f]{128}$`) and
// internal/api/token_refresh.go's verifyProviderSig (Phase 11.4, same
// package, whose own header comment calls its body-signature convention
// "identical to every other provider_sig in this system"). This is used
// uniformly for register, heartbeat, downtime, and depart below.
//
// [FLAGGED — cross-package bug, not fixed here] internal/p2p/heartbeat.go's
// doHeartbeat base64-encodes provider_sig
// (base64.StdEncoding.EncodeToString), and internal/p2p/heartbeat_test.go
// asserts that encoding. This directly contradicts the hex convention above
// and used by every other provider_sig in the system. Changing heartbeat.go
// would fix real-world interop but breaks its existing, currently-passing
// test — a cross-package, cross-milestone conflict between two already-shipped
// pieces of code, not a simple missing-prerequisite gap. This file's
// HeartbeatHandler decodes provider_sig as hex (matching OAS + the
// established server-side convention); the daemon-side encoding needs a
// follow-up fix (and its test updated) before the two will actually
// interoperate. Flagged rather than silently patched: it touches a
// different, already-tested package outside this session's file list.
//
// [FLAGGED — schema addition] providers.promised_return_at did not exist in
// data-model.md §4.2 or migrations/001_initial_schema.sql before this
// session, despite interface-contracts.md §9 already listing an "UPDATE
// promised_return_at" row as if it did. Added to migrations/generator.go the
// same way last_token_refresh_at was added mid-build for Session 11.4.3.
//
// [REF: OAS paths.'/api/v1/provider/*', IC §3.2, IC §9, ADR-005, ADR-007,
// ADR-014, ADR-030, FR-024..FR-036, FR-058, FR-068, build.md Phase 11.6]

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	localcrypto "github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/payment"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/repair"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/scoring"
)

// A named constant for decodeReceiptsCursor
const receiptCursorParts = 2

// ── Shared signing-input helpers ─────────────────────────────────────────

// signingField is one entry of a canonical signing object: a JSON object key
// paired with its already-JSON-encoded value. Order is dictated entirely by
// the caller's slice order, never by map/struct iteration.
type signingField struct {
	key   string
	value string // pre-encoded JSON value, e.g. `"Mumbai"` or `42` or `["a","b"]`
}

// canonicalSigningObject builds `{"key1":value1,"key2":value2,...}` from an
// explicit, caller-ordered field list. See the file header's "signing input
// construction" note: this is the fixed-layout replacement for
// encoding/json.Marshal(map[string]any{...}), which this package (per
// internal/crypto's SIGNING_INPUT_RULE) must not use for signing inputs.
func canonicalSigningObject(fields ...signingField) []byte {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, _ := json.Marshal(f.key) // string marshal never errors
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.WriteString(f.value)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// jstr JSON-encodes a bare string value for use as a signingField.value.
// json.Marshal on a string never returns an error (invalid UTF-8 is replaced,
// never rejected), so the error is safely discarded.
func jstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// jstrArray JSON-encodes a []string as a compact, comma-joined array literal
// for use as a signingField.value.
func jstrArray(ss []string) string {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, s := range ss {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(jstr(s))
	}
	buf.WriteByte(']')
	return buf.String()
}

// decodeProviderSig hex-decodes a provider_sig (or microservice_sig) field
// into the [64]byte crypto.VerifyBytes/SignBytes expects. See file header:
// hex, not base64, is this system's established server-side convention.
func decodeProviderSig(sigHex string) (sig [64]byte, ok bool) {
	raw, err := hex.DecodeString(sigHex)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return sig, false
	}
	copy(sig[:], raw)
	return sig, true
}

// decodeEd25519PublicKeyHex hex-decodes an Ed25519PublicKey field (OAS:
// `^[0-9a-f]{64}$`) into the [32]byte crypto.VerifyBytes expects.
func decodeEd25519PublicKeyHex(keyHex string) (key [32]byte, ok bool) {
	raw, err := hex.DecodeString(keyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return key, false
	}
	copy(key[:], raw)
	return key, true
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.1 — POST /api/v1/provider/register
// ═══════════════════════════════════════════════════════════════════════

var (
	demoASNPattern = regexp.MustCompile(`^SIM-AS\d+$`)
	prodASNPattern = regexp.MustCompile(`^(AS\d+|SIM-AS\d+)$`)

	validProviderRegions = map[string]bool{
		"Delhi NCR": true, "Mumbai": true, "Bangalore": true, "Hyderabad": true,
		"Chennai": true, "Kolkata": true, "Pune": true, "Ahmedabad": true, "Other": true,
	}
)

const (
	minDeclaredStorageGB = 10
	maxDeclaredStorageGB = 100000
	minMultiaddrs        = 1
	maxMultiaddrs        = 8
	minMultiaddrLen      = 10
	maxMultiaddrLen      = 512
	minCityLen           = 2
	maxCityLen           = 100
)

type providerRegisterRequestBody struct {
	Ed25519PublicKey  string   `json:"ed25519_public_key"`
	DeclaredStorageGB int      `json:"declared_storage_gb"`
	City              string   `json:"city"`
	Region            string   `json:"region"`
	ASN               *string  `json:"asn"`      // optional per OAS (not in its required list)
	DemoASN           *string  `json:"demo_asn"` // optional, nullable; demo mode only
	InitialMultiaddrs []string `json:"initial_multiaddrs"`
	ProviderSig       string   `json:"provider_sig"`
}

type providerRegisterResponseBody struct {
	ProviderID           uuid.UUID `json:"provider_id"`
	Status               string    `json:"status"`
	Token                string    `json:"token"`
	RazorpayCoolingUntil time.Time `json:"razorpay_cooling_until"`
	// StorageAdvisoryGB: NFR-044's per-provider chunk storage ceiling
	// advisory (build.md Phase 11.11) — see upload.go's
	// activeChunkStorageCeilingGB for why this is a single, uniform value
	// today rather than genuinely per-provider.
	StorageAdvisoryGB int `json:"storage_advisory_gb"`
}

// canonicalRegisterSigningInput builds the signing input for provider_sig:
// every other field in the request, in alphabetical key order, with asn and
// demo_asn included only when the client actually sent them (nil pointer =
// absent from the original JSON body = excluded here, matching OAS's "all
// other fields in this request body").
func canonicalRegisterSigningInput(req providerRegisterRequestBody) []byte {
	var fields []signingField
	if req.ASN != nil {
		fields = append(fields, signingField{"asn", jstr(*req.ASN)})
	}
	fields = append(fields, signingField{"city", jstr(req.City)})
	fields = append(fields, signingField{"declared_storage_gb", strconv.Itoa(req.DeclaredStorageGB)})
	if req.DemoASN != nil {
		fields = append(fields, signingField{"demo_asn", jstr(*req.DemoASN)})
	}
	fields = append(fields, signingField{"ed25519_public_key", jstr(req.Ed25519PublicKey)})
	fields = append(fields, signingField{"initial_multiaddrs", jstrArray(req.InitialMultiaddrs)})
	fields = append(fields, signingField{"region", jstr(req.Region)})
	return canonicalSigningObject(fields...)
}

// ProviderRegisterHandler serves POST /api/v1/provider/register (FR-024).
type ProviderRegisterHandler struct {
	db         *sql.DB
	signingKey ed25519.PrivateKey
	profile    config.NetworkProfile
}

func NewProviderRegisterHandler(db *sql.DB, signingKey ed25519.PrivateKey, profile config.NetworkProfile) *ProviderRegisterHandler {
	return &ProviderRegisterHandler{db: db, signingKey: signingKey, profile: profile}
}

// HandleRegister serves POST /api/v1/provider/register. Requires a
// registration-role bearer token (bearerAny — see router.go), the same token
// type OTP verify hands a new entity, mirroring ownerRegisterHandler's
// pattern exactly (RecoverPendingRegistration / DeletePendingRegistration).
func (h *ProviderRegisterHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}

	var req providerRegisterRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}

	if field, msg, ok := validateRegisterRequest(req, h.profile); !ok {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, msg, nil, field, nil)
		return
	}

	pubKeyArr, ok := decodeEd25519PublicKeyHex(req.Ed25519PublicKey)
	if !ok {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "ed25519_public_key must be 64 lowercase hex characters", nil, "ed25519_public_key", nil)
		return
	}
	sigArr, ok := decodeProviderSig(req.ProviderSig)
	if !ok {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "provider_sig must be 128 lowercase hex characters", nil, "provider_sig", nil)
		return
	}
	if !localcrypto.VerifyBytes(pubKeyArr, canonicalRegisterSigningInput(req), sigArr) {
		WriteError(w, http.StatusUnauthorized, ErrInvalidBodySignature, "invalid provider_sig", nil, "", nil)
		return
	}

	phoneNumber, err := RecoverPendingRegistration(ctx, h.db, claims.Subject)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "registration token expired or unknown", nil, "", nil)
		return
	}

	finalASN, field, msg, ok := h.resolveASN(ctx, req)
	if !ok {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, msg, nil, field, nil)
		return
	}

	multiaddrsJSON, err := json.Marshal(req.InitialMultiaddrs)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to encode multiaddrs", nil, "", nil)
		return
	}

	// razorpay_cooling_until = NOW() + profile.RazorpayCoolingPeriod, set
	// directly at registration per this session's own task text ("never
	// hardcoded 24h — MVP §5.4"). data-model.md §8.3 describes this column
	// as set later, on the Razorpay webhook; build.md's explicit instruction
	// for this session is followed here, matching this project's established
	// precedent of build.md's operative instructions taking priority over a
	// docs comment describing a different (and, for this session, unbuilt)
	// mechanism. Actually creating the Razorpay Route Linked Account (FR-025)
	// has no hook in payment.PaymentProvider's current interface — that
	// remains a downstream gap, not something this handler can invoke.
	razorpayCoolingUntil := time.Now().UTC().Add(h.profile.RazorpayCoolingPeriod)

	var providerID uuid.UUID
	var status string
	err = h.db.QueryRowContext(ctx, `
		INSERT INTO providers
			(phone_number, ed25519_public_key, declared_storage_gb, city, region, asn,
			 last_known_multiaddrs, razorpay_cooling_until)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING provider_id, status`,
		phoneNumber, pubKeyArr[:], req.DeclaredStorageGB, req.City, req.Region, finalASN,
		multiaddrsJSON, razorpayCoolingUntil,
	).Scan(&providerID, &status)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			WriteError(w, http.StatusConflict, ErrPhoneAlreadyRegistered, "phone number already registered", nil, "", nil)
			return
		}
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to create provider", nil, "", nil)
		return
	}

	// Non-fatal cleanup, mirroring ownerRegisterHandler exactly: the
	// provider row is already committed; a stale pending_registrations row
	// expires on its own via expires_at even if this delete fails.
	_ = DeletePendingRegistration(ctx, h.db, claims.Subject)

	token, err := IssueJWT(h.signingKey, providerID, "provider", ProviderTokenTTL)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "token issuance failed", nil, "", nil)
		return
	}

	resp := providerRegisterResponseBody{
		ProviderID:           providerID,
		Status:               status,
		Token:                token,
		RazorpayCoolingUntil: razorpayCoolingUntil,
		StorageAdvisoryGB:    activeChunkStorageCeilingGB(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// validateRegisterRequest applies the field-level constraints declared in
// OAS's ProviderRegisterRequest schema. Returns the offending field name and
// message on the first violation found.
func validateRegisterRequest(req providerRegisterRequestBody, profile config.NetworkProfile) (field, msg string, ok bool) {
	if req.DeclaredStorageGB < minDeclaredStorageGB || req.DeclaredStorageGB > maxDeclaredStorageGB {
		return "declared_storage_gb", fmt.Sprintf("must be between %d and %d", minDeclaredStorageGB, maxDeclaredStorageGB), false
	}
	if len(req.City) < minCityLen || len(req.City) > maxCityLen {
		return "city", fmt.Sprintf("must be between %d and %d characters", minCityLen, maxCityLen), false
	}
	if !validProviderRegions[req.Region] {
		return "region", "must be one of the declared metro regions", false
	}
	if len(req.InitialMultiaddrs) < minMultiaddrs || len(req.InitialMultiaddrs) > maxMultiaddrs {
		return "initial_multiaddrs", fmt.Sprintf("must supply between %d and %d multiaddrs", minMultiaddrs, maxMultiaddrs), false
	}
	for _, a := range req.InitialMultiaddrs {
		if len(a) < minMultiaddrLen || len(a) > maxMultiaddrLen {
			return "initial_multiaddrs", fmt.Sprintf("each multiaddr must be between %d and %d characters", minMultiaddrLen, maxMultiaddrLen), false
		}
	}
	if req.ASN != nil && profile.Mode != "demo" && !prodASNPattern.MatchString(*req.ASN) {
		return "asn", `must match ^(AS\d+|SIM-AS\d+)$`, false
	}
	if req.DemoASN != nil && !demoASNPattern.MatchString(*req.DemoASN) {
		return "demo_asn", `must match ^SIM-AS\d+$`, false
	}
	// [FLAGGED] OAS does not list "asn" as required, but providers.asn is
	// NOT NULL and there is no production fallback mechanism to derive it.
	// Treated as effectively required in production mode (demo mode always
	// resolves an ASN via resolveASN below, regardless of this field).
	if profile.Mode != "demo" && (req.ASN == nil || strings.TrimSpace(*req.ASN) == "") {
		return "asn", "required in production mode", false
	}
	return "", "", true
}

// resolveASN implements FR-068: demo mode accepts demo_asn (overriding
// whatever asn carries) or, if omitted, auto-assigns the least-used
// SIM-AS{1..profile.MinDistinctASNs} value — a round-robin-by-usage
// interpretation of "the next available synthetic ASN from the pool",
// spreading new demo providers across the pool rather than clustering them
// on SIM-AS1. Production mode passes req.ASN through unchanged (already
// validated by validateRegisterRequest).
func (h *ProviderRegisterHandler) resolveASN(ctx context.Context, req providerRegisterRequestBody) (asn, field, msg string, ok bool) {
	if h.profile.Mode != "demo" {
		if req.ASN != nil {
			return *req.ASN, "", "", true
		}
		return "", "", "", true // unreachable given validateRegisterRequest's production check
	}
	if req.DemoASN != nil {
		return *req.DemoASN, "", "", true
	}
	assigned, err := assignDemoASN(ctx, h.db, h.profile.MinDistinctASNs)
	if err != nil {
		return "", "demo_asn", "failed to auto-assign a synthetic ASN", false
	}
	return assigned, "", "", true
}

// assignDemoASN picks the least-used value in the pool SIM-AS1..SIM-AS{n},
// defaulting to SIM-AS1 when the pool is entirely unused so far.
func assignDemoASN(ctx context.Context, db *sql.DB, n int) (string, error) {
	if n <= 0 {
		n = 1
	}
	usage := make(map[string]int, n)
	for i := 1; i <= n; i++ {
		usage[fmt.Sprintf("SIM-AS%d", i)] = 0
	}
	rows, err := db.QueryContext(ctx, `SELECT asn, COUNT(*) FROM providers WHERE asn ~ '^SIM-AS[0-9]+$' GROUP BY asn`)
	if err != nil {
		return "", fmt.Errorf("api: assignDemoASN: query usage: %w", err)
	}

	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("assignDemoASN: close rows", "error", err)
		}
	}()

	for rows.Next() {
		var asn string
		var count int
		if err := rows.Scan(&asn, &count); err != nil {
			return "", fmt.Errorf("api: assignDemoASN: scan: %w", err)
		}
		if _, tracked := usage[asn]; tracked {
			usage[asn] = count
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("api: assignDemoASN: rows: %w", err)
	}

	keys := make([]string, 0, len(usage))
	for k := range usage {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	best := keys[0]
	for _, k := range keys {
		if usage[k] < usage[best] {
			best = k
		}
	}
	return best, nil
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.2 — POST /api/v1/provider/heartbeat
// ═══════════════════════════════════════════════════════════════════════

const heartbeatTimestampSkew = 5 * time.Minute

type providerHeartbeatRequestBody struct {
	ProviderID        uuid.UUID `json:"provider_id"`
	CurrentMultiaddrs []string  `json:"current_multiaddrs"`
	Timestamp         string    `json:"timestamp"`
	DaemonVersion     string    `json:"daemon_version"`
	ProviderSig       string    `json:"provider_sig"`
}

type providerHeartbeatResponseBody struct {
	ReceivedAt      time.Time `json:"received_at"`
	MicroserviceSig string    `json:"microservice_sig"`
}

// canonicalHeartbeatSigningInputAPI MUST byte-for-byte match
// internal/p2p.canonicalHeartbeatSigningInput (this handler is that
// function's verifier). Duplicated rather than imported: the p2p helper is
// unexported, and internal/api importing internal/p2p purely for one small
// hand-built byte-sequence function was judged not worth the cross-package
// coupling — unlike internal/repair.EnqueueRepairForRealChunks (Session
// 11.6.6), which is genuinely large, actively shared logic.
func canonicalHeartbeatSigningInputAPI(multiaddrs []string, timestamp string) []byte {
	return canonicalSigningObject(
		signingField{"current_multiaddrs", jstrArray(multiaddrs)},
		signingField{"timestamp", jstr(timestamp)},
	)
}

// canonicalMicroserviceSigningInput builds the signing input for
// microservice_sig: {"received_at":...,"provider_id":...}. This literal
// field order (received_at before provider_id) is written identically in
// both the OAS description and this session's build.md task text, despite
// both also saying "sorted keys" — true alphabetical order would put
// provider_id first. Since this is a brand-new signature with no existing
// counterpart implementation to match, the explicit, twice-repeated literal
// order is followed rather than a stricter reading of "sorted."
func canonicalMicroserviceSigningInput(receivedAt time.Time, providerID uuid.UUID) []byte {
	return canonicalSigningObject(
		signingField{"received_at", jstr(receivedAt.UTC().Format(time.RFC3339))},
		signingField{"provider_id", jstr(providerID.String())},
	)
}

// ProviderHeartbeatHandler serves POST /api/v1/provider/heartbeat.
type ProviderHeartbeatHandler struct {
	db         *sql.DB
	signingKey ed25519.PrivateKey // microservice's own identity key (same keypair as JWT signing)
}

func NewProviderHeartbeatHandler(db *sql.DB, signingKey ed25519.PrivateKey) *ProviderHeartbeatHandler {
	return &ProviderHeartbeatHandler{db: db, signingKey: signingKey}
}

func (h *ProviderHeartbeatHandler) HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}

	var req providerHeartbeatRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	if req.ProviderID != claims.Subject {
		WriteError(w, http.StatusForbidden, ErrUnauthorized, "provider_id does not match the JWT sub claim", nil, "", nil)
		return
	}

	requestTimestamp, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "timestamp must be ISO 8601", nil, "timestamp", nil)
		return
	}
	if absDuration(time.Since(requestTimestamp)) > heartbeatTimestampSkew {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "timestamp skew exceeds 5 minutes", nil, "timestamp", nil)
		return
	}

	var rawKey []byte
	var status string
	err = h.db.QueryRowContext(ctx, `SELECT ed25519_public_key, status FROM providers WHERE provider_id = $1`, req.ProviderID).
		Scan(&rawKey, &status)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "unknown provider", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "provider lookup failed", nil, "", nil)
		return
	}
	// FR-036: a departed provider reconnecting (sending a heartbeat) gets
	// 403, enforced here per internal/repair/departure.go's own downstream
	// note naming this exact check.
	if status == "DEPARTED" {
		WriteError(w, http.StatusForbidden, ErrProviderDeparted, "provider has departed", nil, "", nil)
		return
	}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], rawKey)

	sigArr, ok := decodeProviderSig(req.ProviderSig)
	if !ok {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "provider_sig must be 128 lowercase hex characters", nil, "provider_sig", nil)
		return
	}
	signingInput := canonicalHeartbeatSigningInputAPI(req.CurrentMultiaddrs, req.Timestamp)
	if !localcrypto.VerifyBytes(pubKeyArr, signingInput, sigArr) {
		WriteError(w, http.StatusUnauthorized, ErrInvalidBodySignature, "invalid provider_sig", nil, "", nil)
		return
	}

	multiaddrsJSON, err := json.Marshal(req.CurrentMultiaddrs)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to encode multiaddrs", nil, "", nil)
		return
	}

	// FR-026: advance PENDING_ONBOARDING -> VETTING on first successful
	// heartbeat. promised_return_at is cleared here too (IC §9: "cleared on
	// return heartbeat or overrun") — receiving any heartbeat means the
	// provider is back, ending any open downtime window early.
	_, err = h.db.ExecContext(ctx, `
		UPDATE providers
		SET last_heartbeat_ts = NOW(),
		    last_known_multiaddrs = $2,
		    multiaddr_stale = FALSE,
		    promised_return_at = NULL,
		    status = CASE WHEN status = 'PENDING_ONBOARDING' THEN 'VETTING' ELSE status END
		WHERE provider_id = $1`,
		req.ProviderID, multiaddrsJSON,
	)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to record heartbeat", nil, "", nil)
		return
	}

	receivedAt := time.Now().UTC()
	microserviceSig := localcrypto.SignBytes(h.signingKey, canonicalMicroserviceSigningInput(receivedAt, req.ProviderID))

	resp := providerHeartbeatResponseBody{
		ReceivedAt:      receivedAt,
		MicroserviceSig: hex.EncodeToString(microserviceSig[:]),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.3 — GET /api/v1/provider/{provider_id}/status
// ═══════════════════════════════════════════════════════════════════════

type providerStatusResponseBody struct {
	ProviderID             uuid.UUID  `json:"provider_id"`
	Status                 string     `json:"status"`
	Region                 string     `json:"region"`
	ASN                    string     `json:"asn"`
	ConsecutiveAuditPasses int        `json:"consecutive_audit_passes"`
	Score24h               *float64   `json:"score_24h"`
	Score7d                *float64   `json:"score_7d"`
	Score30d               *float64   `json:"score_30d"`
	ScoreComposite         *float64   `json:"score_composite"`
	PendingEarningsPaise   int64      `json:"pending_earnings_paise"`
	HeldEarningsPaise      int64      `json:"held_earnings_paise"`
	LastHeartbeatTS        *time.Time `json:"last_heartbeat_ts"`
	MultiaddrStale         bool       `json:"multiaddr_stale"`
	StoredChunks           int        `json:"stored_chunks"`
	P95ThroughputKbps      float64    `json:"p95_throughput_kbps"`
	AcceleratedReaudit     bool       `json:"accelerated_reaudit"`
	FirstChunkAssignmentAt *time.Time `json:"first_chunk_assignment_at"`
	VettingChunksAssigned  *int       `json:"vetting_chunks_assigned"`
	VettingChunkCap        *int       `json:"vetting_chunk_cap"`
	VettingEligibleAt      *time.Time `json:"vetting_eligible_at"`
	VettingGCPending       *bool      `json:"vetting_gc_pending"`
	NetworkMode            string     `json:"network_mode"`
	// StorageAdvisoryGB: NFR-044's per-provider chunk storage ceiling
	// advisory (build.md Phase 11.11) — see upload.go's
	// activeChunkStorageCeilingGB for why this is a single, uniform value
	// today rather than genuinely per-provider.
	StorageAdvisoryGB int `json:"storage_advisory_gb"`
}

// vettingChunksPerGB is ADR-030's synthetic vetting chunk cap formula:
// floor(declared_storage_gb * 400).
const vettingChunksPerGB = 400

// ProviderStatusHandler serves GET /api/v1/provider/{provider_id}/status.
type ProviderStatusHandler struct {
	db      *sql.DB
	profile config.NetworkProfile
	payment payment.PaymentProvider
}

func NewProviderStatusHandler(db *sql.DB, profile config.NetworkProfile, pp payment.PaymentProvider) *ProviderStatusHandler {
	return &ProviderStatusHandler{db: db, profile: profile, payment: pp}
}

func (h *ProviderStatusHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}
	providerID, err := uuid.Parse(r.PathValue("provider_id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "provider_id must be a UUID", nil, "provider_id", nil)
		return
	}
	// A provider may only view its own status — mirrors
	// ownerBalanceHandler's identical path-vs-claims.Subject check exactly.
	if providerID != claims.Subject {
		WriteError(w, http.StatusForbidden, ErrUnauthorized, "provider_id does not match the JWT sub claim", nil, "", nil)
		return
	}

	var (
		status                 string
		region, asn            string
		consecutiveAuditPasses int
		lastHeartbeatTS        sql.NullTime
		multiaddrStale         bool
		p95ThroughputKbps      sql.NullFloat64
		acceleratedReaudit     bool
		firstChunkAssignmentAt sql.NullTime
	)
	err = h.db.QueryRowContext(ctx, `
		SELECT p.status, p.region, p.asn, p.consecutive_audit_passes, p.last_heartbeat_ts,
		       p.multiaddr_stale, p.p95_throughput_kbps, p.accelerated_reaudit,
		       p.first_chunk_assignment_at
		FROM providers p
		WHERE p.provider_id = $1`, providerID,
	).Scan(&status, &region, &asn, &consecutiveAuditPasses, &lastHeartbeatTS,
		&multiaddrStale, &p95ThroughputKbps, &acceleratedReaudit, &firstChunkAssignmentAt)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusNotFound, ErrNotFound, "provider not found", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "provider lookup failed", nil, "", nil)
		return
	}

	var storedChunks int
	if err := h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM chunk_assignments WHERE provider_id = $1 AND status = 'ACTIVE'`, providerID,
	).Scan(&storedChunks); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "chunk count failed", nil, "", nil)
		return
	}

	// p95_throughput_kbps: application substitutes the pool median when
	// this provider has no samples yet — the providers.p95_throughput_kbps
	// column's own comment already specifies this substitution; it is not a
	// judgment call introduced here.
	throughput := p95ThroughputKbps.Float64
	if !p95ThroughputKbps.Valid {
		var median sql.NullFloat64
		if err := h.db.QueryRowContext(ctx,
			`SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY p95_throughput_kbps) FROM providers WHERE p95_throughput_kbps IS NOT NULL`,
		).Scan(&median); err == nil && median.Valid {
			throughput = median.Float64
		}
	}

	// pending_earnings_paise / held_earnings_paise: the ledger
	// (mv_provider_escrow_balance / payment.GetBalance) tracks a single
	// running balance and has no mechanism distinguishing a rolled-forward
	// partial-release remainder ("held") from freshly-accrued,
	// not-yet-processed earnings ("pending") — both live in the same
	// figure. [FLAGGED] pending_earnings_paise is reported as the current
	// balance (accurate: it genuinely has not been released yet);
	// held_earnings_paise is always 0 pending a ledger enhancement that can
	// actually separate the two, rather than fabricating a split the data
	// does not support.
	var pendingEarnings int64
	if h.payment != nil {
		pendingEarnings, _ = h.payment.GetBalance(ctx, providerID) // best-effort; 0 on error
	}

	resp := providerStatusResponseBody{
		ProviderID:             providerID,
		Status:                 status,
		Region:                 region,
		ASN:                    asn,
		ConsecutiveAuditPasses: consecutiveAuditPasses,
		PendingEarningsPaise:   pendingEarnings,
		HeldEarningsPaise:      0,
		MultiaddrStale:         multiaddrStale,
		StoredChunks:           storedChunks,
		P95ThroughputKbps:      throughput,
		AcceleratedReaudit:     acceleratedReaudit,
		NetworkMode:            h.profile.Mode,
		StorageAdvisoryGB:      activeChunkStorageCeilingGB(),
	}
	if lastHeartbeatTS.Valid {
		resp.LastHeartbeatTS = &lastHeartbeatTS.Time
	}
	if firstChunkAssignmentAt.Valid {
		resp.FirstChunkAssignmentAt = &firstChunkAssignmentAt.Time
	}

	// Milestone 8 corrections session: this used to be its own independent
	// LEFT JOIN mv_provider_scores query, scanned into four sql.NullFloat64
	// and copied across with four .Valid checks — a second, subtly
	// out-of-sync implementation of exactly what scoring.GetScore already
	// does. Folded into one coordinated call, now that GetScore's own
	// NULL-vs-zero handling is fixed (see score.go) and actually gives this
	// handler the real nullable semantics openapi.yaml's nullable: true
	// requires, rather than the false-0.0-on-error/no-history behavior the
	// standalone query silently had before.
	score, err := scoring.GetScore(ctx, h.db, providerID)
	switch {
	case errors.Is(err, scoring.ErrProviderNotFound):
		// No audit history yet: all four score_* fields stay nil in the
		// response, exactly as the old LEFT JOIN's all-NULL row did for a
		// provider absent from mv_provider_scores entirely.
	case err != nil:
		WriteError(w, http.StatusInternalServerError, ErrInternal, "score lookup failed", nil, "", nil)
		return
	default:
		if score.HasScore24h {
			v := score.Score24h
			resp.Score24h = &v
		}
		if score.HasScore7d {
			v := score.Score7d
			resp.Score7d = &v
		}
		if score.HasScore30d {
			v := score.Score30d
			resp.Score30d = &v
		}
		// score_composite has no Has* counterpart: mv_provider_scores'
		// score_composite column is COALESCE'd to 0 per missing window at
		// the view level (DM §7), so it is always a real number whenever
		// this provider has ANY row in the view at all — i.e. whenever
		// GetScore did not return ErrProviderNotFound above.
		v := score.Composite
		resp.ScoreComposite = &v
	}

	// Vetting fields: vetting_chunks_assigned / vetting_chunk_cap /
	// vetting_eligible_at only when status == 'VETTING' (build.md task text
	// AND OAS's per-field descriptions agree on these three).
	if status == "VETTING" {
		var declaredStorageGB int
		if err := h.db.QueryRowContext(ctx, `SELECT declared_storage_gb FROM providers WHERE provider_id = $1`, providerID).
			Scan(&declaredStorageGB); err == nil {
			cap := declaredStorageGB * vettingChunksPerGB
			resp.VettingChunkCap = &cap
		}
		var vettingAssigned int
		if err := h.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM chunk_assignments WHERE provider_id = $1 AND is_vetting_chunk = TRUE AND status = 'ACTIVE'`,
			providerID).Scan(&vettingAssigned); err == nil {
			resp.VettingChunksAssigned = &vettingAssigned
		}
		if firstChunkAssignmentAt.Valid {
			eligibleAt := firstChunkAssignmentAt.Time.Add(h.profile.VettingMinDuration)
			resp.VettingEligibleAt = &eligibleAt
		}
	}
	// vetting_gc_pending: [FLAGGED] OAS's own field description gates this
	// on status == 'ACTIVE' ("null when status != 'ACTIVE' or GC is
	// complete"), NOT 'VETTING' as build.md's summary sentence for this
	// group of fields implies — the more specific, logically-coherent
	// per-field description is followed here (a provider that never
	// transitioned to ACTIVE has nothing to GC).
	if status == "ACTIVE" {
		var gcPending bool
		if err := h.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM chunk_assignments WHERE provider_id = $1 AND is_vetting_chunk = TRUE AND status = 'PENDING_DELETION')`,
			providerID).Scan(&gcPending); err == nil {
			resp.VettingGCPending = &gcPending
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.4 — GET /api/v1/provider/receipts
// ═══════════════════════════════════════════════════════════════════════

const (
	defaultReceiptsLimit = 100
	maxReceiptsLimit     = 200
)

type auditReceiptListItem struct {
	ReceiptID            uuid.UUID  `json:"receipt_id"`
	ChunkID              string     `json:"chunk_id"`
	FileID               *uuid.UUID `json:"file_id"`
	ChallengeNonce       string     `json:"challenge_nonce"`
	ServerChallengeTS    time.Time  `json:"server_challenge_ts"`
	ResponseHash         *string    `json:"response_hash"`
	ResponseLatencyMs    *int       `json:"response_latency_ms"`
	AuditResult          *string    `json:"audit_result"`
	AddressWasStale      bool       `json:"address_was_stale"`
	ProviderSig          *string    `json:"provider_sig"`
	ServiceSig           *string    `json:"service_sig"`
	ServiceCountersignTS *time.Time `json:"service_countersign_ts"`
}

type providerReceiptsResponseBody struct {
	Receipts   []auditReceiptListItem `json:"receipts"`
	Total      int                    `json:"total"`
	NextCursor *string                `json:"next_cursor"`
}

// ProviderReceiptsHandler serves GET /api/v1/provider/receipts (FR-058).
// Deliberately available with no departed-status check: this is the
// provider's primary dispute evidence path and FR-058 requires it to remain
// reachable even after the provider's status is DEPARTED.
type ProviderReceiptsHandler struct {
	db *sql.DB
}

func NewProviderReceiptsHandler(db *sql.DB) *ProviderReceiptsHandler {
	return &ProviderReceiptsHandler{db: db}
}

func (h *ProviderReceiptsHandler) HandleReceipts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}
	providerID := claims.Subject

	q := r.URL.Query()
	limit := defaultReceiptsLimit
	if l := q.Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed <= 0 || parsed > maxReceiptsLimit {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, fmt.Sprintf("limit must be between 1 and %d", maxReceiptsLimit), nil, "limit", nil)
			return
		}
		limit = parsed
	}

	where := []string{"provider_id = $1"}
	args := []any{providerID}

	if chunkIDHex := q.Get("chunk_id"); chunkIDHex != "" {
		raw, err := hex.DecodeString(chunkIDHex)
		if err != nil || len(raw) != 32 {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "chunk_id must be 64 lowercase hex characters", nil, "chunk_id", nil)
			return
		}
		args = append(args, raw)
		where = append(where, fmt.Sprintf("chunk_id = $%d", len(args)))
	}
	if from := q.Get("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "from must be ISO 8601", nil, "from", nil)
			return
		}
		args = append(args, t)
		where = append(where, fmt.Sprintf("server_challenge_ts >= $%d", len(args)))
	}
	if to := q.Get("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "to must be ISO 8601", nil, "to", nil)
			return
		}
		args = append(args, t)
		where = append(where, fmt.Sprintf("server_challenge_ts <= $%d", len(args)))
	}
	if result := q.Get("result"); result != "" {
		if result != "PASS" && result != "FAIL" && result != "TIMEOUT" {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "result must be PASS, FAIL, or TIMEOUT", nil, "result", nil)
			return
		}
		args = append(args, result)
		where = append(where, fmt.Sprintf("audit_result = $%d", len(args)))
	}

	var cursorTS time.Time
	var cursorID uuid.UUID
	if cursor := q.Get("cursor"); cursor != "" {
		var decErr error
		cursorTS, cursorID, decErr = decodeReceiptsCursor(cursor)
		if decErr != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid cursor", nil, "cursor", nil)
			return
		}
		args = append(args, cursorTS, cursorID)
		where = append(where, fmt.Sprintf("(server_challenge_ts, receipt_id) < ($%d, $%d)", len(args)-1, len(args)))
	}

	whereClause := strings.Join(where, " AND ")

	var total int
	if err := h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_receipts WHERE `+whereClause, args...).Scan(&total); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "count failed", nil, "", nil)
		return
	}

	// Fetch limit+1 to know definitively whether a next page exists.
	fetchArgs := append(append([]any{}, args...), limit+1)
	rows, err := h.db.QueryContext(ctx, `
		SELECT receipt_id, chunk_id, file_id, challenge_nonce, server_challenge_ts,
		       response_hash, response_latency_ms, audit_result, address_was_stale,
		       provider_sig, service_sig, service_countersign_ts
		FROM audit_receipts
		WHERE `+whereClause+`
		ORDER BY server_challenge_ts DESC, receipt_id DESC
		LIMIT $`+strconv.Itoa(len(fetchArgs)), fetchArgs...)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "query failed", nil, "", nil)
		return
	}

	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("HandleReceipts: close rows", "error", err)
		}
	}()

	items := make([]auditReceiptListItem, 0, limit)
	for rows.Next() {
		var (
			item                                       auditReceiptListItem
			chunkIDRaw, nonceRaw                       []byte
			responseHashRaw, providerSigRaw, svcSigRaw []byte
			fileID                                     uuid.NullUUID
			auditResult                                sql.NullString
			responseLatency                            sql.NullInt64
			svcCountersignTS                           sql.NullTime
		)
		if err := rows.Scan(&item.ReceiptID, &chunkIDRaw, &fileID, &nonceRaw, &item.ServerChallengeTS,
			&responseHashRaw, &responseLatency, &auditResult, &item.AddressWasStale,
			&providerSigRaw, &svcSigRaw, &svcCountersignTS); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "scan failed", nil, "", nil)
			return
		}
		item.ChunkID = hex.EncodeToString(chunkIDRaw)
		item.ChallengeNonce = hex.EncodeToString(nonceRaw)
		if fileID.Valid {
			id := fileID.UUID
			item.FileID = &id
		}
		if responseHashRaw != nil {
			s := hex.EncodeToString(responseHashRaw)
			item.ResponseHash = &s
		}
		if responseLatency.Valid {
			v := int(responseLatency.Int64)
			item.ResponseLatencyMs = &v
		}
		if auditResult.Valid {
			item.AuditResult = &auditResult.String
		}
		if providerSigRaw != nil {
			s := hex.EncodeToString(providerSigRaw)
			item.ProviderSig = &s
		}
		if svcSigRaw != nil {
			s := hex.EncodeToString(svcSigRaw)
			item.ServiceSig = &s
		}
		if svcCountersignTS.Valid {
			item.ServiceCountersignTS = &svcCountersignTS.Time
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "row iteration failed", nil, "", nil)
		return
	}

	var nextCursor *string
	if len(items) > limit {
		last := items[limit-1]
		c := encodeReceiptsCursor(last.ServerChallengeTS, last.ReceiptID)
		nextCursor = &c
		items = items[:limit]
	}

	resp := providerReceiptsResponseBody{Receipts: items, Total: total, NextCursor: nextCursor}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func encodeReceiptsCursor(ts time.Time, id uuid.UUID) string {
	raw := fmt.Sprintf("%d:%s", ts.UnixNano(), id.String())
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeReceiptsCursor(cursor string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, uuid.UUID{}, fmt.Errorf("api: decodeReceiptsCursor: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", receiptCursorParts)
	if len(parts) != receiptCursorParts {
		return time.Time{}, uuid.UUID{}, fmt.Errorf("api: decodeReceiptsCursor: malformed")
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, uuid.UUID{}, fmt.Errorf("api: decodeReceiptsCursor: bad timestamp: %w", err)
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return time.Time{}, uuid.UUID{}, fmt.Errorf("api: decodeReceiptsCursor: bad uuid: %w", err)
	}
	return time.Unix(0, nanos).UTC(), id, nil
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.5 — POST/GET /api/v1/provider/downtime
// ═══════════════════════════════════════════════════════════════════════

type providerDowntimeRequestBody struct {
	PromisedReturnAt string  `json:"promised_return_at"`
	Reason           *string `json:"reason"`
	ProviderSig      string  `json:"provider_sig"`
}

type providerDowntimeResponseBody struct {
	Active           bool      `json:"active"`
	PromisedReturnAt time.Time `json:"promised_return_at"`
	PenaltyFiresAt   time.Time `json:"penalty_fires_at"`
}

// canonicalDowntimeSigningInput signs promised_return_at (and reason, if the
// client included it — nil means the key was absent from the original JSON
// body, matching OAS's "all other fields in this request body").
func canonicalDowntimeSigningInput(req providerDowntimeRequestBody) []byte {
	fields := []signingField{{"promised_return_at", jstr(req.PromisedReturnAt)}}
	if req.Reason != nil {
		fields = append(fields, signingField{"reason", jstr(*req.Reason)})
	}
	return canonicalSigningObject(fields...)
}

// ProviderDowntimeHandler serves POST /api/v1/provider/downtime
// (announceDowntime, wired) and implements GET's handler logic
// (HandleGetActive) for direct unit testing — NOT wired into router.go: see
// this package's router.go header comment for why (no GET path exists in
// openapi.yaml yet).
type ProviderDowntimeHandler struct {
	db      *sql.DB
	profile config.NetworkProfile
}

func NewProviderDowntimeHandler(db *sql.DB, profile config.NetworkProfile) *ProviderDowntimeHandler {
	return &ProviderDowntimeHandler{db: db, profile: profile}
}

// HandleAnnounce serves POST /api/v1/provider/downtime (FR-032, FR-033).
func (h *ProviderDowntimeHandler) HandleAnnounce(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}
	providerID := claims.Subject

	var req providerDowntimeRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}

	var rawKey []byte
	var status string
	var existingPromisedReturn sql.NullTime
	err := h.db.QueryRowContext(ctx,
		`SELECT ed25519_public_key, status, promised_return_at FROM providers WHERE provider_id = $1`, providerID,
	).Scan(&rawKey, &status, &existingPromisedReturn)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "unknown provider", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "provider lookup failed", nil, "", nil)
		return
	}
	// Session 11.6.5's task text explicitly specifies 409 here (not
	// FR-036's general 403) — a departed provider trying to declare
	// downtime is a conflict with its already-terminal state.
	if status == "DEPARTED" {
		WriteError(w, http.StatusConflict, ErrProviderDeparted, "provider has departed", nil, "", nil)
		return
	}
	// [Interpretation] "a window is open" means promised_return_at is set
	// AND still in the future. A promised_return_at in the past that
	// hasn't yet been reclassified to silent departure (FR-033's overrun
	// detection — a background-process concern, not implemented in this
	// file) is treated as no longer active, allowing a fresh declaration.
	if existingPromisedReturn.Valid && existingPromisedReturn.Time.After(time.Now()) {
		WriteError(w, http.StatusConflict, ErrDowntimeAlreadyActive, "a downtime window is already open", nil, "", nil)
		return
	}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], rawKey)

	sigArr, ok := decodeProviderSig(req.ProviderSig)
	if !ok {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "provider_sig must be 128 lowercase hex characters", nil, "provider_sig", nil)
		return
	}
	if !localcrypto.VerifyBytes(pubKeyArr, canonicalDowntimeSigningInput(req), sigArr) {
		WriteError(w, http.StatusUnauthorized, ErrInvalidBodySignature, "invalid provider_sig", nil, "", nil)
		return
	}

	promisedReturnAt, err := time.Parse(time.RFC3339, req.PromisedReturnAt)
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "promised_return_at must be ISO 8601", nil, "promised_return_at", nil)
		return
	}
	now := time.Now()
	if promisedReturnAt.Before(now) {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "promised_return_at must not be in the past", nil, "promised_return_at", nil)
		return
	}
	// FR-032 literally says "0-72 hours"; routed through
	// profile.PromisedDowntimeMaximum (72h prod / 10min demo) rather than
	// hardcoded, matching this package's established pattern for every
	// other profile-variable duration (e.g. Session 11.6.3's
	// VettingMinDuration).
	if promisedReturnAt.After(now.Add(h.profile.PromisedDowntimeMaximum)) {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "promised_return_at exceeds the maximum downtime window", nil, "promised_return_at", nil)
		return
	}

	if _, err := h.db.ExecContext(ctx, `UPDATE providers SET promised_return_at = $2 WHERE provider_id = $1`,
		providerID, promisedReturnAt); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to record downtime window", nil, "", nil)
		return
	}

	resp := providerDowntimeResponseBody{
		Active:           true,
		PromisedReturnAt: promisedReturnAt,
		PenaltyFiresAt:   promisedReturnAt, // per this session's task text: penalty_fires_at == promised_return_at
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleGetActive implements the (unrouted) GET /api/v1/provider/downtime
// logic: returns whether the caller currently has an open downtime window.
// Response shape ({active, promised_return_at, penalty_fires_at}) matches
// what this project's own build.md flagged-gap note (Phase 11.3) already
// specifies for this not-yet-in-OAS path, rather than an ad hoc design of
// this handler's own.
func (h *ProviderDowntimeHandler) HandleGetActive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}
	var promisedReturnAt sql.NullTime
	err := h.db.QueryRowContext(ctx, `SELECT promised_return_at FROM providers WHERE provider_id = $1`, claims.Subject).
		Scan(&promisedReturnAt)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "unknown provider", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "provider lookup failed", nil, "", nil)
		return
	}

	resp := providerDowntimeResponseBody{Active: promisedReturnAt.Valid && promisedReturnAt.Time.After(time.Now())}
	if resp.Active {
		resp.PromisedReturnAt = promisedReturnAt.Time
		resp.PenaltyFiresAt = promisedReturnAt.Time
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ═══════════════════════════════════════════════════════════════════════
// Session 11.6.6 — POST /api/v1/provider/depart
// ═══════════════════════════════════════════════════════════════════════

type providerDepartRequestBody struct {
	DepartAt    *string `json:"depart_at"`
	ProviderSig string  `json:"provider_sig"`
}

type providerDepartResponseBody struct {
	Status             string `json:"status"`
	EscrowReleasePaise int64  `json:"escrow_release_paise"`
	RepairJobsQueued   int    `json:"repair_jobs_queued"`
}

// canonicalDepartSigningInput signs depart_at only if the client included it
// (nil = absent). [FLAGGED] When depart_at is omitted, the signing input
// degenerates to the fixed byte sequence `{}` — a valid signature over "{}"
// would be replayable indefinitely, since nothing provider- or time-specific
// is signed. This is judged low-severity here: the request is still gated by
// a genuine, time-bounded JWT bearer token, and depart is a rare, terminal,
// effectively idempotent action (a second attempt against an
// already-departed provider is rejected below).
func canonicalDepartSigningInput(req providerDepartRequestBody) []byte {
	if req.DepartAt != nil {
		return canonicalSigningObject(signingField{"depart_at", jstr(*req.DepartAt)})
	}
	return canonicalSigningObject()
}

// ProviderDepartHandler serves POST /api/v1/provider/depart (ADR-007
// announced departure path).
type ProviderDepartHandler struct {
	db      *sql.DB
	profile config.NetworkProfile
	payment payment.PaymentProvider
}

func NewProviderDepartHandler(db *sql.DB, profile config.NetworkProfile, pp payment.PaymentProvider) *ProviderDepartHandler {
	return &ProviderDepartHandler{db: db, profile: profile, payment: pp}
}

func (h *ProviderDepartHandler) HandleDepart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "missing auth claims", nil, "", nil)
		return
	}
	providerID := claims.Subject

	var req providerDepartRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}

	var rawKey []byte
	var status string
	err := h.db.QueryRowContext(ctx, `SELECT ed25519_public_key, status FROM providers WHERE provider_id = $1`, providerID).
		Scan(&rawKey, &status)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "unknown provider", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "provider lookup failed", nil, "", nil)
		return
	}
	// Not specified explicitly by this session's task text (unlike
	// downtime's 409); extended here for the same reason as heartbeat's
	// FR-036 check — an already-departed provider cannot meaningfully
	// depart again.
	if status == "DEPARTED" {
		WriteError(w, http.StatusForbidden, ErrProviderDeparted, "provider has already departed", nil, "", nil)
		return
	}
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], rawKey)

	sigArr, ok := decodeProviderSig(req.ProviderSig)
	if !ok {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "provider_sig must be 128 lowercase hex characters", nil, "provider_sig", nil)
		return
	}
	if !localcrypto.VerifyBytes(pubKeyArr, canonicalDepartSigningInput(req), sigArr) {
		WriteError(w, http.StatusUnauthorized, ErrInvalidBodySignature, "invalid provider_sig", nil, "", nil)
		return
	}

	// depart_at is part of the signed payload (canonicalDepartSigningInput)
	// and, when present, must be a valid ISO 8601 timestamp — format
	// validation only. [M10 corrections review Finding #8] The parsed value
	// itself is no longer threaded into the release idempotency key (see
	// below): both release paths must derive the same key from
	// (providerID, auditPeriodID) alone, so a client-supplied departure
	// timestamp can no longer be part of that formula.
	if req.DepartAt != nil {
		if _, err := time.Parse(time.RFC3339, *req.DepartAt); err != nil {
			WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "depart_at must be ISO 8601", nil, "depart_at", nil)
			return
		}
	}

	releaseAmountPaise, auditPeriodID, err := h.computeAnnouncedDepartureRelease(ctx, providerID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "escrow computation failed", nil, "", nil)
		return
	}
	if releaseAmountPaise > 0 && auditPeriodID != nil && h.payment != nil {
		// [Fixed, M10 corrections review Finding #8] this idempotency key was
		// previously derived from announcedDepartureIdempotencyKey — a
		// different formula from payment.ReleaseIdempotencyKey, which
		// ComputeMonthlyRelease uses for a release against the exact same
		// (providerID, auditPeriodID) pair. That let both paths successfully
		// release against the same period, defeating the
		// escrow_events.idempotency_key UNIQUE constraint's "one release per
		// provider per audit period" guarantee. Both paths now derive the
		// same key for the same logical event.
		idempotencyKey := payment.ReleaseIdempotencyKey(providerID, *auditPeriodID)
		if err := h.payment.ReleaseEscrow(ctx, providerID, releaseAmountPaise, *auditPeriodID, idempotencyKey); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "escrow release failed", nil, "", nil)
			return
		}
		// [Added, M10 corrections review Finding #8] mark this audit period
		// released so ComputeMonthlyRelease's pendingReleaseCandidates query
		// (WHERE release_computed = FALSE) stops re-selecting it. Not
		// wrapped in the same DB transaction as the ReleaseEscrow call above
		// — PaymentProvider's interface does not expose transaction control
		// to its callers (MockProvider/RazorpayProvider each own their DB
		// handle internally) — but errors here are surfaced to the caller
		// rather than silently dropped, unlike this package's established
		// best-effort "non-fatal cleanup" pattern elsewhere: a stuck
		// release_computed = FALSE row has an ongoing cost (re-queried every
		// cycle, forever), unlike a stale pending-registration row.
		if err := payment.MarkReleaseComputed(ctx, h.db, *auditPeriodID); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to finalize escrow release", nil, "", nil)
			return
		}
	}

	if _, err := h.db.ExecContext(ctx,
		`UPDATE providers SET status = 'DEPARTED', departed_at = NOW() WHERE provider_id = $1`, providerID,
	); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to record departure", nil, "", nil)
		return
	}

	var repairJobsQueued int
	_ = h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM chunk_assignments WHERE provider_id = $1 AND is_vetting_chunk = FALSE AND status = 'ACTIVE'`,
		providerID).Scan(&repairJobsQueued)
	// Best-effort: departure itself (status + escrow release) is already
	// committed above; a failure here does not roll that back, matching
	// this package's established non-fatal-cleanup pattern elsewhere
	// (e.g. DeletePendingRegistration in owner.go/provider register above).
	_ = repair.EnqueueRepairForRealChunks(ctx, h.db, h.profile, providerID, repair.TriggerAnnouncedDeparture)

	resp := providerDepartResponseBody{
		Status:             "DEPARTED",
		EscrowReleasePaise: releaseAmountPaise,
		RepairJobsQueued:   repairJobsQueued,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// computeAnnouncedDepartureRelease releases escrow proportional to the
// fraction of the current 30-day audit period completed so far. Returns
// (0, nil) if the provider has no open audit period yet — a genuine edge
// case (no period to prorate against) rather than releasing the full
// balance speculatively.
func (h *ProviderDepartHandler) computeAnnouncedDepartureRelease(ctx context.Context, providerID uuid.UUID) (int64, *uuid.UUID, error) {
	var auditPeriodID uuid.UUID
	var periodStart, periodEnd time.Time
	err := h.db.QueryRowContext(ctx, `
		SELECT id, period_start, period_end
		FROM audit_periods
		WHERE provider_id = $1 AND period_start <= NOW() AND period_end > NOW()
		ORDER BY period_start DESC LIMIT 1`, providerID,
	).Scan(&auditPeriodID, &periodStart, &periodEnd)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, fmt.Errorf("api: computeAnnouncedDepartureRelease: %w", err)
	}

	if h.payment == nil {
		return 0, nil, nil
	}
	balance, err := h.payment.GetBalance(ctx, providerID)
	if err != nil {
		return 0, nil, fmt.Errorf("api: computeAnnouncedDepartureRelease: get balance: %w", err)
	}
	total := periodEnd.Sub(periodStart)
	if total <= 0 {
		return 0, &auditPeriodID, nil
	}
	elapsed := time.Since(periodStart)
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed > total {
		elapsed = total
	}
	fraction := float64(elapsed) / float64(total)
	release := int64(float64(balance) * fraction)
	return release, &auditPeriodID, nil
}
