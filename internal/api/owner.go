// Package api is declared in doc.go.
// This file implements the six owner endpoints: register, deposit initiate,
// balance, file list, escrow history, and withdraw.
//
// [REF: OAS paths./api/v1/owner/*, FR-001, FR-006, FR-014, FR-019, FR-021,
// FR-059, DM §4.9, build.md Phase 11.5]

package api

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	"github.com/masamasaowl/Vyomanaut_V2/internal/payment"
)

// ── Session 11.5.1 — Owner Register ─────────────────────────────────────────────

type ownerRegisterRequestBody struct {
	Ed25519PublicKey string `json:"ed25519_public_key"` // 64 hex chars
	OwnerSig         string `json:"owner_sig"`          // 128 hex chars
}

type ownerRegisterResponseBody struct {
	OwnerID uuid.UUID `json:"owner_id"`
	Token   string    `json:"token"`
}

// OwnerRegisterHandler completes registration for a data owner (Session
// 11.5.1). Must be reached only via bearerAny (a registration token, whose
// Role == "") — router.go wires this correctly.
type OwnerRegisterHandler struct {
	db         *sql.DB
	signingKey ed25519.PrivateKey
}

func NewOwnerRegisterHandler(db *sql.DB, signingKey ed25519.PrivateKey) *OwnerRegisterHandler {
	return &OwnerRegisterHandler{db: db, signingKey: signingKey}
}

// HandleRegister serves POST /api/v1/owner/register.
func (h *OwnerRegisterHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "missing token claims", nil, "", nil)
		return
	}
	if claims.Role != "" {
		WriteError(w, http.StatusForbidden, ErrWrongRole, "token is not a registration token", nil, "", nil)
		return
	}

	var req ownerRegisterRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	pubKeyBytes, err := hex.DecodeString(req.Ed25519PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "ed25519_public_key must be 64 hex chars", nil, "ed25519_public_key", nil)
		return
	}
	if !verifyOwnerSig(pubKeyBytes, req.Ed25519PublicKey, req.OwnerSig) {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "invalid owner_sig", nil, "", nil)
		return
	}

	ctx := r.Context()
	phoneNumber, err := RecoverPendingRegistration(ctx, h.db, claims.Subject)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "registration token expired or invalid", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "registration lookup failed", nil, "", nil)
		return
	}

	ownerID := uuid.New()
	_, err = h.db.ExecContext(ctx, `INSERT INTO owners (owner_id, phone_number, ed25519_public_key) VALUES ($1, $2, $3)`,
		ownerID, phoneNumber, pubKeyBytes)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			WriteError(w, http.StatusConflict, ErrPhoneAlreadyRegistered, "phone number already registered", nil, "", nil)
			return
		}
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to create owner", nil, "", nil)
		return
	}

	// Non-fatal cleanup: the owner row is already committed; a stale
	// pending_registrations row expires on its own via expires_at even if
	// this delete fails.
	_ = DeletePendingRegistration(ctx, h.db, claims.Subject)

	token, err := IssueJWT(h.signingKey, ownerID, "owner", OwnerTokenTTL)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "token issuance failed", nil, "", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ownerRegisterResponseBody{OwnerID: ownerID, Token: token})
}

// verifyOwnerSig verifies sigHex against plain (not hash-prefixed) Ed25519
// over the canonical JSON `{"ed25519_public_key":"<value>"}` — exactly OAS's
// own description ("sorted keys, no trailing whitespace"), which for a
// single-key object needs no actual sorting. This is a THIRD distinct
// signing convention in this package (alongside jwt.go's raw-EdDSA-over-JOSE
// and token_refresh.go's SHA-256-then-sign), each matching what its own OAS
// schema literally specifies rather than applying one convention uniformly.
func verifyOwnerSig(pubKey []byte, ed25519PublicKeyHex, sigHex string) bool {
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	signingInput := fmt.Sprintf(`{"ed25519_public_key":"%s"}`, ed25519PublicKeyHex)
	return ed25519.Verify(pubKey, []byte(signingInput), sigBytes)
}

// ── Session 11.5.2 — Deposit Initiate ───────────────────────────────────────────

type depositInitiateRequestBody struct {
	AmountPaise int64 `json:"amount_paise"`
	// IdempotencyKey is a client-supplied 64-lowercase-hex-char token — the
	// SAME shape and validation withdrawRequestBody.IdempotencyKey already
	// uses below.
	//
	// [Added, M10 corrections review Finding #4] MockProvider.InitiateEscrow
	// credits owner_escrow_events SYNCHRONOUSLY ("because there is no real
	// Razorpay webhook to wait for in demo mode" — see its own doc comment)
	// and derives its idempotency key from (ownerID, contractID). Before
	// this field existed, HandleDeposit minted a fresh contractID on every
	// call, so every retry of this HTTP request in demo mode credited the
	// owner's balance again, with no protection at all — unlike
	// /owner/withdraw, a structurally identical money-moving endpoint built
	// in this same milestone, which already required a client-supplied key.
	IdempotencyKey string `json:"idempotency_key"`
}

type depositInitiateResponseBody struct {
	VPA       string    `json:"vpa"`
	QRCodeURL string    `json:"qr_code_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// depositSessionTTL is how long the returned VPA/QR session is valid before
// a fresh deposit must be initiated — no ADR/FR gives a concrete figure;
// 30 minutes is a reasonable placeholder for a payment-session window.
const depositSessionTTL = 30 * time.Minute

// OwnerDepositHandler holds the payment.PaymentProvider dependency needed
// to actually create the Smart Collect virtual account.
type OwnerDepositHandler struct {
	provider payment.PaymentProvider
}

func NewOwnerDepositHandler(provider payment.PaymentProvider) *OwnerDepositHandler {
	return &OwnerDepositHandler{provider: provider}
}

// HandleDeposit serves POST /api/v1/owner/deposit.
//
// [Flagged and corrected — repeats the M9-M10 table confusion.] OAS's own
// path description says "The microservice records the DEPOSIT event to
// escrow_events on receipt of the webhook" — escrow_events is the
// PROVIDER-scoped ledger; an owner deposit belongs in owner_escrow_events
// (DM §4.9), exactly the fix already made to Milestone 10 Session 10.3.1's
// HandleDepositCaptured. This handler itself writes NOTHING to either
// ledger — it only calls PaymentProvider.InitiateEscrow, which creates the
// virtual account; the actual credit is recorded asynchronously by the
// (already-corrected) webhook handler.
func (h *OwnerDepositHandler) HandleDeposit(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.Role != "owner" {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "missing or wrong-role token", nil, "", nil)
		return
	}

	var req depositInitiateRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	if req.AmountPaise <= 0 {
		WriteError(w, http.StatusBadRequest, ErrInvalidAmount, "amount_paise must be a positive integer", nil, "amount_paise", nil)
		return
	}
	if !idempotencyKeyPattern.MatchString(req.IdempotencyKey) {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "idempotency_key must be 64 hex chars", nil, "idempotency_key", nil)
		return
	}

	// [Fixed, M10 corrections review Finding #4] contractID is derived
	// DETERMINISTICALLY from (ownerID, req.IdempotencyKey) — a version-5
	// (SHA-1 name-based) UUID, RFC 4122 §4.3 — rather than uuid.New()'s
	// fresh-every-call random value. A retry with the same idempotency_key
	// therefore reproduces the exact same contractID, which
	// MockProvider.InitiateEscrow's own idempotency key
	// (mockDepositIdempotencyKey(ownerID, contractID)) is derived from —
	// so a retried deposit hits owner_escrow_events' UNIQUE(idempotency_key)
	// constraint and is treated as an already-credited no-op, instead of
	// crediting the owner's balance a second time. Passing a deterministic
	// contractID to RazorpayProvider.InitiateEscrow is likewise safe (and a
	// welcome side effect): it forwards unchanged to
	// razorpayClient.CreateVirtualAccount, which callers should be able to
	// retry with the same correlation ID without side effects, matching how
	// idempotencyKey is already used for ReleaseEscrow/Penalise/
	// WithdrawOwnerEscrow's underlying gateway calls elsewhere in this
	// package.
	depositContractNamespace := uuid.Nil
	contractID := uuid.NewSHA1(depositContractNamespace, []byte("vyomanaut-deposit:"+claims.Subject.String()+":"+req.IdempotencyKey))
	vpa, qrURL, err := h.provider.InitiateEscrow(r.Context(), claims.Subject, req.AmountPaise, contractID)
	if err != nil {
		WriteError(w, http.StatusServiceUnavailable, ErrRazorpayUnavailable, "escrow initiation failed", nil, "", nil)
		return
	}

	resp := depositInitiateResponseBody{
		VPA:       vpa,
		QRCodeURL: qrURL,
		ExpiresAt: time.Now().UTC().Add(depositSessionTTL),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ── Session 11.5.3 — Owner Balance ──────────────────────────────────────────────

type ownerBalanceResponseBody struct {
	BalancePaise         int64 `json:"balance_paise"`
	ReservedNext30dPaise int64 `json:"reserved_next_30d_paise"`
	AvailablePaise       int64 `json:"available_paise"`
}

type OwnerBalanceHandler struct {
	db      *sql.DB
	profile config.NetworkProfile
}

func NewOwnerBalanceHandler(db *sql.DB, profile config.NetworkProfile) *OwnerBalanceHandler {
	return &OwnerBalanceHandler{db: db, profile: profile}
}

// HandleBalance serves GET /api/v1/owner/{owner_id}/balance.
func (h *OwnerBalanceHandler) HandleBalance(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.Role != "owner" {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "missing or wrong-role token", nil, "", nil)
		return
	}
	ownerID, err := uuid.Parse(r.PathValue("owner_id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "owner_id must be a UUID", nil, "owner_id", nil)
		return
	}
	if ownerID != claims.Subject {
		WriteError(w, http.StatusForbidden, ErrUnauthorized, "owner_id does not match the token subject", nil, "", nil)
		return
	}

	balance, reserved, err := ownerBalanceAndReserved(r.Context(), h.db, h.profile, ownerID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "balance lookup failed", nil, "", nil)
		return
	}

	available := balance - reserved
	if available < 0 {
		available = 0
	}
	resp := ownerBalanceResponseBody{BalancePaise: balance, ReservedNext30dPaise: reserved, AvailablePaise: available}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ownerBalanceAndReserved reads mv_owner_escrow_balance (balance_paise
// already has the view's own GREATEST(...,0) floor — DM §7) and computes
// the next-30-day reserve as the sum of every ACTIVE file's
// monthly_cost_paise (see fileMonthlyCostPaiseForBytes), since 30 days is
// approximately one billing month.
func ownerBalanceAndReserved(ctx context.Context, db *sql.DB, profile config.NetworkProfile, ownerID uuid.UUID) (balancePaise, reservedPaise int64, err error) {
	err = db.QueryRowContext(ctx, `SELECT balance_paise FROM mv_owner_escrow_balance WHERE owner_id = $1`, ownerID).Scan(&balancePaise)
	if errors.Is(err, sql.ErrNoRows) {
		balancePaise = 0
	} else if err != nil {
		return 0, 0, fmt.Errorf("ownerBalanceAndReserved: balance: %w", err)
	}

	var totalBytes int64
	err = db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(original_size_bytes), 0) FROM files
		WHERE owner_id = $1 AND status = 'ACTIVE'`,
		ownerID,
	).Scan(&totalBytes)
	if err != nil {
		return 0, 0, fmt.Errorf("ownerBalanceAndReserved: active file bytes: %w", err)
	}
	reservedPaise = fileMonthlyCostPaiseForBytes(totalBytes, profile)

	return balancePaise, reservedPaise, nil
}

// bytesPerGB converts bytes to GB for cost calculations (2^30, matching
// this system's own binary-GB convention elsewhere, e.g. declared_storage_gb).
const bytesPerGB = 1024 * 1024 * 1024

// roundingHalf is the standard "round half up" offset added before
// truncating a float to an integer.
const roundingHalf = 0.5

// fileMonthlyCostPaiseForBytes computes the monthly storage cost for
// sizeBytes at profile.StorageRatePaisePerGBPerMonth.
func fileMonthlyCostPaiseForBytes(sizeBytes int64, profile config.NetworkProfile) int64 {
	gb := float64(sizeBytes) / float64(bytesPerGB)
	return int64(gb*float64(profile.StorageRatePaisePerGBPerMonth) + roundingHalf)
}

// ── Session 11.5.4 — Owner File List ────────────────────────────────────────────

type fileListItemBody struct {
	FileID                uuid.UUID `json:"file_id"`
	OriginalSizeBytes     int64     `json:"original_size_bytes"`
	UploadedAt            time.Time `json:"uploaded_at"`
	MonthlyCostPaise      int64     `json:"monthly_cost_paise"`
	Status                string    `json:"status"`
	Availability          string    `json:"availability,omitempty"`
	AvailableShardCount   int       `json:"available_shard_count"`
	TotalShardCount       int       `json:"total_shard_count"`
	DisplayNameCiphertext *string   `json:"display_name_ciphertext,omitempty"`
	DisplayNameNonce      *string   `json:"display_name_nonce,omitempty"`
	DisplayNameTag        *string   `json:"display_name_tag,omitempty"`
}

type ownerFileListResponseBody struct {
	Files      []fileListItemBody `json:"files"`
	Total      int                `json:"total"`
	NextCursor *string            `json:"next_cursor,omitempty"`
}

const (
	ownerFileListDefaultLimit = 50
	ownerFileListMaxLimit     = 100
)

type OwnerFileListHandler struct {
	db      *sql.DB
	profile config.NetworkProfile
}

func NewOwnerFileListHandler(db *sql.DB, profile config.NetworkProfile) *OwnerFileListHandler {
	return &OwnerFileListHandler{db: db, profile: profile}
}

// HandleFiles serves GET /api/v1/owner/{owner_id}/files.
//
// [Flagged and corrected — hardcoded production shard thresholds.] OAS's
// own schema description is written in fixed production terms ("OK —
// available_shard_count >= s+r0 = 24... CRITICAL — < s = 16"). These are
// production-only (DataShards=16, LazyRepairR0=8); demo mode uses
// DataShards=3, LazyRepairR0=1 (thresholds 4 and 3). Computed from
// profile.DataShards + profile.LazyRepairR0 / profile.DataShards below,
// never the literals 24/16.
func (h *OwnerFileListHandler) HandleFiles(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.Role != "owner" {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "missing or wrong-role token", nil, "", nil)
		return
	}
	ownerID, err := uuid.Parse(r.PathValue("owner_id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "owner_id must be a UUID", nil, "owner_id", nil)
		return
	}
	if ownerID != claims.Subject {
		WriteError(w, http.StatusForbidden, ErrUnauthorized, "owner_id does not match the token subject", nil, "", nil)
		return
	}

	status := r.URL.Query().Get("status")
	if status == "" {
		status = "ACTIVE"
	}
	limit := ownerFileListDefaultLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, perr := parsePositiveInt(l); perr == nil && parsed > 0 && parsed <= ownerFileListMaxLimit {
			limit = parsed
		}
	}

	ctx := r.Context()
	rows, err := h.db.QueryContext(ctx, `
		SELECT f.file_id, f.original_size_bytes, f.uploaded_at, f.status,
		       f.display_name_ciphertext, f.display_name_nonce, f.display_name_tag,
		       COALESCE(SUM(msc.available_shard_count), 0) AS total_available,
		       COALESCE(MIN(msc.available_shard_count), 0) AS worst_segment_available,
		       COUNT(s.segment_id) AS segment_count
		FROM files f
		LEFT JOIN segments s ON s.file_id = f.file_id
		LEFT JOIN mv_segment_shard_counts msc ON msc.segment_id = s.segment_id
		WHERE f.owner_id = $1 AND f.status = $2
		GROUP BY f.file_id, f.original_size_bytes, f.uploaded_at, f.status,
		         f.display_name_ciphertext, f.display_name_nonce, f.display_name_tag
		ORDER BY f.uploaded_at DESC
		LIMIT $3`,
		ownerID, status, limit,
	)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "file list query failed", nil, "", nil)
		return
	}
	defer func() { _ = rows.Close() }()

	okThreshold := h.profile.DataShards + h.profile.LazyRepairR0
	criticalThreshold := h.profile.DataShards

	var items []fileListItemBody
	for rows.Next() {
		var item fileListItemBody
		var displayNameCiphertext, displayNameNonce, displayNameTag []byte
		var totalAvailable, worstSegmentAvailable, segmentCount int
		if err := rows.Scan(&item.FileID, &item.OriginalSizeBytes, &item.UploadedAt, &item.Status,
			&displayNameCiphertext, &displayNameNonce, &displayNameTag, &totalAvailable, &worstSegmentAvailable, &segmentCount); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "file list scan failed", nil, "", nil)
			return
		}
		item.MonthlyCostPaise = fileMonthlyCostPaiseForBytes(item.OriginalSizeBytes, h.profile)
		// available_shard_count/total_shard_count are sums across all of the
		// file's segments (OAS's own field description: "across all
		// segments"). Availability, by contrast, is judged on the WORST
		// segment — a multi-segment file is only as retrievable as its
		// weakest segment, which a summed count would mask (one segment at
		// CRITICAL and the rest at OK could still sum well above the OK
		// threshold).
		item.AvailableShardCount = totalAvailable
		item.TotalShardCount = segmentCount * h.profile.TotalShards

		switch {
		case worstSegmentAvailable >= okThreshold:
			item.Availability = "OK"
		case worstSegmentAvailable >= criticalThreshold:
			item.Availability = "DEGRADED"
		default:
			item.Availability = "CRITICAL"
		}

		if displayNameCiphertext != nil {
			s := hex.EncodeToString(displayNameCiphertext)
			item.DisplayNameCiphertext = &s
		}
		if displayNameNonce != nil {
			s := hex.EncodeToString(displayNameNonce)
			item.DisplayNameNonce = &s
		}
		if displayNameTag != nil {
			s := hex.EncodeToString(displayNameTag)
			item.DisplayNameTag = &s
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "file list iteration failed", nil, "", nil)
		return
	}

	resp := ownerFileListResponseBody{Files: items, Total: len(items)}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func parsePositiveInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// ── Session 11.5.5 — Owner Escrow History ───────────────────────────────────────

type ownerEscrowTransactionBody struct {
	EventID     uuid.UUID  `json:"event_id"`
	EventType   string     `json:"event_type"`
	AmountPaise int64      `json:"amount_paise"`
	FileID      *uuid.UUID `json:"file_id,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type ownerEscrowHistoryResponseBody struct {
	BalancePaise         int64                        `json:"balance_paise"`
	ReservedNext30dPaise int64                        `json:"reserved_next_30d_paise"`
	AvailablePaise       int64                        `json:"available_paise"`
	Events               []ownerEscrowTransactionBody `json:"events"`
	NextCursor           *string                      `json:"next_cursor,omitempty"`
}

const (
	ownerEscrowHistoryDefaultLimit = 50
	ownerEscrowHistoryMaxLimit     = 100
)

type OwnerEscrowHistoryHandler struct {
	db      *sql.DB
	profile config.NetworkProfile
}

func NewOwnerEscrowHistoryHandler(db *sql.DB, profile config.NetworkProfile) *OwnerEscrowHistoryHandler {
	return &OwnerEscrowHistoryHandler{db: db, profile: profile}
}

// HandleEscrowHistory serves GET /api/v1/owner/{owner_id}/escrow.
func (h *OwnerEscrowHistoryHandler) HandleEscrowHistory(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.Role != "owner" {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "missing or wrong-role token", nil, "", nil)
		return
	}
	ownerID, err := uuid.Parse(r.PathValue("owner_id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "owner_id must be a UUID", nil, "owner_id", nil)
		return
	}
	if ownerID != claims.Subject {
		WriteError(w, http.StatusForbidden, ErrUnauthorized, "owner_id does not match the token subject", nil, "", nil)
		return
	}

	limit := ownerEscrowHistoryDefaultLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, perr := parsePositiveInt(l); perr == nil && parsed > 0 && parsed <= ownerEscrowHistoryMaxLimit {
			limit = parsed
		}
	}

	ctx := r.Context()
	balance, reserved, err := ownerBalanceAndReserved(ctx, h.db, h.profile, ownerID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "balance lookup failed", nil, "", nil)
		return
	}
	available := balance - reserved
	if available < 0 {
		available = 0
	}

	rows, err := h.db.QueryContext(ctx, `
		SELECT event_id, event_type, amount_paise, file_id, created_at
		FROM owner_escrow_events
		WHERE owner_id = $1
		ORDER BY created_at DESC
		LIMIT $2`,
		ownerID, limit,
	)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "escrow history query failed", nil, "", nil)
		return
	}
	defer func() { _ = rows.Close() }()

	var events []ownerEscrowTransactionBody
	for rows.Next() {
		var ev ownerEscrowTransactionBody
		var fileID uuid.NullUUID
		if err := rows.Scan(&ev.EventID, &ev.EventType, &ev.AmountPaise, &fileID, &ev.CreatedAt); err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "escrow history scan failed", nil, "", nil)
			return
		}
		if fileID.Valid {
			ev.FileID = &fileID.UUID
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "escrow history iteration failed", nil, "", nil)
		return
	}

	resp := ownerEscrowHistoryResponseBody{
		BalancePaise:         balance,
		ReservedNext30dPaise: reserved,
		AvailablePaise:       available,
		Events:               events,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ── Session 11.5.6 — Owner Withdraw ──────────────────────────────────────────────

type withdrawRequestBody struct {
	AmountPaise    int64  `json:"amount_paise"`
	IdempotencyKey string `json:"idempotency_key"`
}

type withdrawResponseBody struct {
	PayoutID    string `json:"payout_id"`
	AmountPaise int64  `json:"amount_paise"`
	Status      string `json:"status"`
}

// InFlightUploadChecker reports whether owner has any upload currently in
// progress (FR-059: withdrawal must be blocked while true). No upload
// session-tracking mechanism exists anywhere in scope yet (Milestone 11
// Phase 11.7 builds /api/v1/upload/assign but does not itself define an
// "in-flight" state machine) — injected interface, stub default (always
// false) until that tracking exists, same pattern as this milestone's other
// not-yet-built-elsewhere dependencies.
type InFlightUploadChecker interface {
	HasInFlightUpload(ctx context.Context, ownerID uuid.UUID) (bool, error)
}

// NoInFlightUploadChecker always reports false — a placeholder until
// Phase 11.7's upload flow defines real in-flight tracking.
type NoInFlightUploadChecker struct{}

func (NoInFlightUploadChecker) HasInFlightUpload(context.Context, uuid.UUID) (bool, error) {
	return false, nil
}

// OwnerWithdrawHandler holds the dependencies for withdrawal: the balance
// view (via db+profile, reusing ownerBalanceAndReserved), the payment
// provider (payment.WithdrawOwnerEscrow, Milestone 10 Phase 10.5), and the
// in-flight-upload check (FR-059).
//
// [Flagged — the reversal path for owner withdrawals has no clean home.]
// A reversed payout can equally be a provider RELEASE or an owner
// WITHDRAWAL; Milestone 10 Session 10.3.1's HandlePayoutReversed already
// branches on both cases (see internal/payment/razorpay.go), inserting an
// OwnerDeposit-typed row with idempotency key
// SHA-256("withdrawal-reversal" || original_idempotency_key) for the owner
// case — addressed proactively there per that session's own note that this
// is "a follow-up to Milestone 10 Session 10.3.1, not a new session".
type OwnerWithdrawHandler struct {
	db       *sql.DB
	profile  config.NetworkProfile
	provider payment.PaymentProvider
	inFlight InFlightUploadChecker
}

func NewOwnerWithdrawHandler(db *sql.DB, profile config.NetworkProfile, provider payment.PaymentProvider, inFlight InFlightUploadChecker) *OwnerWithdrawHandler {
	return &OwnerWithdrawHandler{db: db, profile: profile, provider: provider, inFlight: inFlight}
}

var idempotencyKeyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HandleWithdraw serves POST /api/v1/owner/withdraw.
func (h *OwnerWithdrawHandler) HandleWithdraw(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.Role != "owner" {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "missing or wrong-role token", nil, "", nil)
		return
	}

	var req withdrawRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	if req.AmountPaise <= 0 {
		WriteError(w, http.StatusBadRequest, ErrInvalidAmount, "amount_paise must be a positive integer", nil, "amount_paise", nil)
		return
	}
	if !idempotencyKeyPattern.MatchString(req.IdempotencyKey) {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "idempotency_key must be 64 hex chars", nil, "idempotency_key", nil)
		return
	}

	ctx := r.Context()
	inFlight, err := h.inFlight.HasInFlightUpload(ctx, claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "in-flight upload check failed", nil, "", nil)
		return
	}
	if inFlight {
		WriteError(w, http.StatusConflict, ErrInvalidRequest, "withdrawal blocked while an upload is in-flight", nil, "", nil)
		return
	}

	balance, reserved, err := ownerBalanceAndReserved(ctx, h.db, h.profile, claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "balance lookup failed", nil, "", nil)
		return
	}
	available := balance - reserved
	if available < 0 {
		available = 0
	}
	if req.AmountPaise > available {
		WriteError(w, http.StatusConflict, ErrInsufficientEscrow, "amount_paise exceeds available balance", nil, "", nil)
		return
	}

	payoutID, err := h.provider.WithdrawOwnerEscrow(ctx, claims.Subject, req.AmountPaise, req.IdempotencyKey)
	if err != nil {
		WriteError(w, http.StatusServiceUnavailable, ErrRazorpayUnavailable, "withdrawal failed", nil, "", nil)
		return
	}

	resp := withdrawResponseBody{PayoutID: payoutID, AmountPaise: req.AmountPaise, Status: "QUEUED"}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}