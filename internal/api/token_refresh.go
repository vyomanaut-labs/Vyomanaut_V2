// Package api is declared in doc.go.
// This file implements POST /api/v1/provider/token/refresh: two-factor
// re-authentication (grace-period JWT + fresh Ed25519 body signature) that
// lets a long-running provider daemon renew its 7-day JWT without a human
// completing OTP verification.
//
// [Decision] The body signature here is SHA-256(provider_id ||
// timestamp_string) — exactly internal/crypto.SignBytes/VerifyBytes's
// hash-then-sign composition (IC §3.2), unlike jwt.go's JWT signing, which
// deliberately does NOT use that convention (see jwt.go's own header note).
// The two signing schemes coexist correctly in this one file because they
// serve different purposes: the JWT must be verifiable by standard JOSE
// tooling; this body signature is Vyomanaut's own internal provider-auth
// convention, identical to every other provider_sig in this system.
//
// [REF: OAS paths./api/v1/provider/token/refresh, IC §3.2,
// build.md Phase 11.4]

package api

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
)

const (
	tokenRefreshGracePeriod = 1 * time.Hour
	tokenRefreshSkew        = 5 * time.Minute
	tokenRefreshRateLimit   = 30 * time.Minute
)

type tokenRefreshRequestBody struct {
	ProviderID  uuid.UUID `json:"provider_id"`
	Timestamp   string    `json:"timestamp"`
	ProviderSig string    `json:"provider_sig"`
}

type tokenRefreshResponseBody struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ProviderTokenRefreshHandler holds the dependencies for the refresh
// endpoint: publicKey verifies the presented (possibly grace-period-expired)
// JWT; signingKey issues the new one.
type ProviderTokenRefreshHandler struct {
	db         *sql.DB
	publicKey  ed25519.PublicKey
	signingKey ed25519.PrivateKey
}

func NewProviderTokenRefreshHandler(db *sql.DB, publicKey ed25519.PublicKey, signingKey ed25519.PrivateKey) *ProviderTokenRefreshHandler {
	return &ProviderTokenRefreshHandler{db: db, publicKey: publicKey, signingKey: signingKey}
}

// HandleRefresh serves POST /api/v1/provider/token/refresh.
func (h *ProviderTokenRefreshHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "missing Bearer token", nil, "", nil)
		return
	}
	presentedToken := strings.TrimPrefix(authHeader, prefix)

	claims, err := verifyJWTWithGracePeriod(h.publicKey, presentedToken, tokenRefreshGracePeriod)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "token invalid or beyond the 1-hour grace period", nil, "", nil)
		return
	}

	var req tokenRefreshRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON body", nil, "", nil)
		return
	}
	if req.ProviderID != claims.Subject {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "provider_id does not match the JWT sub claim", nil, "", nil)
		return
	}

	requestTimestamp, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "timestamp must be ISO 8601", nil, "timestamp", nil)
		return
	}
	if absDuration(time.Since(requestTimestamp)) > tokenRefreshSkew {
		WriteError(w, http.StatusBadRequest, ErrInvalidRequest, "timestamp skew exceeds 5 minutes", nil, "timestamp", nil)
		return
	}

	ctx := r.Context()
	providerPublicKey, status, lastRefresh, err := h.lookupProvider(ctx, req.ProviderID)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "unknown provider", nil, "", nil)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "provider lookup failed", nil, "", nil)
		return
	}
	if status == "DEPARTED" {
		WriteError(w, http.StatusForbidden, ErrProviderDeparted, "provider has departed", nil, "", nil)
		return
	}

	if !verifyProviderSig(providerPublicKey, req.ProviderID, req.Timestamp, req.ProviderSig) {
		WriteError(w, http.StatusForbidden, ErrInvalidBodySignature, "invalid provider_sig", nil, "", nil)
		return
	}

	if lastRefresh != nil && time.Since(*lastRefresh) < tokenRefreshRateLimit {
		retryAfter := int(tokenRefreshRateLimit.Seconds()) - int(time.Since(*lastRefresh).Seconds())
		if retryAfter < 0 {
			retryAfter = 0
		}
		WriteError(w, http.StatusTooManyRequests, ErrTokenRefreshRateLimited,
			"token refresh rate limit exceeded; retry in 30 minutes", &retryAfter, "", nil)
		return
	}

	newToken, err := IssueJWT(h.signingKey, req.ProviderID, "provider", ProviderTokenTTL)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "token issuance failed", nil, "", nil)
		return
	}
	expiresAt := time.Now().UTC().Add(ProviderTokenTTL)

	if _, err := h.db.ExecContext(ctx, `UPDATE providers SET last_token_refresh_at = NOW() WHERE provider_id = $1`, req.ProviderID); err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "failed to record refresh", nil, "", nil)
		return
	}

	resp := tokenRefreshResponseBody{Token: newToken, ExpiresAt: expiresAt}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *ProviderTokenRefreshHandler) lookupProvider(ctx context.Context, providerID uuid.UUID) (pubKey [32]byte, status string, lastRefresh *time.Time, err error) {
	var rawKey []byte
	var lastRefreshNull sql.NullTime
	err = h.db.QueryRowContext(ctx, `SELECT ed25519_public_key, status, last_token_refresh_at FROM providers WHERE provider_id = $1`, providerID).
		Scan(&rawKey, &status, &lastRefreshNull)
	if err != nil {
		return pubKey, "", nil, err
	}
	copy(pubKey[:], rawKey)
	if lastRefreshNull.Valid {
		t := lastRefreshNull.Time
		lastRefresh = &t
	}
	return pubKey, status, lastRefresh, nil
}

// verifyProviderSig verifies sigHex (128 hex chars = 64 bytes) against
// SHA-256(providerID.String() || timestamp) — using the raw timestamp
// string exactly as submitted, never re-serialised or normalised (OAS: "no
// normalisation").
func verifyProviderSig(publicKey [32]byte, providerID uuid.UUID, timestamp, sigHex string) bool {
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != 64 {
		return false
	}
	var sig [64]byte
	copy(sig[:], sigBytes)

	signingInput := []byte(providerID.String() + timestamp)
	return crypto.VerifyBytes(publicKey, signingInput, sig)
}

// verifyJWTWithGracePeriod accepts a token that is either currently valid,
// or expired by no more than gracePeriod — the two-factor refresh flow's
// "factor 1" (OAS: "accepted if valid OR if expired within the last 1
// hour"). VerifyJWT itself has no grace-period concept (every other caller
// wants a hard expiry check), so this wraps it rather than complicating
// that function's own contract for one caller's special case.
func verifyJWTWithGracePeriod(publicKey ed25519.PublicKey, token string, gracePeriod time.Duration) (VerifiedClaims, error) {
	claims, err := VerifyJWT(publicKey, token)
	if err == nil {
		return claims, nil
	}
	if !errors.Is(err, ErrJWTExpired) {
		return VerifiedClaims{}, err
	}

	claims, parseErr := parseJWTClaimsIgnoringExpiry(publicKey, token)
	if parseErr != nil {
		return VerifiedClaims{}, parseErr
	}
	if time.Since(claims.Expiry) > gracePeriod {
		return VerifiedClaims{}, ErrJWTExpired
	}
	return claims, nil
}

// parseJWTClaimsIgnoringExpiry duplicates VerifyJWT's signature/format
// checks but skips the expiry comparison — used only by
// verifyJWTWithGracePeriod, which needs the claims of an
// already-known-to-be-expired token to measure how long ago that was.
func parseJWTClaimsIgnoringExpiry(publicKey ed25519.PublicKey, token string) (VerifiedClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != jwtPartsCount {
		return VerifiedClaims{}, ErrJWTMalformed
	}
	signingInput := parts[0] + "." + parts[1]

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return VerifiedClaims{}, ErrJWTMalformed
	}
	if !ed25519.Verify(publicKey, []byte(signingInput), sigBytes) {
		return VerifiedClaims{}, ErrJWTInvalidSignature
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return VerifiedClaims{}, ErrJWTMalformed
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return VerifiedClaims{}, ErrJWTMalformed
	}
	subject, err := uuid.Parse(claims.Sub)
	if err != nil {
		return VerifiedClaims{}, ErrJWTMalformed
	}
	return VerifiedClaims{
		Subject: subject,
		Role:    claims.Role,
		Issuer:  claims.Iss,
		Expiry:  time.Unix(claims.Exp, 0).UTC(),
	}, nil
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
