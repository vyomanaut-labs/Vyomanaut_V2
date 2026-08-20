// Package api is declared in doc.go.
// Unit tests for the routing tree: every still-stubbed route returns 501
// once past whatever auth it requires; admin routes reject a missing or
// too-short X-Admin-API-Key; public routes need no auth at all; BearerAuth
// routes reject a missing/wrong-role token.
//
// Tests:
//   - TestAllStubRoutesReturn501WithValidAuth
//   - TestAdminRoutesRejectMissingAPIKey
//   - TestAdminRoutesRejectShortAPIKey
//   - TestPublicRoutesAccessibleWithoutAuth
//   - TestBearerRoutesRejectMissingToken
//   - TestBearerRoutesRejectWrongRole
//
// [REF: OAS paths, build.md Phase 11.3 Session 11.3.1, Phase 11.4]

package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// testAdminKey returns a valid-shaped (64 hex chars = 32 bytes) admin key.
func testAdminKey(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// testRouterConfig builds a RouterConfig suitable for router-level tests: a
// real (throwaway) test DB, a fresh JWT keypair, and NoopOtpSender. Returns
// the config alongside the admin key and JWT private key so tests can mint
// matching credentials.
func testRouterConfig(t *testing.T) (cfg RouterConfig, adminKey string, jwtPriv ed25519.PrivateKey) {
	t.Helper()
	db := openTestDB(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	adminKey = testAdminKey(t)
	cfg = RouterConfig{
		AdminAPIKey:   adminKey,
		DB:            db,
		JWTPublicKey:  pub,
		JWTPrivateKey: priv,
		JWTKeyID:      "test-key",
		OtpSender:     NoopOtpSender{},
	}
	return cfg, adminKey, priv
}

// authKind describes what a route needs to get past its middleware.
type authKind int

const (
	authNone authKind = iota
	authAdmin
	authBearerAny
	authBearerOwner
	authBearerProvider
)

// routeFixture describes one registered route, with any path parameters
// already substituted with a placeholder value.
type routeFixture struct {
	method      string
	path        string
	auth        authKind
	implemented bool // true if this route has real logic, not a 501 stub
}

// allRegisteredRoutes mirrors router.go's own registrations (excluding the
// deliberately-unregistered GET /api/v1/provider/downtime — see router.go's
// header comment on that flagged OAS gap).
func allRegisteredRoutes() []routeFixture {
	return []routeFixture{
		{"GET", "/.well-known/jwks.json", authNone, true},
		{"POST", "/api/v1/auth/otp/send", authNone, true},
		{"POST", "/api/v1/auth/otp/verify", authNone, true},
		{"GET", "/api/v1/pricing/estimate", authNone, true},
		{"GET", "/api/v1/pricing/provider-estimate", authNone, true},
		{"POST", "/api/v1/owner/register", authBearerAny, true},
		{"POST", "/api/v1/owner/deposit", authBearerOwner, false},
		{"GET", "/api/v1/owner/11111111-1111-1111-1111-111111111111/balance", authBearerOwner, true},
		{"GET", "/api/v1/owner/11111111-1111-1111-1111-111111111111/files", authBearerOwner, true},
		{"GET", "/api/v1/owner/11111111-1111-1111-1111-111111111111/escrow", authBearerOwner, true},
		{"POST", "/api/v1/owner/withdraw", authBearerOwner, false},
		{"POST", "/api/v1/provider/register", authBearerAny, true},
		{"POST", "/api/v1/provider/heartbeat", authBearerProvider, true},
		{"POST", "/api/v1/provider/token/refresh", authNone, true}, // its own two-factor auth, checked inside the handler
		{"GET", "/api/v1/provider/11111111-1111-1111-1111-111111111111/status", authBearerProvider, true},
		{"GET", "/api/v1/provider/receipts", authBearerProvider, true},
		{"POST", "/api/v1/provider/downtime", authBearerProvider, true},
		{"POST", "/api/v1/provider/depart", authBearerProvider, true},
		{"POST", "/api/v1/upload/assign", authBearerOwner, false}, // cfg.Readiness left nil in these tests -> still stub501
		{"POST", "/api/v1/file/register", authBearerOwner, true},
		{"GET", "/api/v1/file/11111111-1111-1111-1111-111111111111/pointer", authBearerOwner, true},
		{"DELETE", "/api/v1/file/11111111-1111-1111-1111-111111111111", authBearerOwner, true},
		{"POST", "/api/v1/audit/challenge", authAdmin, false}, // cfg.ClusterSecretCache left nil in these tests -> still stub501
		{"GET", "/api/v1/admin/readiness", authAdmin, false},  // cfg.Readiness left nil in these tests -> still stub501
		{"GET", "/api/v1/admin/repair/queue", authAdmin, true},
		{"POST", "/api/v1/admin/repair/trigger", authAdmin, true},
		{"GET", "/api/v1/admin/providers", authAdmin, true},
		{"GET", "/api/v1/admin/audit/stats", authAdmin, true},
		{"GET", "/api/v1/admin/vetting/status", authAdmin, true},
		{"POST", "/api/v1/admin/vetting/gc/retry", authAdmin, true},
		{"GET", "/api/v1/admin/file/11111111-1111-1111-1111-111111111111/shards", authAdmin, true}, // M17-E Session 17.6.1, ADR-084 §D-2a
		{"POST", "/webhooks/razorpay", authNone, false},
	}
}

func TestAllStubRoutesReturn501WithValidAuth(t *testing.T) {
	cfg, adminKey, jwtPriv := testRouterConfig(t)
	mux := NewRouter(cfg)

	for _, rt := range allRegisteredRoutes() {
		if rt.implemented {
			continue // has real logic now; not a 501 stub, covered by its own dedicated tests
		}
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			switch rt.auth {
			case authNone:
				// no credential needed
			case authAdmin:
				req.Header.Set("X-Admin-API-Key", adminKey)
			case authBearerAny:
				token, err := IssueJWT(jwtPriv, uuid.New(), "", RegistrationTokenTTL)
				if err != nil {
					t.Fatalf("IssueJWT: %v", err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
			case authBearerOwner:
				token, err := IssueJWT(jwtPriv, uuid.New(), "owner", OwnerTokenTTL)
				if err != nil {
					t.Fatalf("IssueJWT: %v", err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
			case authBearerProvider:
				token, err := IssueJWT(jwtPriv, uuid.New(), "provider", ProviderTokenTTL)
				if err != nil {
					t.Fatalf("IssueJWT: %v", err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != 501 {
				t.Errorf("%s %s: status = %d, want 501, body = %s", rt.method, rt.path, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), string(ErrInternal)) {
				t.Errorf("%s %s: body %q does not contain error_code %q", rt.method, rt.path, rec.Body.String(), ErrInternal)
			}
		})
	}
}

func TestAdminRoutesRejectMissingAPIKey(t *testing.T) {
	cfg, _, _ := testRouterConfig(t)
	mux := NewRouter(cfg)

	for _, rt := range allRegisteredRoutes() {
		if rt.auth != authAdmin {
			continue
		}
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil) // no X-Admin-API-Key header at all
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != 401 && rec.Code != 403 {
				t.Errorf("%s %s: status = %d, want 401 or 403 (missing key), not 501", rt.method, rt.path, rec.Code)
			}
		})
	}
}

func TestAdminRoutesRejectShortAPIKey(t *testing.T) {
	cfg, _, _ := testRouterConfig(t)
	mux := NewRouter(cfg)

	shortKey := "deadbeef" // 8 hex chars = 4 bytes, well under the 32-byte minimum
	req := httptest.NewRequest("GET", "/api/v1/admin/providers", nil)
	req.Header.Set("X-Admin-API-Key", shortKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 401 && rec.Code != 403 {
		t.Errorf("short API key: status = %d, want 401 or 403", rec.Code)
	}
}

func TestPublicRoutesAccessibleWithoutAuth(t *testing.T) {
	cfg, _, _ := testRouterConfig(t)
	mux := NewRouter(cfg)

	for _, rt := range allRegisteredRoutes() {
		if rt.auth != authNone {
			continue
		}
		if rt.path == "/api/v1/provider/token/refresh" {
			// authNone here means "no shared middleware", not "no auth
			// required" — this route always needs its own internal
			// two-factor auth (see TestRefresh* in token_refresh_test.go).
			continue
		}
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil) // no auth headers of any kind
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code == 401 || rec.Code == 403 {
				t.Errorf("%s %s: status = %d, want a non-auth-rejection status (this route needs no auth)",
					rt.method, rt.path, rec.Code)
			}
		})
	}
}

func TestBearerRoutesRejectMissingToken(t *testing.T) {
	cfg, _, _ := testRouterConfig(t)
	mux := NewRouter(cfg)

	for _, rt := range allRegisteredRoutes() {
		if rt.auth != authBearerAny && rt.auth != authBearerOwner && rt.auth != authBearerProvider {
			continue
		}
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil) // no Authorization header
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != 401 {
				t.Errorf("%s %s: status = %d, want 401 (missing bearer token)", rt.method, rt.path, rec.Code)
			}
		})
	}
}

func TestBearerRoutesRejectWrongRole(t *testing.T) {
	cfg, _, jwtPriv := testRouterConfig(t)
	mux := NewRouter(cfg)

	for _, rt := range allRegisteredRoutes() {
		// Present an OWNER token to a route that specifically requires
		// PROVIDER, and vice versa — bearerAny routes accept any role, so
		// they're skipped here (there is no "wrong" role for them).
		var wrongRole string
		switch rt.auth {
		case authNone, authAdmin, authBearerAny:
			continue
		case authBearerOwner:
			wrongRole = "provider"
		case authBearerProvider:
			wrongRole = "owner"
		}
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			token, err := IssueJWT(jwtPriv, uuid.New(), wrongRole, OwnerTokenTTL)
			if err != nil {
				t.Fatalf("IssueJWT: %v", err)
			}
			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != 403 {
				t.Errorf("%s %s: status = %d, want 403 (wrong role %q presented)", rt.method, rt.path, rec.Code, wrongRole)
			}
		})
	}
}
