// Package api is declared in doc.go.
// This file establishes the HTTP routing tree: every operation in OAS's
// paths (verified against its exact operationId), wired with the correct
// auth middleware for its security scheme. Endpoints built so far
// (Phase 11.1 errors, 11.2 readiness, 11.4 auth) are wired to their real
// handlers; everything else remains a 501 stub until its own phase lands.
//
// [Flagged, build.md Phase 11.3] GET /api/v1/provider/downtime
// (getActiveDowntime) is described in Session 11.6.5 but openapi.yaml
// defines only POST /api/v1/provider/downtime (announceDowntime) — no GET
// sibling path, schema, or operationId exists anywhere in the spec. This is
// a genuine prerequisite gap, not an oversight in this file: the row is
// listed in the routing table below for completeness and marked BLOCKED,
// but is NOT registered on the mux until openapi.yaml is updated with the
// GET path (Session 11.6.5 implements the handler LOGIC regardless, just
// unreachable via HTTP for now).
//
// [REF: OAS paths, IC §2, build.md Phase 11.3 Session 11.3.1, Phase 11.4]

package api

import (
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"net/http"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/audit"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/payment"
)

// AdminAPIKeyMinHexLen is the minimum X-Admin-API-Key header length: OAS's
// AdminApiKey security scheme requires "≥32 random bytes hex-encoded" — 32
// bytes hex-encoded is 64 characters.
//
// [Corrected — M12 audit corrections, Finding 9] Exported (was
// adminAPIKeyMinHexLen, unexported) so cmd/microservice/keys.go can import
// and use this single definition instead of maintaining its own
// independently-defined duplicate — see that file's own comment. Both
// copies happened to already agree (64), but "same constant stated in two
// places, kept in sync only by convention" is exactly the class of drift
// bug this project has hit before (M11 review, M8 build.md/CI mismatch).
// adminAPIKeyMinHexLen is kept as a local alias immediately below purely so
// every OTHER reference in this file (which has no reason to spell out the
// full package-qualified name for its own package's own constant) doesn't
// need touching.
const AdminAPIKeyMinHexLen = 64

// adminAPIKeyMinHexLen is a same-package alias for AdminAPIKeyMinHexLen —
// see that constant's own doc comment.
const adminAPIKeyMinHexLen = AdminAPIKeyMinHexLen

// stub501 is the placeholder handler for every not-yet-implemented
// operation (Session 11.3.1). Later sessions in this milestone replace
// individual stub501 registrations with real handlers as each endpoint is
// built; this function itself is never called once every session is done.
func stub501(w http.ResponseWriter, _ *http.Request) {
	WriteError(w, http.StatusNotImplemented, ErrInternal, "not yet implemented", nil, "", nil)
}

// adminAuthMiddleware enforces OAS's AdminApiKey security scheme:
// X-Admin-API-Key header, compared in constant time against the configured
// key, rejecting anything shorter than adminAPIKeyMinHexLen characters
// outright before even attempting the comparison. Per OAS's own
// description, this key must never appear in client-facing code or
// provider daemon builds — it is a server-side-only secret, configured by
// whoever wires this middleware in (Milestone 12), never hardcoded here.
func adminAuthMiddleware(configuredKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provided := r.Header.Get("X-Admin-API-Key")
			if len(provided) < adminAPIKeyMinHexLen {
				WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "missing or malformed X-Admin-API-Key", nil, "", nil)
				return
			}
			if _, err := hex.DecodeString(provided); err != nil {
				WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "X-Admin-API-Key is not valid hex", nil, "", nil)
				return
			}
			if subtle.ConstantTimeCompare([]byte(provided), []byte(configuredKey)) != 1 {
				WriteError(w, http.StatusUnauthorized, ErrUnauthorized, "invalid X-Admin-API-Key", nil, "", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RouterConfig bundles every dependency NewRouter needs. It grows as later
// phases in this milestone wire in more real handlers (payment, scoring,
// repair) — a config struct rather than an ever-longer parameter list.
type RouterConfig struct {
	AdminAPIKey string
	DB          *sql.DB

	// JWT signing/verification (Phase 11.4). JWTPublicKey/JWTPrivateKey are
	// the SAME keypair — split into two fields because most callers need
	// only one half (verification-only middleware never sees the private
	// key; issuance-only code never needs the public key separately).
	JWTPublicKey  ed25519.PublicKey
	JWTPrivateKey ed25519.PrivateKey
	JWTKeyID      string // e.g. "vyomanaut-ms-2026-q2" (OAS JwksResponse.kid)

	OtpSender OtpSender // NoopOtpSender{} until real SMS delivery exists

	Readiness *ReadinessEvaluator

	Profile         config.NetworkProfile // Phase 11.5+
	PaymentProvider payment.PaymentProvider
	InFlightUploads InFlightUploadChecker // NoInFlightUploadChecker{} until Phase 11.7's tracking exists

	// ClusterSecretCache backs POST /api/v1/audit/challenge (Phase 11.9).
	// Must already have a successful Load() before being wired in here —
	// see AuditChallengeHandler's own constructor note. nil until whichever
	// later milestone owns cluster-secret startup wires it (mirrors
	// cfg.Readiness's own "may be nil until its owning milestone" pattern).
	ClusterSecretCache *audit.ClusterSecretCache
}

// NewRouter builds the full HTTP routing tree from cfg.
func NewRouter(cfg RouterConfig) *http.ServeMux {
	mux := http.NewServeMux()
	adminAuth := adminAuthMiddleware(cfg.AdminAPIKey)
	admin := func(h http.HandlerFunc) http.Handler { return adminAuth(h) }
	bearerAny := bearerAuthAny(cfg.JWTPublicKey)
	owner := func(h http.HandlerFunc) http.Handler { return bearerAuthRole(cfg.JWTPublicKey, "owner")(h) }
	provider := func(h http.HandlerFunc) http.Handler { return bearerAuthRole(cfg.JWTPublicKey, "provider")(h) }

	otpHandler := NewOtpHandler(cfg.DB, cfg.OtpSender)
	otpVerifyHandler := NewOtpVerifyHandler(otpHandler, cfg.JWTPrivateKey)
	tokenRefreshHandler := NewProviderTokenRefreshHandler(cfg.DB, cfg.JWTPublicKey, cfg.JWTPrivateKey)
	pricingEstimateHandler := NewPricingEstimateHandler(cfg.Profile)
	providerEarningsEstimateHandler := NewProviderEarningsEstimateHandler(cfg.Profile)
	ownerRegisterHandler := NewOwnerRegisterHandler(cfg.DB, cfg.JWTPrivateKey)
	var ownerDepositHandler *OwnerDepositHandler
	if cfg.PaymentProvider != nil {
		ownerDepositHandler = NewOwnerDepositHandler(cfg.PaymentProvider)
	}
	ownerBalanceHandler := NewOwnerBalanceHandler(cfg.DB, cfg.Profile)
	ownerFileListHandler := NewOwnerFileListHandler(cfg.DB, cfg.Profile)
	ownerEscrowHistoryHandler := NewOwnerEscrowHistoryHandler(cfg.DB, cfg.Profile)
	var ownerWithdrawHandler *OwnerWithdrawHandler
	if cfg.PaymentProvider != nil {
		inFlight := cfg.InFlightUploads
		if inFlight == nil {
			inFlight = NoInFlightUploadChecker{}
		}
		ownerWithdrawHandler = NewOwnerWithdrawHandler(cfg.DB, cfg.Profile, cfg.PaymentProvider, inFlight)
	}

	// ── Public routes: no auth middleware ──────────────────────────────────
	mux.HandleFunc("GET /.well-known/jwks.json", HandleJWKS(cfg.JWTPublicKey, cfg.JWTKeyID))                // getJwks
	mux.HandleFunc("POST /api/v1/auth/otp/send", otpHandler.HandleSend)                                     // sendOtp
	mux.HandleFunc("POST /api/v1/auth/otp/verify", otpVerifyHandler.HandleVerify)                           // verifyOtp
	mux.HandleFunc("GET /api/v1/pricing/estimate", pricingEstimateHandler.HandleEstimate)                   // getPricingEstimate
	mux.HandleFunc("GET /api/v1/pricing/provider-estimate", providerEarningsEstimateHandler.HandleEstimate) // getProviderEarningsEstimate

	// ── BearerAuth routes ────────────────────────────────────────────────────
	// register endpoints accept ANY validly-signed token, registration
	// tokens included (bearerAny) — that is exactly the token type OTP
	// verify hands a new entity. Every other BearerAuth route requires the
	// specific role it names, which also means a registration token is
	// correctly rejected everywhere except the two register endpoints.
	mux.Handle("POST /api/v1/owner/register", bearerAny(http.HandlerFunc(ownerRegisterHandler.HandleRegister))) // registerOwner
	if ownerDepositHandler != nil {
		mux.Handle("POST /api/v1/owner/deposit", owner(ownerDepositHandler.HandleDeposit)) // initiateDeposit
	} else {
		mux.Handle("POST /api/v1/owner/deposit", owner(stub501))
	}
	mux.Handle("GET /api/v1/owner/{owner_id}/balance", owner(ownerBalanceHandler.HandleBalance))            // getOwnerBalance
	mux.Handle("GET /api/v1/owner/{owner_id}/files", owner(ownerFileListHandler.HandleFiles))               // listOwnerFiles
	mux.Handle("GET /api/v1/owner/{owner_id}/escrow", owner(ownerEscrowHistoryHandler.HandleEscrowHistory)) // getOwnerEscrowHistory
	if ownerWithdrawHandler != nil {
		mux.Handle("POST /api/v1/owner/withdraw", owner(ownerWithdrawHandler.HandleWithdraw)) // withdrawOwnerEscrow
	} else {
		mux.Handle("POST /api/v1/owner/withdraw", owner(stub501))
	}
	providerRegisterHandler := NewProviderRegisterHandler(cfg.DB, cfg.JWTPrivateKey, cfg.Profile)
	providerHeartbeatHandler := NewProviderHeartbeatHandler(cfg.DB, cfg.JWTPrivateKey)
	providerStatusHandler := NewProviderStatusHandler(cfg.DB, cfg.Profile, cfg.PaymentProvider)
	providerReceiptsHandler := NewProviderReceiptsHandler(cfg.DB)
	providerDowntimeHandler := NewProviderDowntimeHandler(cfg.DB, cfg.Profile)
	providerDepartHandler := NewProviderDepartHandler(cfg.DB, cfg.Profile, cfg.PaymentProvider)
	var auditChallengeHandler *AuditChallengeHandler
	if cfg.ClusterSecretCache != nil {
		auditChallengeHandler = NewAuditChallengeHandler(cfg.DB, cfg.Profile, cfg.ClusterSecretCache)
	}

	mux.Handle("POST /api/v1/provider/register", bearerAny(http.HandlerFunc(providerRegisterHandler.HandleRegister))) // registerProvider
	mux.Handle("POST /api/v1/provider/heartbeat", provider(providerHeartbeatHandler.HandleHeartbeat))                 // providerHeartbeat
	mux.HandleFunc("POST /api/v1/provider/token/refresh", tokenRefreshHandler.HandleRefresh)                          // refreshProviderToken — its own two-factor auth, not bearerAuthRole
	mux.Handle("GET /api/v1/provider/{provider_id}/status", provider(providerStatusHandler.HandleStatus))             // getProviderStatus
	mux.Handle("GET /api/v1/provider/receipts", provider(providerReceiptsHandler.HandleReceipts))                     // listProviderReceipts
	mux.Handle("POST /api/v1/provider/downtime", provider(providerDowntimeHandler.HandleAnnounce))                    // announceDowntime
	// GET /api/v1/provider/downtime (getActiveDowntime): BLOCKED — not yet in
	// openapi.yaml (flagged gap, this file's header comment). Not registered
	// until the OAS path exists; ProviderDowntimeHandler.HandleGetActive
	// implements the handler logic directly-testably in the meantime.
	mux.Handle("POST /api/v1/provider/depart", provider(providerDepartHandler.HandleDepart)) // announceDeparture
	fileRegisterHandler := NewFileRegisterHandler(cfg.DB)
	pointerFileHandler := NewPointerFileHandler(cfg.DB)
	fileDeleteHandler := NewFileDeleteHandler(cfg.DB, cfg.Profile)

	if cfg.Readiness != nil {
		uploadAssignHandler := NewUploadAssignHandler(cfg.DB, cfg.Profile, cfg.JWTPrivateKey, cfg.Readiness)
		mux.Handle("POST /api/v1/upload/assign", owner(uploadAssignHandler.HandleAssign)) // assignUpload
	} else {
		mux.Handle("POST /api/v1/upload/assign", owner(stub501))
	}
	mux.Handle("POST /api/v1/file/register", owner(fileRegisterHandler.HandleRegister))       // registerFile
	mux.Handle("GET /api/v1/file/{file_id}/pointer", owner(pointerFileHandler.HandlePointer)) // getPointerFile
	mux.Handle("DELETE /api/v1/file/{file_id}", owner(fileDeleteHandler.HandleDelete))        // deleteFile

	// retrieveResolveHandler mints download capability tokens (ADR-080) —
	// same signing key as uploadAssignHandler's upload tokens above
	// (cfg.JWTPrivateKey), so both verify against the single msPublicKey
	// every provider daemon already holds. No Readiness gate: unlike
	// upload, resolving an already-ACTIVE file's existing shards has no
	// network-readiness precondition to check.
	retrieveResolveHandler := NewRetrieveResolveHandler(cfg.DB, cfg.JWTPrivateKey)
	mux.Handle("POST /api/v1/owner/files/{file_id}/retrieve/resolve", owner(retrieveResolveHandler.HandleResolve)) // resolveRetrieval

	// ── AdminApiKey routes ──────────────────────────────────────────────────
	if auditChallengeHandler != nil {
		mux.Handle("POST /api/v1/audit/challenge", admin(auditChallengeHandler.HandleDispatch)) // dispatchAuditChallenge
	} else {
		mux.Handle("POST /api/v1/audit/challenge", admin(stub501))
	}
	if cfg.Readiness != nil {
		mux.Handle("GET /api/v1/admin/readiness", admin(http.HandlerFunc(cfg.Readiness.HandleReadiness))) // getReadiness
	} else {
		mux.Handle("GET /api/v1/admin/readiness", admin(stub501))
	}
	adminProvidersHandler := NewAdminProvidersHandler(cfg.DB)
	repairQueueHandler := NewRepairQueueHandler(cfg.DB)
	manualRepairTriggerHandler := NewManualRepairTriggerHandler(cfg.DB, cfg.Profile)
	auditStatsHandler := NewAuditStatsHandler(cfg.DB)
	vettingStatusHandler := NewVettingStatusHandler(cfg.DB)
	vettingGCRetryHandler := NewVettingGCRetryHandler(cfg.DB)
	// M17-E Session 17.6.1, ADR-084 §D-2a: the one new admin endpoint that
	// milestone authorised — cmd/operator's `shards <file_id>` command is
	// its only intended caller.
	shardsHandler := NewAdminFileShardsHandler(cfg.DB, cfg.Profile)
	// M17-E Session 17.6.3, ADR-084 Design Council Addendum A: a second,
	// deliberately reviewed exception to that session's own
	// NO_ADDITIONAL_ROUTES gate — see admin.go's own header note on this
	// handler for the full framing (why a read-only preview, not a
	// mutating trigger). cmd/operator's `payout` command is its only
	// intended caller.
	payoutPreviewHandler := NewAdminPayoutPreviewHandler(cfg.DB)

	mux.Handle("GET /api/v1/admin/repair/queue", admin(repairQueueHandler.HandleQueue))              // getRepairQueue
	mux.Handle("POST /api/v1/admin/repair/trigger", admin(manualRepairTriggerHandler.HandleTrigger)) // triggerRepair
	mux.Handle("GET /api/v1/admin/providers", admin(adminProvidersHandler.HandleList))               // listAdminProviders
	mux.Handle("GET /api/v1/admin/audit/stats", admin(auditStatsHandler.HandleStats))                // getAuditStats
	mux.Handle("GET /api/v1/admin/vetting/status", admin(vettingStatusHandler.HandleStatus))         // getVettingStatus
	mux.Handle("POST /api/v1/admin/vetting/gc/retry", admin(vettingGCRetryHandler.HandleRetry))      // retryVettingGC
	mux.Handle("GET /api/v1/admin/file/{file_id}/shards", admin(shardsHandler.HandleShards))         // getFileShards
	mux.Handle("GET /api/v1/admin/payout/preview", admin(payoutPreviewHandler.HandlePreview))        // getPayoutPreview (M17-E 17.6.3, ADR-084 addendum A)

	// ── Webhook: signature auth (IC §7), confirmed absent from OAS by design ──
	mux.HandleFunc("POST /webhooks/razorpay", stub501)

	return mux
}
