// Package api is declared in doc.go.
// This file implements the readiness evaluator and GET /api/v1/admin/readiness.
//
// [Flagged and corrected, build.md Phase 11.2] IC §3.4 sketches a response
// body ({"ready": bool, "conditions": {"active_providers": {"value",
// "threshold", "met"}, ...}, "evaluated_at": "..."}) that does not match
// OAS's actual ReadinessResponse/ReadinessCondition schemas at all — two
// different, non-overlapping JSON shapes. Per IC §3's own rule, OAS wins.
// This file implements OAS's shape (all_conditions_met, mode, conditions
// keyed by active_vetted_providers/distinct_asns/distinct_metro_regions/
// microservice_quorum/razorpay_accounts_ready/relay_nodes_deployed/
// cluster_audit_secret_loaded, each a ReadinessCondition with name/
// satisfied/current_value/required_value/demo_value). IC §3.4's condition
// table (data source + threshold per condition) is unaffected and remains
// the right reference for the evaluation logic itself.
//
// [Flagged and corrected, build.md Phase 11.2] The original task's quorum
// condition instructions said the threshold "must read from
// NetworkProfile.MinActiveProviders" — a copy-paste error from the
// active-providers condition. There is no dedicated integer profile field
// for the quorum replica count; OAS's own description confirms this is
// DERIVED from the boolean RequireQuorum (3 if true, 1 if false), not read
// from any named field. Implemented as a derivation below, never referencing
// MinActiveProviders.
//
// [Decision] No relay-heartbeat table exists anywhere in the schema (no
// milestone through 11 has built one). RelayNodeCounter is an injected
// interface — analogous to ClusterMembership below — with a stub default
// (always 0), which is correct for demo mode (profile.MinRelayNodes == 0)
// and a conservative placeholder for production until relay infrastructure
// is actually built.
//
// [REF: OAS components/schemas/ReadinessResponse, ReadinessCondition,
// IC §3.4, FR-053, FR-054, ADR-029, build.md Phase 11.2 Session 11.2.1]

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/audit"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// productionQuorumSize and soloInstanceSize are the two possible derived
// values for the microservice_quorum condition (ADR-025, ADR-031) — never
// read from NetworkProfile.MinActiveProviders (see this file's own header
// note on that copy-paste bug).
const (
	productionQuorumSize = 3
	soloInstanceSize     = 1
)

// clusterAuditSecretRequiredValue is the required_value ReadinessCondition
// reports for cluster_audit_secret_loaded — a boolean condition represented
// as 0/1 so it fits the same integer-typed ReadinessCondition shape OAS
// uses for every other condition (current_value/required_value are
// non-nullable integers in OAS, with no boolean variant).
const clusterAuditSecretRequiredValue = 1

// ClusterMembership reports the current gossip cluster's healthy replica
// count (ADR-025). Until Milestone 17 Phase 17.2.1 delivers the real gossip
// cluster, MockClusterMembership stands in.
type ClusterMembership interface {
	HealthyCount() int
}

// MockClusterMembership always reports 3 healthy replicas — a stub
// injected by Milestone 12 until the real gossip cluster exists.
type MockClusterMembership struct{}

func (MockClusterMembership) HealthyCount() int { return productionQuorumSize }

// RelayNodeCounter reports how many relay nodes are currently deployed —
// see this file's header note: no backing table exists yet anywhere in the
// schema.
type RelayNodeCounter interface {
	Count(ctx context.Context) (int, error)
}

// StubRelayNodeCounter always reports zero — correct for demo mode
// (profile.MinRelayNodes == 0) and a safe placeholder for production until
// real relay infrastructure exists.
type StubRelayNodeCounter struct{}

func (StubRelayNodeCounter) Count(context.Context) (int, error) { return 0, nil }

// ReadinessCondition mirrors OAS components/schemas/ReadinessCondition.
type ReadinessCondition struct {
	Name          string `json:"name"`
	Satisfied     bool   `json:"satisfied"`
	CurrentValue  int    `json:"current_value"`
	RequiredValue int    `json:"required_value"`
	DemoValue     *int   `json:"demo_value,omitempty"`
}

// ReadinessConditions mirrors the seven required keys of OAS
// ReadinessResponse.conditions.
type ReadinessConditions struct {
	ActiveVettedProviders    ReadinessCondition `json:"active_vetted_providers"`
	DistinctASNs             ReadinessCondition `json:"distinct_asns"`
	DistinctMetroRegions     ReadinessCondition `json:"distinct_metro_regions"`
	MicroserviceQuorum       ReadinessCondition `json:"microservice_quorum"`
	RazorpayAccountsReady    ReadinessCondition `json:"razorpay_accounts_ready"`
	RelayNodesDeployed       ReadinessCondition `json:"relay_nodes_deployed"`
	ClusterAuditSecretLoaded ReadinessCondition `json:"cluster_audit_secret_loaded"`
}

// ReadinessResponse mirrors OAS components/schemas/ReadinessResponse.
//
// ProvidersNearCeilingCount (build.md Phase 11.11 Session 11.11.1, NFR-044)
// is informational/non-gating — it does not participate in
// AllConditionsMet — surfacing how many ACTIVE providers are approaching
// the per-provider chunk storage ceiling upload/assign enforces (upload.go).
//
// EffectiveDepartureThresholdSeconds (M17-E Session 17.7.1, ADR-084 §D-4)
// is likewise informational/non-gating: the console's own live countdown
// (cmd/operator/panels.go) needs the AUTHORITATIVE detection-latency value
// actually governing repair.NewDepartureDetector right now — which may
// differ from the compiled profile constant whenever cmd/microservice was
// started with its own departure-threshold override flag — not a
// separately-configured guess that could silently disagree with it.
type ReadinessResponse struct {
	AllConditionsMet                   bool                `json:"all_conditions_met"`
	EvaluatedAt                        time.Time           `json:"evaluated_at"`
	Mode                               string              `json:"mode"`
	Conditions                         ReadinessConditions `json:"conditions"`
	ProvidersNearCeilingCount          int                 `json:"providers_near_ceiling_count"`
	EffectiveDepartureThresholdSeconds int64               `json:"effective_departure_threshold_seconds"`
}

// ReadinessEvaluator evaluates all seven readiness conditions (ADR-029,
// FR-053, FR-054).
//
// [Corrected — M12 audit corrections, Finding 3] Evaluate itself still
// computes all seven conditions fresh on every call — that part of this
// struct's original design was always correct. What changed: this file's
// ORIGINAL comment here said the 60-second caching cadence IC §3.4/FR-054
// requires was "a background-goroutine concern (Milestone 12, Session
// 12.1.1)... the HTTP handler here reads whatever the caller (Milestone 12)
// has it call on that cadence" — but that cache was never actually built.
// Both this file's own HandleReadiness and internal/api/upload.go's
// UploadAssignHandler called Evaluate live, synchronously, on every single
// request instead — including the busiest write path in the system
// (upload/assign), running 5+ DB queries, a gossip-membership call, and a
// secrets-cache check on every one, every time, instead of once a minute.
//
// RefreshCache/Cached below (an atomic-pointer-backed cache) are the
// missing piece: HandleReadiness and UploadAssignHandler now read from
// Cached() instead of calling Evaluate directly. See RefreshCache's own doc
// comment for the refresh-loop wiring
// (cmd/microservice/background_loops.go's startReadinessMonitorLoop) and
// Cached's own doc comment for the cold-start fallback that keeps
// correctness intact before the very first refresh ever runs.
type ReadinessEvaluator struct {
	db                 *sql.DB
	profile            config.NetworkProfile
	clusterSecretCache *audit.ClusterSecretCache
	clusterMembership  ClusterMembership
	relayNodeCounter   RelayNodeCounter

	// effectiveDepartureThreshold (M17-E Session 17.7.1, ADR-084 §D-4) is
	// threaded in separately from the profile field above, by design: this
	// package deliberately does not read config.NetworkProfile's own
	// detection-latency setting anywhere in this file — the departure
	// detector (internal/repair) remains the ONLY reader of that specific
	// field inside internal/ (build.md's own "single read site" property,
	// which is what makes a runtime override low-risk in the first place).
	// cmd/microservice/main.go computes the authoritative value once
	// (validated against ADR-084's derived floor) and passes it here
	// explicitly, so this evaluator reports EXACTLY what the running
	// detector is actually using, never a second, independently-derived
	// guess that could drift from it.
	effectiveDepartureThreshold time.Duration

	// cached holds the last RefreshCache result. nil until the first
	// refresh ever completes (see Cached's own doc comment for how callers
	// must handle that window). A pointer, not a value, so Store/Load are
	// single, atomic pointer-swap operations — no partial-struct read is
	// ever possible, and no mutex is needed for what is otherwise a
	// single-writer (the refresh loop), many-reader (every HTTP request)
	// access pattern.
	cached atomic.Pointer[ReadinessResponse]
}

// NewReadinessEvaluator constructs a ReadinessEvaluator. clusterMembership
// and relayNodeCounter may be MockClusterMembership{} / StubRelayNodeCounter{}
// until their respective real subsystems exist (see this file's header note).
// effectiveDepartureThreshold should be exactly the duration value the
// caller is also handing to repair.NewDepartureDetector — see this
// struct's own field doc comment on why this evaluator holds that value
// independently rather than reading it out of profile.
func NewReadinessEvaluator(
	db *sql.DB,
	profile config.NetworkProfile,
	clusterSecretCache *audit.ClusterSecretCache,
	clusterMembership ClusterMembership,
	relayNodeCounter RelayNodeCounter,
	effectiveDepartureThreshold time.Duration,
) *ReadinessEvaluator {
	return &ReadinessEvaluator{
		db:                          db,
		profile:                     profile,
		clusterSecretCache:          clusterSecretCache,
		clusterMembership:           clusterMembership,
		relayNodeCounter:            relayNodeCounter,
		effectiveDepartureThreshold: effectiveDepartureThreshold,
	}
}

// demoValue returns a pointer to requiredValue when profile.IsDemoMode is
// true, and nil otherwise (OAS ReadinessCondition.demo_value: "Null when the
// system is running in production mode").
//
// [M11 audit remediation, Finding 7 (CR-01)] Was profile.Mode != "demo" —
// see config.NetworkProfile.IsDemoMode's doc comment for why.
func (e *ReadinessEvaluator) demoValue(requiredValue int) *int {
	if !e.profile.IsDemoMode {
		return nil
	}
	v := requiredValue
	return &v
}

// Evaluate computes all seven conditions and the overall
// all_conditions_met flag (the AND of all seven satisfied flags).
func (e *ReadinessEvaluator) Evaluate(ctx context.Context) (ReadinessResponse, error) {
	activeVettedCond, err := e.evaluateActiveVettedProviders(ctx)
	if err != nil {
		return ReadinessResponse{}, fmt.Errorf("api.ReadinessEvaluator.Evaluate: active_vetted_providers: %w", err)
	}
	asnCond, err := e.evaluateDistinctASNs(ctx)
	if err != nil {
		return ReadinessResponse{}, fmt.Errorf("api.ReadinessEvaluator.Evaluate: distinct_asns: %w", err)
	}
	regionCond, err := e.evaluateDistinctMetroRegions(ctx)
	if err != nil {
		return ReadinessResponse{}, fmt.Errorf("api.ReadinessEvaluator.Evaluate: distinct_metro_regions: %w", err)
	}
	quorumCond := e.evaluateQuorum()
	razorpayCond, err := e.evaluateRazorpayAccountsReady(ctx) // LIVE QUERY — never cached, re-run every evaluation cycle (ADR-029)
	if err != nil {
		return ReadinessResponse{}, fmt.Errorf("api.ReadinessEvaluator.Evaluate: razorpay_accounts_ready: %w", err)
	}
	relayCond, err := e.evaluateRelayNodesDeployed(ctx)
	if err != nil {
		return ReadinessResponse{}, fmt.Errorf("api.ReadinessEvaluator.Evaluate: relay_nodes_deployed: %w", err)
	}
	secretCond := e.evaluateClusterAuditSecretLoaded()

	// Informational/non-gating (NFR-044, build.md Phase 11.11) — computed
	// alongside the seven gating conditions but deliberately excluded from
	// allMet below.
	nearCeilingCount, err := providersNearChunkCeilingCount(ctx, e.db, chunkCeilingMaxChunks(e.profile))
	if err != nil {
		return ReadinessResponse{}, fmt.Errorf("api.ReadinessEvaluator.Evaluate: providers_near_ceiling_count: %w", err)
	}

	conditions := ReadinessConditions{
		ActiveVettedProviders:    activeVettedCond,
		DistinctASNs:             asnCond,
		DistinctMetroRegions:     regionCond,
		MicroserviceQuorum:       quorumCond,
		RazorpayAccountsReady:    razorpayCond,
		RelayNodesDeployed:       relayCond,
		ClusterAuditSecretLoaded: secretCond,
	}

	allMet := activeVettedCond.Satisfied && asnCond.Satisfied && regionCond.Satisfied &&
		quorumCond.Satisfied && razorpayCond.Satisfied && relayCond.Satisfied && secretCond.Satisfied

	return ReadinessResponse{
		AllConditionsMet:                   allMet,
		EvaluatedAt:                        time.Now().UTC(),
		Mode:                               e.profile.Mode,
		Conditions:                         conditions,
		ProvidersNearCeilingCount:          nearCeilingCount,
		EffectiveDepartureThresholdSeconds: int64(e.effectiveDepartureThreshold.Seconds()),
	}, nil
}

// RefreshCache runs a full Evaluate and atomically stores the result for
// Cached to serve, then returns it. This is the "background goroutine on a
// 60-second cadence" IC §3.4 requires — see cmd/microservice/
// background_loops.go's startReadinessMonitorLoop, the only intended
// caller. Every field is recomputed fresh on every call, including
// evaluateRazorpayAccountsReady's own live query (ADR-029: "MUST NOT cache
// this value between evaluations — it must re-query each 60-second
// cycle") — RefreshCache satisfies that requirement exactly, since it is
// the thing that runs once per 60-second cycle; nothing about caching the
// overall RESPONSE between refreshes touches that sub-condition's own
// re-query-every-cycle rule.
//
// Returns Evaluate's error unchanged, WITHOUT updating cached — a failed
// refresh leaves the previous (still-valid-ish) cached value in place
// rather than clobbering it with nothing, so a single transient DB hiccup
// during one 60-second tick doesn't turn into total readiness-check
// unavailability for every request until the next successful tick.
func (e *ReadinessEvaluator) RefreshCache(ctx context.Context) (ReadinessResponse, error) {
	resp, err := e.Evaluate(ctx)
	if err != nil {
		return ReadinessResponse{}, err
	}
	e.cached.Store(&resp)
	return resp, nil
}

// Cached returns the most recent RefreshCache result. ok is false only
// during the brief startup window before the very first refresh has ever
// completed (cmd/microservice/background_loops.go's
// startReadinessMonitorLoop runs one immediately, before entering its
// ticker loop, specifically to keep this window as short as possible — see
// that function's own doc comment).
//
// Callers (HandleReadiness, UploadAssignHandler) MUST treat ok == false as
// "fall back to a live Evaluate call for this one request" rather than
// either failing the request outright or — worse — silently proceeding as
// if the system were ready with no evaluation having ever actually run.
// This is a startup-only fallback, not a routine code path: once the first
// refresh completes, ok is true for the remaining lifetime of the process.
func (e *ReadinessEvaluator) Cached() (ReadinessResponse, bool) {
	p := e.cached.Load()
	if p == nil {
		return ReadinessResponse{}, false
	}
	return *p, true
}

func (e *ReadinessEvaluator) evaluateActiveVettedProviders(ctx context.Context) (ReadinessCondition, error) {
	var current int
	err := e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM providers WHERE status IN ('VETTING', 'ACTIVE')`,
	).Scan(&current)
	if err != nil {
		return ReadinessCondition{}, err
	}
	required := e.profile.MinActiveProviders
	return ReadinessCondition{
		Name:          "active_vetted_providers",
		Satisfied:     current >= required,
		CurrentValue:  current,
		RequiredValue: required,
		DemoValue:     e.demoValue(required),
	}, nil
}

func (e *ReadinessEvaluator) evaluateDistinctASNs(ctx context.Context) (ReadinessCondition, error) {
	var current int
	err := e.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT asn) FROM providers WHERE status IN ('VETTING', 'ACTIVE')`,
	).Scan(&current)
	if err != nil {
		return ReadinessCondition{}, err
	}
	required := e.profile.MinDistinctASNs
	return ReadinessCondition{
		Name:          "distinct_asns",
		Satisfied:     current >= required,
		CurrentValue:  current,
		RequiredValue: required,
		DemoValue:     e.demoValue(required),
	}, nil
}

func (e *ReadinessEvaluator) evaluateDistinctMetroRegions(ctx context.Context) (ReadinessCondition, error) {
	var current int
	err := e.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT region) FROM providers WHERE status IN ('VETTING', 'ACTIVE')`,
	).Scan(&current)
	if err != nil {
		return ReadinessCondition{}, err
	}
	required := e.profile.MinMetroRegions
	return ReadinessCondition{
		Name:          "distinct_metro_regions",
		Satisfied:     current >= required,
		CurrentValue:  current,
		RequiredValue: required,
		DemoValue:     e.demoValue(required),
	}, nil
}

// evaluateQuorum derives the threshold from the boolean RequireQuorum —
// NEVER from NetworkProfile.MinActiveProviders (see this file's header
// note on the copy-paste bug this corrects). When RequireQuorum is false
// (demo mode), the condition is always satisfied with current=required=1
// WITHOUT ever calling clusterMembership.HealthyCount() at all — matching
// OAS's DemoReady example exactly.
func (e *ReadinessEvaluator) evaluateQuorum() ReadinessCondition {
	if !e.profile.RequireQuorum {
		return ReadinessCondition{
			Name:          "microservice_quorum",
			Satisfied:     true,
			CurrentValue:  soloInstanceSize,
			RequiredValue: soloInstanceSize,
			DemoValue:     e.demoValue(soloInstanceSize),
		}
	}
	current := e.clusterMembership.HealthyCount()
	required := productionQuorumSize
	return ReadinessCondition{
		Name:          "microservice_quorum",
		Satisfied:     current >= required,
		CurrentValue:  current,
		RequiredValue: required,
		DemoValue:     e.demoValue(required),
	}
}

// evaluateRazorpayAccountsReady is a LIVE QUERY — never cached, re-run
// every evaluation cycle (ADR-029: "the assignment service MUST NOT cache
// this value between evaluations").
//
// [Fixed — F-17E-01] Previously counted `razorpay_cooling_until < NOW()`
// alone. internal/repair/assignment.go's drawTwoActiveCandidates (M11
// audit remediation, Finding 5) — the actual gate a provider must clear to
// be a real-shard assignment candidate — requires THREE conditions:
// status = 'ACTIVE', razorpay_linked_account_id IS NOT NULL, AND
// razorpay_cooling_until < NOW(). This condition counted only the third,
// so it could (and in demo mode, before provider.go's own registration
// fix alongside this one, always did) report every provider ready while
// assignment found zero eligible candidates — readiness and assignment
// asking the same real-world question two different ways, the same
// defect shape as the ADR-071 finding. Now mirrors
// drawTwoActiveCandidates' predicate exactly, so this condition can never
// again report ready while assignment cannot actually proceed.
func (e *ReadinessEvaluator) evaluateRazorpayAccountsReady(ctx context.Context) (ReadinessCondition, error) {
	var current int
	err := e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM providers
		 WHERE status = 'ACTIVE'
		   AND razorpay_linked_account_id IS NOT NULL
		   AND razorpay_cooling_until < NOW()`,
	).Scan(&current)
	if err != nil {
		return ReadinessCondition{}, err
	}
	required := e.profile.MinCooledAccounts
	return ReadinessCondition{
		Name:          "razorpay_accounts_ready",
		Satisfied:     current >= required,
		CurrentValue:  current,
		RequiredValue: required,
		DemoValue:     e.demoValue(required),
	}, nil
}

func (e *ReadinessEvaluator) evaluateRelayNodesDeployed(ctx context.Context) (ReadinessCondition, error) {
	current, err := e.relayNodeCounter.Count(ctx)
	if err != nil {
		return ReadinessCondition{}, err
	}
	required := e.profile.MinRelayNodes
	return ReadinessCondition{
		Name:          "relay_nodes_deployed",
		Satisfied:     current >= required,
		CurrentValue:  current,
		RequiredValue: required,
		DemoValue:     e.demoValue(required),
	}, nil
}

func (e *ReadinessEvaluator) evaluateClusterAuditSecretLoaded() ReadinessCondition {
	current := 0
	if e.clusterSecretCache.IsLoaded() {
		current = 1
	}
	return ReadinessCondition{
		Name:          "cluster_audit_secret_loaded",
		Satisfied:     current == clusterAuditSecretRequiredValue,
		CurrentValue:  current,
		RequiredValue: clusterAuditSecretRequiredValue,
		DemoValue:     e.demoValue(clusterAuditSecretRequiredValue),
	}
}

// HandleReadiness serves GET /api/v1/admin/readiness.
//
// [Corrected — M12 audit corrections, Finding 3] Now reads Cached() —
// IC §3.4's 60-second re-evaluation cadence — instead of calling Evaluate
// live on every request. See Cached's own doc comment for the cold-start
// fallback below.
func (e *ReadinessEvaluator) HandleReadiness(w http.ResponseWriter, r *http.Request) {
	resp, ok := e.Cached()
	if !ok {
		// Cold start only (see Cached's doc comment) — no refresh has
		// completed yet. A live Evaluate here, rather than either failing
		// the request or serving an empty/zero-value response, is the only
		// choice that stays correct without waiting on the very first
		// background refresh.
		var err error
		resp, err = e.Evaluate(r.Context())
		if err != nil {
			WriteError(w, http.StatusInternalServerError, ErrInternal, "readiness evaluation failed", nil, "", nil)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
