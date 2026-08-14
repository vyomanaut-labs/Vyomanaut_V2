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
type ReadinessResponse struct {
	AllConditionsMet          bool                `json:"all_conditions_met"`
	EvaluatedAt               time.Time           `json:"evaluated_at"`
	Mode                      string              `json:"mode"`
	Conditions                ReadinessConditions `json:"conditions"`
	ProvidersNearCeilingCount int                 `json:"providers_near_ceiling_count"`
}

// ReadinessEvaluator evaluates all seven readiness conditions (ADR-029,
// FR-053, FR-054). All seven are evaluated on every call — the 60-second
// caching cadence IC §3.4/FR-054 describes is a background-goroutine
// concern (Milestone 12, Session 12.1.1), not this evaluator's own; the
// HTTP handler here reads whatever the caller (Milestone 12) has it call
// on that cadence.
type ReadinessEvaluator struct {
	db                 *sql.DB
	profile            config.NetworkProfile
	clusterSecretCache *audit.ClusterSecretCache
	clusterMembership  ClusterMembership
	relayNodeCounter   RelayNodeCounter
}

// NewReadinessEvaluator constructs a ReadinessEvaluator. clusterMembership
// and relayNodeCounter may be MockClusterMembership{} / StubRelayNodeCounter{}
// until their respective real subsystems exist (see this file's header note).
func NewReadinessEvaluator(
	db *sql.DB,
	profile config.NetworkProfile,
	clusterSecretCache *audit.ClusterSecretCache,
	clusterMembership ClusterMembership,
	relayNodeCounter RelayNodeCounter,
) *ReadinessEvaluator {
	return &ReadinessEvaluator{
		db:                 db,
		profile:            profile,
		clusterSecretCache: clusterSecretCache,
		clusterMembership:  clusterMembership,
		relayNodeCounter:   relayNodeCounter,
	}
}

// demoValue returns a pointer to requiredValue when profile.Mode == "demo",
// and nil otherwise (OAS ReadinessCondition.demo_value: "Null when the
// system is running in production mode").
func (e *ReadinessEvaluator) demoValue(requiredValue int) *int {
	if e.profile.Mode != "demo" {
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
		AllConditionsMet:          allMet,
		EvaluatedAt:               time.Now().UTC(),
		Mode:                      e.profile.Mode,
		Conditions:                conditions,
		ProvidersNearCeilingCount: nearCeilingCount,
	}, nil
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
func (e *ReadinessEvaluator) evaluateRazorpayAccountsReady(ctx context.Context) (ReadinessCondition, error) {
	var current int
	err := e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM providers WHERE razorpay_cooling_until < NOW()`,
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
func (e *ReadinessEvaluator) HandleReadiness(w http.ResponseWriter, r *http.Request) {
	resp, err := e.Evaluate(r.Context())
	if err != nil {
		WriteError(w, http.StatusInternalServerError, ErrInternal, "readiness evaluation failed", nil, "", nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
