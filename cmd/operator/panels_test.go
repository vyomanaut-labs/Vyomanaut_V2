// Tests for panels.go (M17-E Session 17.6.2).
//
// Tests:
//   - TestHeartbeatAgePastHalfThresholdRendersCountdown
//   - TestASNCapPanelShowsZeroHeadroomAtDemoTopology
//   - TestReadinessPanelReadsProfileThresholds
//   - TestEffectiveDepartureThresholdMatchesProfile
//   - TestRepairPanelFlagsJobsAtOrBelowR0
package main

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// TestHeartbeatAgePastHalfThresholdRendersCountdown confirms a provider
// whose heartbeat age has crossed half of effectiveDepartureThreshold gets
// a "departs in" countdown line — task item 3's own build contract, and
// the instrument 17.7's ungraceful-departure path is observed through.
func TestHeartbeatAgePastHalfThresholdRendersCountdown(t *testing.T) {
	profile := config.DemoProfile // DepartureThreshold = 10 minutes
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	// Age = 6 minutes: past half (5 minutes) of the 10-minute threshold,
	// with 4 minutes remaining before it would be treated as departed.
	staleHeartbeat := now.Add(-6 * time.Minute)
	providers := &adminProvidersResponse{
		Providers: []providerAdminItem{
			{ProviderID: "11111111-1111-1111-1111-111111111111", Status: "ACTIVE", ASN: "AS1", LastHeartbeatTS: &staleHeartbeat},
		},
	}

	out := renderFleet(profile, providers, now)

	if !strings.Contains(out, "departs in") {
		t.Errorf("renderFleet output missing a countdown for a heartbeat past half the effective threshold:\n%s", out)
	}

	// A fresh heartbeat (well under half the threshold) must NOT show a
	// countdown — only the ones actually past the halfway point do.
	freshHeartbeat := now.Add(-30 * time.Second)
	freshProviders := &adminProvidersResponse{
		Providers: []providerAdminItem{
			{ProviderID: "22222222-2222-2222-2222-222222222222", Status: "ACTIVE", ASN: "AS2", LastHeartbeatTS: &freshHeartbeat},
		},
	}
	freshOut := renderFleet(profile, freshProviders, now)
	if strings.Contains(freshOut, "departs in") {
		t.Errorf("renderFleet showed a countdown for a fresh heartbeat, want none:\n%s", freshOut)
	}
}

// TestASNCapPanelShowsZeroHeadroomAtDemoTopology reproduces ADR-075's own
// finding: at demo scale (TotalShards=5, ASNCapFraction=one fifth → cap=1),
// five providers each in a distinct ASN holding one shard each sit at
// exactly full occupancy — zero headroom on every ASN, which is what
// explains the need for a seventh provider (ADR-075, cited in task item 4).
func TestASNCapPanelShowsZeroHeadroomAtDemoTopology(t *testing.T) {
	profile := config.DemoProfile

	providers := &adminProvidersResponse{}
	for i := 1; i <= profile.MinDistinctASNs; i++ {
		providers.Providers = append(providers.Providers, providerAdminItem{
			ProviderID:   strconv.Itoa(i),
			Status:       "ACTIVE",
			ASN:          "AS" + strconv.Itoa(i),
			StoredChunks: 1,
		})
	}

	out := renderASNCap(profile, providers)

	wantCap := asnShardCap(profile)
	if wantCap != 1 {
		t.Fatalf("test fixture assumption broken: asnShardCap(DemoProfile) = %d, want 1 (floor(5 shards times the profile's ASN-cap fraction))", wantCap)
	}
	headroomZeroCount := strings.Count(out, "headroom 0")
	if headroomZeroCount != profile.MinDistinctASNs {
		t.Errorf("renderASNCap: found %d 'headroom 0' occurrences, want %d (one per ASN at full occupancy):\n%s",
			headroomZeroCount, profile.MinDistinctASNs, out)
	}
}

// TestReadinessPanelReadsProfileThresholds proves the readiness bars read
// their required values from the profile passed in, not from any
// hardcoded number — a profile with deliberately unusual threshold values
// (nothing DemoProfile or ProductionProfile actually uses) must show
// exactly those unusual values.
func TestReadinessPanelReadsProfileThresholds(t *testing.T) {
	profile := config.DemoProfile
	profile.MinActiveProviders = 42
	profile.MinDistinctASNs = 17
	profile.MinMetroRegions = 9
	profile.MinRelayNodes = 3
	profile.MinCooledAccounts = 55

	resp := &readinessAdminResponse{
		Conditions: readinessConditionsAdmin{
			ActiveVettedProviders: readinessConditionAdmin{CurrentValue: 1},
			DistinctASNs:          readinessConditionAdmin{CurrentValue: 1},
			DistinctMetroRegions:  readinessConditionAdmin{CurrentValue: 1},
			RelayNodesDeployed:    readinessConditionAdmin{CurrentValue: 1},
			RazorpayAccountsReady: readinessConditionAdmin{CurrentValue: 1},
		},
	}

	out := renderReadiness(profile, resp)

	for _, want := range []string{"1 / 42", "1 / 17", "1 / 9", "1 / 3", "1 / 55"} {
		if !strings.Contains(out, want) {
			t.Errorf("renderReadiness output missing %q (profile threshold not reflected):\n%s", want, out)
		}
	}
}

// TestEffectiveDepartureThresholdMatchesProfile confirms the named
// function VERIFY's COUNTDOWN_USES_EFFECTIVE_THRESHOLD check looks for
// actually returns profile.DepartureThreshold, and reflects a change to
// that field rather than a compiled-in constant.
func TestEffectiveDepartureThresholdMatchesProfile(t *testing.T) {
	profile := config.DemoProfile
	profile.DepartureThreshold = 37 * time.Minute

	got := effectiveDepartureThreshold(profile)
	if got != 37*time.Minute {
		t.Errorf("effectiveDepartureThreshold = %v, want %v (profile.DepartureThreshold)", got, 37*time.Minute)
	}
}

// TestRepairPanelFlagsJobsAtOrBelowR0 confirms the repair panel's r0
// comparison uses profile.LazyRepairR0, not a hardcoded value, and counts
// jobs at-or-below it correctly.
func TestRepairPanelFlagsJobsAtOrBelowR0(t *testing.T) {
	profile := config.DemoProfile
	profile.LazyRepairR0 = 2

	rq := &repairQueueAdminResponse{
		Jobs: []repairJobAdminItem{
			{JobID: "a", Status: "QUEUED", AvailableShardCount: 1}, // below r0
			{JobID: "b", Status: "QUEUED", AvailableShardCount: 2}, // at r0
			{JobID: "c", Status: "QUEUED", AvailableShardCount: 5}, // above r0
		},
	}

	out := renderRepair(profile, rq)
	if !strings.Contains(out, "2 job(s) at/below r0") {
		t.Errorf("renderRepair did not report 2 jobs at/below r0=2:\n%s", out)
	}
}
