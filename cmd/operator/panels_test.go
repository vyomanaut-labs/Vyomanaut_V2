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
	"fmt"
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

	out := renderFleet(profile, providers, nil, now)

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
	freshOut := renderFleet(profile, freshProviders, nil, now)
	if strings.Contains(freshOut, "departs in") {
		t.Errorf("renderFleet showed a countdown for a fresh heartbeat, want none:\n%s", freshOut)
	}
}

// TestASNCapPanelDoesNotAlarmOnAggregateChunkCounts pins the Session 18.1.2
// correction (F-18-1). It replaces TestASNCapPanelShowsZeroHeadroomAtDemo\u2010
// Topology, which asserted the old, wrong semantics: five ASNs holding one
// chunk each rendering "headroom 0" against the per-segment cap of 1.
//
// That assertion encoded a unit error. The cap is per SEGMENT (renderASNCap's
// own header, and internal/repair/assignment.go's asnWithinCap, which takes a
// segmentID); StoredChunks is a lifetime total across every segment. A single
// two-segment upload therefore put every ASN at 2 chunks against a cap of 1
// and painted the whole panel alert-red on a healthy fleet \u2014 the panel
// alarmed harder the more the network was actually used.
//
// The fixture below is that exact case: five ASNs, two chunks each, which is
// what one 1 MB file legitimately produces at demo parameters. The panel must
// not report a breach.
func TestASNCapPanelDoesNotAlarmOnAggregateChunkCounts(t *testing.T) {
	profile := config.DemoProfile

	const chunksPerASNFromOneTwoSegmentFile = 2

	providers := &adminProvidersResponse{}
	for i := 1; i <= profile.MinDistinctASNs; i++ {
		providers.Providers = append(providers.Providers, providerAdminItem{
			ProviderID:   strconv.Itoa(i),
			Status:       "ACTIVE",
			ASN:          "AS" + strconv.Itoa(i),
			StoredChunks: chunksPerASNFromOneTwoSegmentFile,
		})
	}

	out := renderASNCap(profile, providers)

	if wantCap := asnShardCap(profile); wantCap != 1 {
		t.Fatalf("test fixture assumption broken: asnShardCap(DemoProfile) = %d, want 1 (floor(5 shards times the profile's ASN-cap fraction))", wantCap)
	}
	if strings.Contains(out, "headroom") {
		t.Errorf("renderASNCap still reports headroom against a per-segment cap it cannot measure from aggregate chunk counts (F-18-1):\n%s", out)
	}
	if !strings.Contains(out, "per segment") {
		t.Errorf("renderASNCap must state that the cap is per-segment, so the chunk totals below it are not read as a cap reading:\n%s", out)
	}
	if !strings.Contains(out, "chunk(s)") {
		t.Errorf("renderASNCap should still show the per-ASN chunk distribution it CAN measure:\n%s", out)
	}
}

// TestFleetPanelShowsVettingAuditPassProgress covers Session 18.1.2's fleet
// column. A VETTING provider's row must show its consecutive audit passes
// against VettingMinPasses, since that is the gate an operator watches to
// judge how far a provider is from ACTIVE. A provider past that gate has no
// gate left to render, so it shows the bare count.
func TestFleetPanelShowsVettingAuditPassProgress(t *testing.T) {
	profile := config.DemoProfile
	now := time.Now()

	providers := &adminProvidersResponse{Providers: []providerAdminItem{
		{ProviderID: "1", Status: "VETTING", ASN: "AS1", ConsecutiveAuditPasses: 3},
		{ProviderID: "2", Status: "ACTIVE", ASN: "AS2", ConsecutiveAuditPasses: 9},
	}}

	out := renderFleet(profile, providers, nil, now)

	wantVetting := "3/" + strconv.Itoa(profile.VettingMinPasses)
	if !strings.Contains(out, wantVetting) {
		t.Errorf("renderFleet: VETTING row should show progress toward the vetting gate as %q:\n%s", wantVetting, out)
	}
	if !strings.Contains(out, "PASSES") {
		t.Errorf("renderFleet: fleet table is missing the PASSES column header:\n%s", out)
	}
	if strings.Contains(out, "9/"+strconv.Itoa(profile.VettingMinPasses)) {
		t.Errorf("renderFleet: an ACTIVE provider has already cleared the gate and must not render against it:\n%s", out)
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
// falls back to profile.DepartureThreshold before any readiness snapshot
// has arrived (reflecting a change to that field rather than a
// compiled-in constant), and — the point of Session 17.7.1's own update —
// prefers the server's authoritative effective_departure_threshold_seconds
// the moment one is available, even when it disagrees with this
// process's own local profile constant.
func TestEffectiveDepartureThresholdMatchesProfile(t *testing.T) {
	profile := config.DemoProfile
	profile.DepartureThreshold = 37 * time.Minute

	// No readiness snapshot yet: falls back to the local profile constant.
	got := effectiveDepartureThreshold(profile, nil)
	if got != 37*time.Minute {
		t.Errorf("effectiveDepartureThreshold(profile, nil) = %v, want %v (profile.DepartureThreshold)", got, 37*time.Minute)
	}

	// A readiness snapshot with a DIFFERENT value present: the server's
	// authoritative figure wins, even though it disagrees with this
	// process's own profile.DepartureThreshold above — the console must
	// never show a countdown that disagrees with the detector actually
	// running (ADR-084 §D-4).
	readiness := &readinessAdminResponse{EffectiveDepartureThresholdSeconds: 90}
	got = effectiveDepartureThreshold(profile, readiness)
	if got != 90*time.Second {
		t.Errorf("effectiveDepartureThreshold(profile, readiness) = %v, want %v (the server's authoritative value, not the local profile constant)", got, 90*time.Second)
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

// TestFleetRowFormatSurvivesLongestStatus pins F-18-2. PENDING_ONBOARDING is
// the longest status this system emits; with the old %-10s STATUS field it
// overflowed and shifted every column to its right by eight characters, so a
// provider's declared GB printed under CHUNKS on the one screen a reviewer
// reads. Asserting on column POSITIONS rather than on the format string means
// this test still fails if someone widens the status vocabulary later.
func TestFleetRowFormatSurvivesLongestStatus(t *testing.T) {
	const longestStatus = "PENDING_ONBOARDING"

	header := fmt.Sprintf(fleetRowFormat, "ID", "ASN", "STATUS", "HEARTBEAT", "GB", "CHUNKS", "PASSES", "SCORE")
	row := fmt.Sprintf(fleetRowFormat, "699c248a", "SIM-AS4", longestStatus, "16s", "200", "0", "0", "-")

	if len(header) != len(row) {
		t.Errorf("fleet header and row widths diverge with status %q (header %d, row %d) — the row will shift its own columns (F-18-2):\n%s\n%s",
			longestStatus, len(header), len(row), header, row)
	}
	if strings.Index(row, "200") != strings.Index(header, "GB") {
		t.Errorf("declared GB does not land under the GB header when status is %q (F-18-2):\n%s\n%s", longestStatus, header, row)
	}
}

// TestEventFeedCollapsesConsecutiveDuplicates pins F-18-7. During vetting the
// dispatcher issues a challenge every few seconds; uncollapsed, ten identical
// lines filled the panel and pushed every status transition — the events an
// audience is watching for — off screen within seconds of appearing.
func TestEventFeedCollapsesConsecutiveDuplicates(t *testing.T) {
	now := time.Now()

	var events []eventFeedEntry
	for i := 0; i < 8; i++ {
		events = append(events, eventFeedEntry{Kind: "audit", Message: "1 new audit challenge issued", At: now.Add(-time.Duration(90-i*10) * time.Second)})
	}
	events = append(events, eventFeedEntry{Kind: "status_transition", Message: "provider abc: VETTING -> ACTIVE", At: now.Add(-5 * time.Second)})

	out := renderEventsWithin(events, now, eventFeedDisplayDepth)

	if !strings.Contains(out, "\u00d78") {
		t.Errorf("renderEventsWithin did not collapse 8 consecutive identical events into a counted line (F-18-7):\n%s", out)
	}
	if !strings.Contains(out, "VETTING -> ACTIVE") {
		t.Errorf("the status transition was pushed off the feed by repeated audit lines — exactly what collapsing exists to prevent (F-18-7):\n%s", out)
	}
	if got := strings.Count(out, "new audit challenge issued"); got != 1 {
		t.Errorf("expected the 8 duplicates to render as exactly 1 line, got %d:\n%s", got, out)
	}
}

// TestEventFeedNeverRendersFewerThanTheFloor pins the clamp in F-18-6's
// budget path. A short terminal yields a negative budget once the six
// fixed-height panels are subtracted; the feed must degrade to a small
// panel, never to an empty one that reads as broken.
func TestEventFeedNeverRendersFewerThanTheFloor(t *testing.T) {
	now := time.Now()
	events := []eventFeedEntry{
		{Kind: "audit", Message: "one", At: now},
		{Kind: "audit", Message: "two", At: now},
		{Kind: "audit", Message: "three", At: now},
		{Kind: "audit", Message: "four", At: now},
	}

	out := renderEventsWithin(events, now, -8)

	lines := strings.Count(out, "[")
	if lines != minEventFeedDisplayDepth {
		t.Errorf("negative budget should clamp to the %d-line floor, rendered %d lines:\n%s", minEventFeedDisplayDepth, lines, out)
	}
}

// TestASNPanelKeepsASNsWithNoActiveProviders pins F-18-3. An ASN whose only
// provider is still VETTING used to disappear from the diversity panel
// entirely, which reads as "this ASN is gone" rather than "no data yet" —
// and during early startup, when nothing is ACTIVE, the whole panel rendered
// as a bare header.
func TestASNPanelKeepsASNsWithNoActiveProviders(t *testing.T) {
	profile := config.DemoProfile

	providers := &adminProvidersResponse{Providers: []providerAdminItem{
		{ProviderID: "1", Status: "ACTIVE", ASN: "SIM-AS1", StoredChunks: 2},
		{ProviderID: "2", Status: "VETTING", ASN: "SIM-AS2", StoredChunks: 1},
	}}

	out := renderASNCap(profile, providers)

	if !strings.Contains(out, "SIM-AS2") {
		t.Errorf("an ASN whose providers are all VETTING vanished from the diversity panel (F-18-3):\n%s", out)
	}
	if !strings.Contains(out, "SIM-AS2    0 chunk(s)") {
		t.Errorf("a VETTING-only ASN should read as zero chunks, not be omitted (F-18-3):\n%s", out)
	}
}
