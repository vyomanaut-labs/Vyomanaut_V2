// Tests for model.go (M17-E Session 17.6.2).
//
// Tests:
//   - TestUpdateAdvancesStateOnTickMsg
//   - TestUpdateHandlesFetchErrorWithoutPanicking
//   - TestViewRendersAllSevenPanels
//   - TestAppendDerivedEventsTracksStatusTransitions
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// TestUpdateAdvancesStateOnTickMsg confirms tickMsg is the ONLY thing that
// moves watchModel.now forward — Update never reads time.Now() itself,
// which is the entire reason Update/View can be tested as pure functions
// (this package's own header note on why Bubble Tea was chosen).
func TestUpdateAdvancesStateOnTickMsg(t *testing.T) {
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	m := newWatchModel(newAdminClient("http://example.invalid", "key"), config.DemoProfile)
	m.now = start

	later := start.Add(3 * time.Second)
	updated, cmd := m.Update(tickMsg(later))
	wm, ok := updated.(watchModel)
	if !ok {
		t.Fatalf("Update returned %T, want watchModel", updated)
	}
	if !wm.now.Equal(later) {
		t.Errorf("now = %v, want %v (tickMsg's own timestamp)", wm.now, later)
	}
	if cmd == nil {
		t.Error("Update(tickMsg) returned a nil tea.Cmd, want a batch of fetchCmd + tickCmd")
	}
}

// TestUpdateHandlesFetchErrorWithoutPanicking confirms a fully-failed fan-out
// cycle (every endpoint errored, every pointer field nil) is folded into the
// model without panicking, and that the errors are recorded rather than
// silently dropped.
func TestUpdateHandlesFetchErrorWithoutPanicking(t *testing.T) {
	m := newWatchModel(newAdminClient("http://example.invalid", "key"), config.DemoProfile)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Update panicked on a fully-failed fetch cycle: %v", r)
		}
	}()

	msg := fetchResultMsg{
		at:   time.Now(),
		errs: []string{"readiness: connection refused", "providers: connection refused"},
		// every data field left nil — every endpoint failed
	}
	updated, _ := m.Update(msg)
	wm, ok := updated.(watchModel)
	if !ok {
		t.Fatalf("Update returned %T, want watchModel", updated)
	}
	if len(wm.snapshot.FetchErrors) != 2 {
		t.Errorf("FetchErrors = %v, want 2 entries", wm.snapshot.FetchErrors)
	}
	if wm.haveData {
		t.Error("haveData = true after a fully-failed cycle, want false (nothing succeeded yet)")
	}
	// A second Update call, this time with a real result, must also not
	// panic when folded on top of the all-nil previous snapshot.
	goodMsg := fetchResultMsg{at: time.Now(), readiness: &readinessAdminResponse{Mode: "demo"}}
	updated2, _ := wm.Update(goodMsg)
	wm2, ok := updated2.(watchModel)
	if !ok {
		t.Fatalf("updated2 has type %T, want watchModel", updated2)
	}
	if !wm2.haveData {
		t.Error("haveData = false after a successful cycle, want true")
	}
}

// fullFixtureSnapshot builds a complete, self-consistent set of the five
// endpoint responses used across this file's and panels_test.go's fixtures.
func fullFixtureSnapshot() (readinessAdminResponse, adminProvidersResponse, repairQueueAdminResponse, auditStatsAdminResponse, vettingStatusAdminResponse) {
	readiness := readinessAdminResponse{
		AllConditionsMet: false,
		Mode:             "demo",
		Conditions: readinessConditionsAdmin{
			ActiveVettedProviders: readinessConditionAdmin{Satisfied: true, CurrentValue: 5, RequiredValue: 5},
			DistinctASNs:          readinessConditionAdmin{Satisfied: true, CurrentValue: 5, RequiredValue: 5},
			DistinctMetroRegions:  readinessConditionAdmin{Satisfied: true, CurrentValue: 1, RequiredValue: 1},
			RelayNodesDeployed:    readinessConditionAdmin{Satisfied: true, CurrentValue: 0, RequiredValue: 0},
			RazorpayAccountsReady: readinessConditionAdmin{Satisfied: false, CurrentValue: 2, RequiredValue: 5},
		},
	}

	score := 0.87
	hb := time.Now()
	providers := adminProvidersResponse{
		Total: 1,
		Providers: []providerAdminItem{
			{ProviderID: "11111111-1111-1111-1111-111111111111", Status: "ACTIVE", ASN: "AS1", LastHeartbeatTS: &hb, ScoreComposite: &score, StoredChunks: 1, DeclaredStorageGB: 10},
		},
	}

	repairQueue := repairQueueAdminResponse{
		TotalQueued: 1, EmergencyQueued: 0, PermanentDepartureQueued: 1, PreWarningQueued: 0,
		Jobs: []repairJobAdminItem{{JobID: "job-1", Status: "IN_PROGRESS", AvailableShardCount: 1}},
	}

	auditStats := auditStatsAdminResponse{
		WindowStart: time.Now().Add(-time.Hour), WindowEnd: time.Now(),
		Challenges: 10, Results: auditStatsResultsAdmin{Pass: 8, Fail: 1, Timeout: 1}, PassRate: 0.8, TimeoutRate: 0.1,
	}

	vetting := vettingStatusAdminResponse{TotalVettingProviders: 1, TotalSyntheticChunksActive: 3}

	return readiness, providers, repairQueue, auditStats, vetting
}

// TestViewRendersAllSevenPanels confirms a fully-populated model's View()
// contains every one of the seven panels' own titles — the rendered
// integration point for panels.go's seven render(...) functions.
func TestViewRendersAllSevenPanels(t *testing.T) {
	readiness, providers, repairQueue, auditStats, vetting := fullFixtureSnapshot()
	m := newWatchModel(newAdminClient("http://example.invalid", "key"), config.DemoProfile)
	m.now = time.Now()
	m.haveData = true
	m.snapshot = watchSnapshot{
		Timestamp: m.now, Readiness: &readiness, Providers: &providers,
		RepairQueue: &repairQueue, AuditStats: &auditStats, VettingStatus: &vetting,
	}

	out := m.View()

	for _, title := range []string{
		"Readiness gate", "Provider fleet", "ASN diversity",
		"Repair", "Audit", "Escrow & release", "Event feed",
	} {
		if !strings.Contains(out, title) {
			t.Errorf("View() output missing panel %q", title)
		}
	}
}

// TestAppendDerivedEventsTracksStatusTransitions confirms a provider status
// change between two fetch cycles produces a status_transition event feed
// entry — the Event feed panel's real data source (this package's own
// design choice for what "derived from state deltas" means, model.go's
// header note).
func TestAppendDerivedEventsTracksStatusTransitions(t *testing.T) {
	m := newWatchModel(newAdminClient("http://example.invalid", "key"), config.DemoProfile)

	cycle1 := fetchResultMsg{at: time.Now(), providers: &adminProvidersResponse{
		Providers: []providerAdminItem{{ProviderID: "p1", Status: "VETTING"}},
	}}
	updated, _ := m.Update(cycle1)
	wm, ok := updated.(watchModel)
	if !ok {
		t.Fatalf("updated has type %T, want watchModel", updated)
	}

	cycle2 := fetchResultMsg{at: time.Now(), providers: &adminProvidersResponse{
		Providers: []providerAdminItem{{ProviderID: "p1", Status: "ACTIVE"}},
	}}
	updated2, _ := wm.Update(cycle2)
	wm2, ok := updated2.(watchModel)
	if !ok {
		t.Fatalf("updated2 has type %T, want watchModel", updated2)
	}

	found := false
	for _, e := range wm2.events {
		if e.Kind == "status_transition" && strings.Contains(e.Message, "VETTING -> ACTIVE") {
			found = true
		}
	}
	if !found {
		t.Errorf("no status_transition event found for VETTING -> ACTIVE; events = %+v", wm2.events)
	}
}

// TestAppendOtpEventsAnnouncesEachCodeExactlyOnce pins Session 18.1.4's OTP
// feed. The delivery log is re-read on every fetch cycle (once a second),
// so the announce-once property is the whole correctness question: without
// it the feed would refill with the same codes every tick and drown
// everything else.
func TestAppendOtpEventsAnnouncesEachCodeExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "otp.log")

	write := func(lines ...string) {
		if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatalf("write log: %v", err)
		}
	}

	m := newWatchModel(newAdminClient("http://example.invalid", "key"), config.DemoProfile)
	m.otpLogPath = logPath
	now := time.Now()

	// No log file yet — the microservice creates it lazily on the first
	// OTP, so "not there" is the normal state for the first minute.
	m.appendOtpEvents(now)
	if len(m.events) != 0 {
		t.Fatalf("a missing delivery log should produce no events, got %d", len(m.events))
	}

	write("2026-09-01T12:00:00Z  +919571276889  722874")
	m.appendOtpEvents(now)
	if len(m.events) != 1 {
		t.Fatalf("expected 1 event after the first OTP, got %d", len(m.events))
	}
	if !strings.Contains(m.events[0].Message, "722874") || !strings.Contains(m.events[0].Message, "+919571276889") {
		t.Errorf("event should carry both the code and the requesting number, got %q", m.events[0].Message)
	}

	// Re-reading the unchanged log must not re-announce anything.
	m.appendOtpEvents(now)
	if len(m.events) != 1 {
		t.Errorf("an unchanged log re-announced its codes: %d events, want 1", len(m.events))
	}

	// A new line produces exactly one new event.
	write(
		"2026-09-01T12:00:00Z  +919571276889  722874",
		"2026-09-01T12:01:00Z  +919596253928  120412",
	)
	m.appendOtpEvents(now)
	if len(m.events) != 2 {
		t.Fatalf("expected 2 events after a second OTP, got %d", len(m.events))
	}
	if !strings.Contains(m.events[1].Message, "120412") {
		t.Errorf("second event missing its code: %q", m.events[1].Message)
	}

	// Truncation mid-run must re-baseline, not replay the whole log.
	write("2026-09-01T12:02:00Z  +919999999999  555555")
	m.appendOtpEvents(now)
	if len(m.events) != 2 {
		t.Errorf("a truncated log replayed history: %d events, want 2 (re-baseline, no replay)", len(m.events))
	}
}

// TestAppendOtpEventsIsInertWithoutALogPath confirms the feature is off
// unless explicitly enabled. watch.go refuses --otp-delivery-log outside
// demo mode, so an empty path here is what every prod-profile run sees.
func TestAppendOtpEventsIsInertWithoutALogPath(t *testing.T) {
	m := newWatchModel(newAdminClient("http://example.invalid", "key"), config.DemoProfile)
	m.appendOtpEvents(time.Now())
	if len(m.events) != 0 {
		t.Errorf("OTP events were produced with no delivery-log path set: %d", len(m.events))
	}
}
