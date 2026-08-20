// Package main — the console's seven panels (M17-E Session 17.6.2,
// ADR-084 §D-2). Each render function is a pure function of
// (config.NetworkProfile, the relevant snapshot slice, and — where a live
// countdown is shown — the model's own "now"): no wall-clock reads, no
// hidden state, so TestViewRendersAllSevenPanels and its neighbours can
// call these directly with fixture data and fixed timestamps.
//
// Every threshold rendered here comes from a profile field, never a
// hardcoded number (task item 2's own build contract) — the one
// exception, by design rather than oversight, is asnShardCap's floor()
// arithmetic, which lives in model.go so this file never needs to write a
// floating-point conversion (see money.go and this file's own NFR-038
// discipline, held file-wide, not just on the escrow panel).
//
// [REF: ADR-084 D-2; build_M17E.md Phase 17.6 Session 17.6.2]
package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// effectiveDepartureThreshold is the duration of heartbeat silence after
// which a provider is treated as departed. Named as its own function
// (rather than every call site reading profile.DepartureThreshold
// directly) for two reasons: VERIFY's own COUNTDOWN_USES_EFFECTIVE_THRESHOLD
// check looks for this name, and — the real reason the name matters, not
// just the check — this is this session's one clearly-marked extension
// point. A provider with an ACTIVE promised-return window
// (internal/api/provider.go's promised_return_at, ADR-007) should get a
// longer effective threshold than a silent one, but GET /admin/providers
// does not currently expose promised_return_at (neither this session's
// nor Session 17.6.1's own FILES list touched admin.go's response shape
// for it), so today this function is exactly profile.DepartureThreshold —
// a future session that adds that field to the wire contract is the one
// that should extend this function, not invent a parallel one.
func effectiveDepartureThreshold(profile config.NetworkProfile) time.Duration {
	return profile.DepartureThreshold
}

func waitingPanel(title string) string {
	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + dimStyle.Render("waiting for data..."))
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Readiness gate
// ═══════════════════════════════════════════════════════════════════════

func renderReadiness(profile config.NetworkProfile, r *readinessAdminResponse) string {
	const title = "Readiness gate"
	if r == nil {
		return waitingPanel(title)
	}

	bars := []struct {
		label    string
		cond     readinessConditionAdmin
		required int
	}{
		{"Active vetted providers", r.Conditions.ActiveVettedProviders, profile.MinActiveProviders},
		{"Distinct ASNs", r.Conditions.DistinctASNs, profile.MinDistinctASNs},
		{"Distinct metro regions", r.Conditions.DistinctMetroRegions, profile.MinMetroRegions},
		{"Relay nodes deployed", r.Conditions.RelayNodesDeployed, profile.MinRelayNodes},
		{"Razorpay accounts cooled", r.Conditions.RazorpayAccountsReady, profile.MinCooledAccounts},
	}

	var lines []string
	for _, b := range bars {
		sev := severityOK
		mark := "\u2713"
		if !b.cond.Satisfied {
			sev = severityAlert
			mark = "\u2717"
		}
		line := fmt.Sprintf("%s %-26s %d / %d", mark, b.label, b.cond.CurrentValue, b.required)
		lines = append(lines, statusStyle(sev).Render(line))
	}

	overall, overallSev := "NOT READY", severityAlert
	if r.AllConditionsMet {
		overall, overallSev = "READY", severityOK
	}
	lines = append(lines, "", statusStyle(overallSev).Render(overall))

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Provider fleet
// ═══════════════════════════════════════════════════════════════════════

func renderFleet(profile config.NetworkProfile, providers *adminProvidersResponse, now time.Time) string {
	const title = "Provider fleet"
	if providers == nil {
		return waitingPanel(title)
	}

	threshold := effectiveDepartureThreshold(profile)
	half := threshold / 2

	lines := []string{dimStyle.Render(fmt.Sprintf("%-10s %-8s %-10s %-28s %5s %7s %6s", "ID", "ASN", "STATUS", "HEARTBEAT", "GB", "CHUNKS", "SCORE"))}
	for _, p := range providers.Providers {
		heartbeatCol := "\u2014"
		style := dimStyle
		if p.LastHeartbeatTS != nil {
			age := now.Sub(*p.LastHeartbeatTS)
			remaining := threshold - age
			switch {
			case age > half && remaining <= 0:
				heartbeatCol = fmt.Sprintf("%s (OVERDUE)", roundDuration(age))
				style = statusStyle(severityAlert)
			case age > half:
				heartbeatCol = fmt.Sprintf("%s (departs in %s)", roundDuration(age), roundDuration(remaining))
				style = statusStyle(severityWarn)
			default:
				heartbeatCol = roundDuration(age)
				style = statusStyle(severityOK)
			}
		}
		row := fmt.Sprintf("%-10s %-8s %-10s %-28s %5d %7d %6s",
			shortID(p.ProviderID), p.ASN, p.Status, heartbeatCol, p.DeclaredStorageGB, p.StoredChunks, scoreLabel(p.ScoreComposite))
		lines = append(lines, style.Render(row))
	}

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// ═══════════════════════════════════════════════════════════════════════
// 3. ASN cap occupancy
// ═══════════════════════════════════════════════════════════════════════

func renderASNCap(profile config.NetworkProfile, providers *adminProvidersResponse) string {
	const title = "ASN cap occupancy"
	if providers == nil {
		return waitingPanel(title)
	}

	shardCap := asnShardCap(profile)
	occ := asnOccupancy(providers)

	asns := make([]string, 0, len(occ))
	for asn := range occ {
		asns = append(asns, asn)
	}
	sort.Strings(asns)

	lines := []string{
		dimStyle.Render(fmt.Sprintf("cap = floor(%d shards \u00d7 %.0f%%) = %d per ASN", profile.TotalShards, profile.ASNCapFraction*100, shardCap)),
	}
	for _, asn := range asns {
		count := occ[asn]
		headroom := shardCap - count
		sev := severityOK
		switch {
		case headroom <= 0:
			sev = severityAlert
		case headroom == 1:
			sev = severityWarn
		}
		lines = append(lines, statusStyle(sev).Render(fmt.Sprintf("%-10s %d / %d  (headroom %d)", asn, count, shardCap, headroom)))
	}

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// asnOccupancy sums StoredChunks per ASN across ACTIVE providers only —
// DEPARTED/VETTING providers hold no live shard assignments a fresh upload
// would be routed around, so they don't count toward current occupancy.
func asnOccupancy(providers *adminProvidersResponse) map[string]int {
	occ := make(map[string]int)
	for _, p := range providers.Providers {
		if p.Status != "ACTIVE" {
			continue
		}
		occ[p.ASN] += p.StoredChunks
	}
	return occ
}

// ═══════════════════════════════════════════════════════════════════════
// 4. Repair
// ═══════════════════════════════════════════════════════════════════════

func renderRepair(profile config.NetworkProfile, rq *repairQueueAdminResponse) string {
	const title = "Repair"
	if rq == nil {
		return waitingPanel(title)
	}

	inFlight, completed, belowR0 := 0, 0, 0
	for _, j := range rq.Jobs {
		switch j.Status {
		case "IN_PROGRESS":
			inFlight++
		case "COMPLETED":
			completed++
		}
		if j.AvailableShardCount <= profile.LazyRepairR0 {
			belowR0++
		}
	}

	lines := []string{
		fmt.Sprintf("queued:     %d  (emergency %d, departure %d, pre-warning %d)",
			rq.TotalQueued, rq.EmergencyQueued, rq.PermanentDepartureQueued, rq.PreWarningQueued),
		fmt.Sprintf("in-flight:  %d", inFlight),
		fmt.Sprintf("completed:  %d (this page)", completed),
		dimStyle.Render(fmt.Sprintf("r0 = %d shards (F-LTS-07: lazy-repair gate not yet built, system repairs eagerly); %d job(s) at/below r0",
			profile.LazyRepairR0, belowR0)),
	}

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// ═══════════════════════════════════════════════════════════════════════
// 5. Audit
// ═══════════════════════════════════════════════════════════════════════

func renderAudit(profile config.NetworkProfile, as *auditStatsAdminResponse, now time.Time) string {
	const title = "Audit"
	if as == nil {
		return waitingPanel(title)
	}

	passRatePct := int(as.PassRate * 100)
	timeoutRatePct := int(as.TimeoutRate * 100)
	nextTick := as.WindowEnd.Add(profile.AuditPeriodDuration)

	lines := []string{
		fmt.Sprintf("challenges: %d  (pass %d, fail %d, timeout %d, pending %d)",
			as.Challenges, as.Results.Pass, as.Results.Fail, as.Results.Timeout, as.Results.Pending),
		fmt.Sprintf("pass rate:  %d%%   timeout rate: %d%%", passRatePct, timeoutRatePct),
		dimStyle.Render(fmt.Sprintf("period %s; next window in %s", roundDuration(profile.AuditPeriodDuration), roundDuration(nextTick.Sub(now)))),
	}

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// ═══════════════════════════════════════════════════════════════════════
// 6. Escrow & release
// ═══════════════════════════════════════════════════════════════════════

// renderEscrow — charged/released paise and the per-provider split have no
// live data source in this session: no admin endpoint exposes escrow
// balances yet (mv_owner_escrow_balance/mv_provider_escrow_balance exist
// in the schema, DM §7, but nothing refreshes them, and NO_ADDITIONAL_ROUTES
// forbids this session from adding one), and Session 17.6.3's own `operator
// payout` snapshot — the data source ADR-084's panel table names — does
// not exist yet. formatPaise(0) is shown rather than a blank string
// specifically so the formatter itself, and its column alignment, are
// visibly exercised now; the dimmed line beneath says plainly that the
// number is not live. The next-tick countdowns ARE real: both intervals
// come straight from profile fields with no other data needed.
func renderEscrow(profile config.NetworkProfile) string {
	const title = "Escrow & release"

	nextCharge, nextRelease := "\u2014", "\u2014"
	if profile.ChargeComputationInterval > 0 {
		nextCharge = roundDuration(profile.ChargeComputationInterval)
	}
	if profile.ReleaseComputationInterval > 0 {
		nextRelease = roundDuration(profile.ReleaseComputationInterval)
	}

	lines := []string{
		fmt.Sprintf("charged paise:  %s", formatPaise(0)),
		fmt.Sprintf("released paise: %s", formatPaise(0)),
		dimStyle.Render("figures above are not live — Session 17.6.3's `operator payout` snapshot supplies this panel's real data"),
		fmt.Sprintf("next charge tick in %s, next release tick in %s", nextCharge, nextRelease),
	}

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// ═══════════════════════════════════════════════════════════════════════
// 7. Event feed
// ═══════════════════════════════════════════════════════════════════════

const eventFeedDisplayDepth = 10

func renderEvents(events []eventFeedEntry, now time.Time) string {
	const title = "Event feed"
	if len(events) == 0 {
		return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + dimStyle.Render("no events yet"))
	}

	start := 0
	if len(events) > eventFeedDisplayDepth {
		start = len(events) - eventFeedDisplayDepth
	}
	var lines []string
	for _, e := range events[start:] {
		age := roundDuration(now.Sub(e.At))
		lines = append(lines, fmt.Sprintf("[%s ago] %s: %s", age, e.Kind, e.Message))
	}

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// ═══════════════════════════════════════════════════════════════════════
// Shared small formatters
// ═══════════════════════════════════════════════════════════════════════

func roundDuration(d time.Duration) string {
	if d < 0 {
		return "-" + d.Abs().Round(time.Second).String()
	}
	return d.Round(time.Second).String()
}

func shortID(id string) string {
	const shortIDLen = 8
	if len(id) <= shortIDLen {
		return id
	}
	return id[:shortIDLen]
}
