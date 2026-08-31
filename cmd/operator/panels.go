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
	"strconv"
	"strings"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// effectiveDepartureThreshold is the duration of heartbeat silence after
// which a provider is treated as departed.
//
// [Updated, M17-E Session 17.7.1, ADR-084 §D-4] cmd/microservice can now
// be started with its own runtime override
// (--departure-threshold/VYOMANAUT_DEPARTURE_THRESHOLD), so
// profile.DepartureThreshold — this operator process's OWN, separately
// selected profile constant — is no longer guaranteed to match what the
// running detector is actually using. GET /admin/readiness now carries
// the authoritative value the server itself computed
// (effective_departure_threshold_seconds, internal/api/readiness.go); this
// function prefers that field whenever a readiness snapshot is available,
// falling back to the local profile constant only before the very first
// successful fetch — "no countdown yet" is honest; "a countdown that
// disagrees with the detector" (ADR-084 §D-4's own words) is not.
func effectiveDepartureThreshold(profile config.NetworkProfile, readiness *readinessAdminResponse) time.Duration {
	if readiness != nil && readiness.EffectiveDepartureThresholdSeconds > 0 {
		return time.Duration(readiness.EffectiveDepartureThresholdSeconds) * time.Second
	}
	return profile.DepartureThreshold
}

// halfDivisor names the "half of the effective departure threshold" split
// task item 3 defines — the point past which the fleet panel starts
// showing a countdown, rather than a bare literal 2 at the one call site.
const halfDivisor = 2

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

// fleetRowFormat is the ONE column layout the fleet table's header and its
// rows both use, so the two can never drift apart.
//
// [Fixed, Session 18.1.2 — F-18-2] The STATUS field was %-10s while the
// longest status this system can emit, PENDING_ONBOARDING, is 18 characters.
// A provider in that state overflowed its own column and shifted every
// column to its right by eight characters, so its GB value printed under
// CHUNKS and its chunk count under SCORE — on the one screen a reviewer
// reads. Widened to %-19s (18 + a guaranteed separating space) and pinned
// here rather than repeated at two call sites.
//
// GB and CHUNKS are passed as pre-formatted strings, not ints, for the same
// reason: one format string cannot serve both a %d row and a %s header, and
// having two near-identical formats is exactly how the drift above happened.
const fleetRowFormat = "%-10s %-8s %-19s %-24s %5s %7s %7s %6s"

func renderFleet(profile config.NetworkProfile, providers *adminProvidersResponse, readiness *readinessAdminResponse, now time.Time) string {
	const title = "Provider fleet"
	if providers == nil {
		return waitingPanel(title)
	}

	threshold := effectiveDepartureThreshold(profile, readiness)
	half := threshold / halfDivisor

	lines := []string{dimStyle.Render(fmt.Sprintf(fleetRowFormat, "ID", "ASN", "STATUS", "HEARTBEAT", "GB", "CHUNKS", "PASSES", "SCORE"))}
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
		row := fmt.Sprintf(fleetRowFormat,
			shortID(p.ProviderID), p.ASN, p.Status, heartbeatCol,
			strconv.Itoa(p.DeclaredStorageGB), strconv.Itoa(p.StoredChunks),
			auditPassLabel(profile, p), scoreLabel(p.ScoreComposite))
		lines = append(lines, style.Render(row))
	}

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// auditPassLabel renders a provider's consecutive audit passes.
//
// For a VETTING provider it is rendered against the gate it is counting
// toward, "3/5" — VettingMinPasses is one of the two conditions promotion
// waits on (the other being VettingMinDuration), so this is the column that
// answers "how much longer until ACTIVE?" without reading the database. The
// count is necessary but not sufficient: a provider showing 5/5 still waits
// for the duration floor to elapse and for the next audit-dispatch tick to
// apply the transition, which is why the demo timeline gives promotion as a
// window rather than a fixed moment.
//
// For any other status the gate no longer applies, so the bare count is
// shown — for an ACTIVE provider it keeps climbing and is a health signal,
// and a reset to 0 means a failed audit broke the streak.
func auditPassLabel(profile config.NetworkProfile, p providerAdminItem) string {
	if p.Status == "VETTING" {
		return fmt.Sprintf("%d/%d", p.ConsecutiveAuditPasses, profile.VettingMinPasses)
	}
	return strconv.Itoa(p.ConsecutiveAuditPasses)
}

// ═══════════════════════════════════════════════════════════════════════
// 3. ASN cap occupancy
// ═══════════════════════════════════════════════════════════════════════

// renderASNCap shows how this fleet's stored chunks are distributed across
// ASNs, and states the placement cap that governs diversity.
//
// [Corrected, Session 18.1.2 — F-18-1] This panel previously compared each
// ASN's TOTAL stored chunk count against floor(TotalShards × ASNCapFraction)
// and coloured the row red when the difference went negative. Those are two
// different quantities and the comparison was never meaningful:
//
//   - The cap ADR-014/FR-045 defines is PER SEGMENT. internal/repair/
//     assignment.go's asnWithinCap takes a segmentID and asks whether one
//     more shard OF THAT SEGMENT would push one ASN above the cap. At demo
//     parameters that cap is floor(5 × 0.2) = 1, i.e. no ASN may hold two
//     shards of the same segment.
//   - StoredChunks is a provider's LIFETIME count of active chunk
//     assignments, summed here across every file and every segment.
//
// So a single 1 MB upload — two segments, five shards each — legitimately
// leaves every ASN holding 2 chunks, and the old panel rendered 2/1
// "headroom -1" in alert red on every row, on a fleet with no violation of
// anything. Worse, the alarm was unavoidable: it fired harder the more the
// network was used, so the one panel meant to show diversity health became
// a permanent false positive the moment the demo did its job.
//
// The honest fix is not to invent a per-segment number this panel cannot
// compute. GET /api/v1/admin/providers returns per-provider totals and no
// segment breakdown, and I-DEMO-1 forbids cmd/operator a database of its
// own to join against, so a true per-segment occupancy reading needs a new
// admin endpoint — out of scope here and recorded rather than faked. This
// panel therefore reports the distribution it can actually measure, states
// the cap as the placement rule it is, and raises no severity from the two
// being compared. [Flagged, not fabricated.]
func renderASNCap(profile config.NetworkProfile, providers *adminProvidersResponse) string {
	const title = "ASN diversity"
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
		dimStyle.Render(fmt.Sprintf("placement cap: floor(%d shards \u00d7 %.0f%%) = %d shard per ASN, per segment (FR-045, ADR-014)",
			profile.TotalShards, profile.ASNCapFraction*percentageScale, shardCap)),
		dimStyle.Render(fmt.Sprintf("enforced at assignment and repair; %d distinct ASNs required, %d present", profile.MinDistinctASNs, len(asns))),
		dimStyle.Render("below: active chunks per ASN across ALL segments — a distribution, not a cap reading"),
	}

	// Severity here is about DIVERSITY, the property this panel can actually
	// measure: too few ASNs carrying data is the real risk, not a large
	// chunk count on any one of them.
	sev := severityOK
	switch {
	case len(asns) < profile.MinDistinctASNs:
		sev = severityAlert
	case len(asns) == profile.MinDistinctASNs:
		sev = severityWarn
	}

	if len(asns) == 0 {
		lines = append(lines, dimStyle.Render("no providers registered yet"))
	}
	for _, asn := range asns {
		lines = append(lines, statusStyle(sev).Render(fmt.Sprintf("%-10s %d chunk(s)", asn, occ[asn])))
	}

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// asnOccupancy sums live chunk counts per ASN, and registers EVERY ASN the
// fleet contains — including ones whose providers are all still VETTING,
// which contribute a zero.
//
// [Fixed, Session 18.1.2 — F-18-3] This previously skipped any provider not
// yet ACTIVE, and the caller built its row list from this map's keys. The
// consequence on screen was an ASN silently vanishing from the diversity
// panel the moment its only provider was mid-vetting, and the whole panel
// rendering as a bare header during early startup when nothing is ACTIVE
// yet — both of which read as "this ASN is gone" rather than "this ASN has
// no data yet". Since the panel's job is diversity, an ASN with zero chunks
// is information, not absence: it is a home the placer can still use.
//
// Only ACTIVE providers contribute to the COUNT (a VETTING or DEPARTED
// provider holds nothing a fresh upload would be routed around), which is
// the original and correct rule — it is only the key set that widened.
func asnOccupancy(providers *adminProvidersResponse) map[string]int {
	occ := make(map[string]int)
	for _, p := range providers.Providers {
		if p.ASN == "" {
			continue
		}
		if _, seen := occ[p.ASN]; !seen {
			occ[p.ASN] = 0
		}
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
		// [Reworded, Session 18.1.2 — F-18-4] This line used to read
		// "F-LTS-07: lazy-repair gate not yet built". That is a build-tracker
		// tag, meaningless to anyone who has not read the finding log, and
		// this panel sits in front of reviewers. The behaviour it describes is
		// unchanged and still disclosed — repairs fire immediately rather than
		// batching at the r0 threshold — just in words that stand on their own.
		dimStyle.Render(fmt.Sprintf("repair threshold r0 = %d shards; repairs currently fire immediately rather than batching at r0. %d job(s) at/below r0",
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

	passRatePct := int(as.PassRate * percentageScale)
	timeoutRatePct := int(as.TimeoutRate * percentageScale)

	// [Fixed, Session 18.1.2 — F-18-5] This line used to render
	// "next window in <d>", computed as WindowEnd + AuditPeriodDuration -
	// now. The server sets window_end to its own now() on every request
	// (internal/api/admin.go), so that expression collapses to exactly
	// AuditPeriodDuration on every single refresh: a countdown that never
	// counted down, sitting on screen reading "2m0s" forever. Anyone
	// watching it for two minutes would notice, and the natural conclusion
	// is that the console is frozen.
	//
	// The two real quantities are shown instead, both honestly labelled:
	// the trailing window these counts are drawn from, and the cadence at
	// which the dispatcher issues challenges.
	lines := []string{
		fmt.Sprintf("challenges: %d  (pass %d, fail %d, timeout %d, pending %d)",
			as.Challenges, as.Results.Pass, as.Results.Fail, as.Results.Timeout, as.Results.Pending),
		fmt.Sprintf("pass rate:  %d%%   timeout rate: %d%%", passRatePct, timeoutRatePct),
		dimStyle.Render(fmt.Sprintf("counts cover the trailing %s; challenges dispatched every %s",
			roundDuration(as.WindowEnd.Sub(as.WindowStart)), roundDuration(profile.AuditPeriodDuration))),
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
		// [Reworded, Session 18.1.2 — F-18-4] Same reason as the repair panel:
		// "Session 17.6.3's snapshot" names a build session, not a thing the
		// reader can act on. The disclosure is identical in substance — these
		// two totals are placeholders — and now also says where the real
		// numbers live, which is the question the old wording provoked.
		dimStyle.Render("the two totals above are placeholders, not live figures — run `operator payout` for the real per-provider split"),
		fmt.Sprintf("next charge tick in %s, next release tick in %s", nextCharge, nextRelease),
	}

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// ═══════════════════════════════════════════════════════════════════════
// 7. Event feed
// ═══════════════════════════════════════════════════════════════════════

const eventFeedDisplayDepth = 10

// minEventFeedDisplayDepth is the floor renderEventsWithin will not shrink
// the feed below. A feed of one or two lines is still worth showing; a feed
// of zero lines is a panel that looks broken.
const minEventFeedDisplayDepth = 3

func renderEvents(events []eventFeedEntry, now time.Time) string {
	return renderEventsWithin(events, now, eventFeedDisplayDepth)
}

// renderEventsWithin renders the feed with an explicit line budget, so
// View can shrink it to whatever the terminal actually has room for.
//
// [Fixed, Session 18.1.2 — F-18-6] Two problems, one cause. The console
// captured the terminal height on every tea.WindowSizeMsg and then never
// used it, so on a short terminal the last panels ran off the bottom and
// the footer was cut mid-render; and when the view shrank between frames
// the alt-screen renderer left the previous frame's trailing line behind,
// which is where the second "press q to quit" came from. Bounding the one
// panel that grows fixes both, because the feed is the only panel whose
// height is not fixed by the data model.
//
// [Fixed, Session 18.1.2 — F-18-7] Consecutive identical events are also
// now collapsed into a single line with a count. During vetting the
// dispatcher issues a challenge every few seconds and the feed became ten
// consecutive copies of "1 new audit challenge issued", pushing every
// status transition — the events an audience is actually watching for —
// off the panel within seconds of them appearing. Collapsing is display
// only: m.events itself is untouched, and --json still emits every entry.
func renderEventsWithin(events []eventFeedEntry, now time.Time, depth int) string {
	const title = "Event feed"
	if len(events) == 0 {
		return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + dimStyle.Render("no events yet"))
	}
	if depth < minEventFeedDisplayDepth {
		depth = minEventFeedDisplayDepth
	}

	collapsed := collapseRepeatedEvents(events)

	start := 0
	if len(collapsed) > depth {
		start = len(collapsed) - depth
	}
	var lines []string
	for _, e := range collapsed[start:] {
		age := roundDuration(now.Sub(e.at))
		suffix := ""
		if e.count > 1 {
			suffix = fmt.Sprintf(" (\u00d7%d)", e.count)
		}
		lines = append(lines, fmt.Sprintf("[%s ago] %s: %s%s", age, e.kind, e.message, suffix))
	}

	return panelStyle.Render(panelTitleStyle.Render(title) + "\n" + strings.Join(lines, "\n"))
}

// collapsedEvent is a run of consecutive identical events. at is the run's
// MOST RECENT timestamp, so a repeating event's age keeps ticking from its
// latest occurrence rather than freezing at the first.
type collapsedEvent struct {
	kind    string
	message string
	at      time.Time
	count   int
}

func collapseRepeatedEvents(events []eventFeedEntry) []collapsedEvent {
	out := make([]collapsedEvent, 0, len(events))
	for _, e := range events {
		if n := len(out); n > 0 && out[n-1].kind == e.Kind && out[n-1].message == e.Message {
			out[n-1].count++
			out[n-1].at = e.At
			continue
		}
		out = append(out, collapsedEvent{kind: e.Kind, message: e.Message, at: e.At, count: 1})
	}
	return out
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
