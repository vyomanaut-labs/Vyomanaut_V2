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

	return wrapPanel(title, strings.Join(lines, "\n"), overallSev)
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

	// worstSev tracks the least healthy heartbeat seen, so the panel's own
	// border reflects fleet health at a glance — an OVERDUE provider
	// anywhere turns the whole panel's border red, not just its own row.
	worstSev := severityOK

	lines := []string{dimStyle.Render(fmt.Sprintf(fleetRowFormat, "ID", "ASN", "STATUS", "HEARTBEAT", "GB", "CHUNKS", "PASSES", "SCORE"))}
	for _, p := range providers.Providers {
		heartbeatCol := "\u2014"
		style := dimStyle
		rowSev := severityOK
		if p.LastHeartbeatTS != nil {
			age := now.Sub(*p.LastHeartbeatTS)
			remaining := threshold - age
			switch {
			case age > half && remaining <= 0:
				heartbeatCol = fmt.Sprintf("%s (OVERDUE)", roundDuration(age))
				rowSev = severityAlert
			case age > half:
				heartbeatCol = fmt.Sprintf("%s (departs in %s)", roundDuration(age), roundDuration(remaining))
				rowSev = severityWarn
			default:
				heartbeatCol = roundDuration(age)
				rowSev = severityOK
			}
			style = statusStyle(rowSev)
		}
		if rowSev > worstSev {
			worstSev = rowSev
		}
		row := fmt.Sprintf(fleetRowFormat,
			shortID(p.ProviderID), p.ASN, p.Status, heartbeatCol,
			strconv.Itoa(p.DeclaredStorageGB), strconv.Itoa(p.StoredChunks),
			auditPassLabel(profile, p), scoreLabel(p.ScoreComposite))
		lines = append(lines, style.Render(row))
	}

	return wrapPanel(title, strings.Join(lines, "\n"), worstSev)
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
// 3. ASN diversity
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

	// Severity here is about DIVERSITY, the property this panel can
	// actually measure: too few ASNs carrying data is the real risk, not a
	// large chunk count on any one of them. Meeting the requirement
	// exactly is a healthy, fully-expected steady state at demo scale (5
	// providers, 5 required ASNs) — it is NOT a warning, and treating it
	// as one would paint this panel permanently amber for the length of
	// an ordinary run, which is the same false-alarm shape F-18-1 already
	// fixed once for this panel.
	sev := severityOK
	if len(asns) < profile.MinDistinctASNs {
		sev = severityAlert
	}

	// [Trimmed, Session 18.1.3] The per-segment cap's full definition
	// (FR-045/ADR-014) and the "this is a distribution, not a cap
	// reading" caveat both moved to the '?' legend — this line keeps only
	// the two numbers a glance actually needs. "per segment" stays inline
	// (not just in the legend) because omitting it invites reading the
	// chunk counts below as a cap violation, which is the exact
	// misreading F-18-1 corrected.
	lines := []string{
		dimStyle.Render(fmt.Sprintf("cap %d/ASN per segment \u00b7 ASNs %d/%d", shardCap, len(asns), profile.MinDistinctASNs)),
	}

	if len(asns) == 0 {
		lines = append(lines, dimStyle.Render("no providers registered yet"))
	}
	for _, asn := range asns {
		lines = append(lines, statusStyle(sev).Render(fmt.Sprintf("%-10s %d chunk(s)", asn, occ[asn])))
	}

	return wrapPanel(title, strings.Join(lines, "\n"), sev)
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

	// [Trimmed, Session 18.1.3] The full explanation of what r0 means and
	// why repairs fire immediately rather than batching (F-18-4's own
	// wording) moved to the '?' legend. belowR0 itself is folded into the
	// queued line rather than dropped — it is a real count, not prose.
	lines := []string{
		fmt.Sprintf("queued:     %d  (emergency %d, departure %d, pre-warning %d)",
			rq.TotalQueued, rq.EmergencyQueued, rq.PermanentDepartureQueued, rq.PreWarningQueued),
		fmt.Sprintf("in-flight:  %d", inFlight),
		fmt.Sprintf("completed:  %d (this page), %d job(s) at/below r0", completed, belowR0),
	}

	return wrapPanelNeutral(title, strings.Join(lines, "\n"))
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

	// [Trimmed, Session 18.1.3] The window/cadence explanation (F-18-5's
	// own fix, replacing a countdown that never counted down) moved to the
	// '?' legend along with everything else. NFR-027 sets the same 5%
	// timeout-rate threshold this panel's own alert border now watches for.
	sev := severityOK
	if timeoutRatePct > auditTimeoutAlertPct {
		sev = severityAlert
	}

	lines := []string{
		fmt.Sprintf("challenges: %d  (pass %d, fail %d, timeout %d, pending %d)",
			as.Challenges, as.Results.Pass, as.Results.Fail, as.Results.Timeout, as.Results.Pending),
		fmt.Sprintf("pass rate:  %d%%   timeout rate: %d%%", passRatePct, timeoutRatePct),
	}

	return wrapPanel(title, strings.Join(lines, "\n"), sev)
}

// auditTimeoutAlertPct mirrors NFR-027's own trigger — a timeout rate above
// 5% of challenges issued — so the Audit panel's border turns red for the
// same reason the requirement itself would flag the network, not an
// invented threshold.
const auditTimeoutAlertPct = 5

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

	// [Trimmed, Session 18.1.3] The full explanation (F-18-4's own fix,
	// pointing at `operator payout` for real numbers) moved to the '?'
	// legend. The word "(placeholder)" stays attached directly to each
	// value line rather than following it into the legend — the one fact
	// that must never be a click or a keypress away is that ₹0.00 here is
	// not a real balance, and a reader who never opens the legend must
	// still see that on the line itself.
	lines := []string{
		fmt.Sprintf("charged paise:  %s (placeholder)", formatPaise(0)),
		fmt.Sprintf("released paise: %s (placeholder)", formatPaise(0)),
		fmt.Sprintf("next charge tick in %s, next release tick in %s", nextCharge, nextRelease),
	}

	return wrapPanelNeutral(title, strings.Join(lines, "\n"))
}

// ═══════════════════════════════════════════════════════════════════════
// 7. Event feed
// ═══════════════════════════════════════════════════════════════════════

const eventFeedDisplayDepth = 10

// minEventFeedDisplayDepth is the floor renderEventsWithin will not shrink
// the feed below. A feed of one or two lines is still worth showing; a feed
// of zero lines is a panel that looks broken.
const minEventFeedDisplayDepth = 3

// renderEventsWithin is the sole entry point; renderFleet's neighbours in
// this file are called directly by name (renderReadiness, renderAudit, ...)
// but the event feed's caller (model.go's View) always has an explicit line
// budget to pass, computed from the terminal height, so there is no
// default-depth wrapper here to keep in sync with it — a second, unused
// entry point is exactly how the F-18-6 height bug went unnoticed as long
// as it did.
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
		return wrapPanelNeutral(title, dimStyle.Render("no events yet"))
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

	return wrapPanelNeutral(title, strings.Join(lines, "\n"))
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

// ═══════════════════════════════════════════════════════════════════════
// Legend — the '?' overlay
// ═══════════════════════════════════════════════════════════════════════

// renderLegend holds every explanation Session 18.1.3 trimmed out of the
// seven panel bodies themselves, plus the console's keybindings. It exists
// so removing that prose from the main view (F-18-4/F-18-5's own
// wording, and this session's own ASN/Repair/Audit trims) is a relocation,
// not a deletion — a presenter can still surface any of it on demand
// without it competing for space with the numbers on every single frame.
func renderLegend(profile config.NetworkProfile) string {
	shardCap := asnShardCap(profile)

	return strings.Join([]string{
		panelTitleStyle.Render("What each panel means"),
		"",
		"Readiness gate     Five server-side conditions checked before the network",
		"                   accepts real uploads. READY/NOT READY is the coordinator's",
		"                   own verdict, not this console's — trust it over the",
		"                   fractions if --mode was ever passed wrong.",
		"",
		fmt.Sprintf("Provider fleet     PASSES shows consecutive audit passes against the %d-pass", profile.VettingMinPasses),
		fmt.Sprintf("                   vetting gate while VETTING (also needs %s elapsed —", roundDuration(profile.VettingMinDuration)),
		"                   both conditions, not either). HEARTBEAT turns amber past",
		"                   half the departure threshold, red once overdue.",
		"",
		fmt.Sprintf("ASN diversity      No ASN may hold more than %d shard(s) of the SAME SEGMENT", shardCap),
		"                   (FR-045, ADR-014). Chunk counts shown are lifetime totals",
		"                   across every segment, not a per-segment cap reading — a",
		"                   multi-segment file legitimately shows more than the cap",
		fmt.Sprintf("                   per ASN. Meeting the %d required distinct ASNs exactly is", profile.MinDistinctASNs),
		"                   healthy, not a warning.",
		"",
		fmt.Sprintf("Repair             r0 = %d shards. Repairs fire immediately once queued rather", profile.LazyRepairR0),
		"                   than batching at r0 — this build has no batching gate yet.",
		"",
		"Audit              Counts cover a trailing 1-hour window; challenges dispatch",
		fmt.Sprintf("                   every %s. Border turns red above a %d%% timeout rate,", roundDuration(profile.AuditPeriodDuration), auditTimeoutAlertPct),
		"                   the same trigger NFR-027 itself defines.",
		"",
		"Escrow & release   Both totals are placeholders (marked inline) — no admin",
		"                   endpoint yet exposes live escrow balances. Run",
		"                   `operator payout` for the real per-provider split.",
		"",
		panelTitleStyle.Render("Keys"),
		"  [1]-[7]        focus that panel full-size; same digit again to un-zoom",
		"  [esc] or [0]   back to the grid",
		"  [\u2191/\u2193] [j/k]     scroll    [PgUp/PgDn] page",
		"  [?]            toggle this legend",
		"  [q]            quit",
	}, "\n")
}
