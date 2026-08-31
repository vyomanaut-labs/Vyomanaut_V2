// Package main — the watch console's Bubble Tea Model/Update, and the
// data it operates on (M17-E Session 17.6.2, ADR-084 §D-2).
//
// Elm architecture: Update and View are pure functions of watchModel — no
// wall-clock reads inside either (tickMsg carries its own timestamp, which
// becomes watchModel.now). This is the entire reason ADR-084 §D-2 chose
// Bubble Tea over a hand-rolled redraw loop: Update/View's purity is what
// makes TestUpdateAdvancesStateOnTickMsg, TestHeartbeatAgePastHalfThresholdRendersCountdown,
// and friends model-level tests with no terminal, no PTY, no teatest.
//
// The five new admin-fetch methods below are defined as methods on
// *adminClient (client.go, Session 17.6.1) rather than duplicating its
// doGet/HTTP-client plumbing here — same type, same package, a different
// file is all Go requires, and it keeps client.go's own file untouched by
// this session (its FILES list is watch.go/model.go/panels.go/theme.go/
// money.go only).
//
// [REF: ADR-084 D-2; build_M17E.md Phase 17.6 Session 17.6.2]
package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// ═══════════════════════════════════════════════════════════════════════
// Local mirrors of the five admin endpoints' response shapes. Same
// convention client.go's shardsAdminResponseBody already established
// (Session 17.6.1): this package does not import internal/api (I-DEMO-1),
// so every wire shape it depends on is copied here by hand.
// ═══════════════════════════════════════════════════════════════════════

type readinessConditionAdmin struct {
	Name          string `json:"name"`
	Satisfied     bool   `json:"satisfied"`
	CurrentValue  int    `json:"current_value"`
	RequiredValue int    `json:"required_value"`
}

type readinessConditionsAdmin struct {
	ActiveVettedProviders    readinessConditionAdmin `json:"active_vetted_providers"`
	DistinctASNs             readinessConditionAdmin `json:"distinct_asns"`
	DistinctMetroRegions     readinessConditionAdmin `json:"distinct_metro_regions"`
	MicroserviceQuorum       readinessConditionAdmin `json:"microservice_quorum"`
	RazorpayAccountsReady    readinessConditionAdmin `json:"razorpay_accounts_ready"`
	RelayNodesDeployed       readinessConditionAdmin `json:"relay_nodes_deployed"`
	ClusterAuditSecretLoaded readinessConditionAdmin `json:"cluster_audit_secret_loaded"`
}

type readinessAdminResponse struct {
	AllConditionsMet          bool                     `json:"all_conditions_met"`
	EvaluatedAt               time.Time                `json:"evaluated_at"`
	Mode                      string                   `json:"mode"`
	Conditions                readinessConditionsAdmin `json:"conditions"`
	ProvidersNearCeilingCount int                      `json:"providers_near_ceiling_count"`
	// EffectiveDepartureThresholdSeconds (M17-E Session 17.7.1, ADR-084
	// §D-4): the AUTHORITATIVE detection-latency value the running
	// cmd/microservice's departure detector is actually using right now
	// — which may differ from config.NetworkProfile's own compiled
	// constant whenever that process was started with its own runtime
	// override flag. The fleet panel's countdown reads this field, not a
	// separately-computed local guess (panels.go's own
	// effectiveDepartureThreshold, below).
	EffectiveDepartureThresholdSeconds int64 `json:"effective_departure_threshold_seconds"`
}

type providerAdminItem struct {
	ProviderID      string     `json:"provider_id"`
	PhoneNumber     string     `json:"phone_number"`
	Status          string     `json:"status"`
	ASN             string     `json:"asn"`
	Region          string     `json:"region"`
	LastHeartbeatTS *time.Time `json:"last_heartbeat_ts"`
	ScoreComposite  *float64   `json:"score_composite"`
	StoredChunks    int        `json:"stored_chunks"`
	// ConsecutiveAuditPasses — Session 18.1.2. GET /api/v1/admin/providers
	// has always returned this field (internal/api/admin.go's
	// adminProviderItem, selected straight from providers.consecutive_
	// audit_passes); this struct simply never decoded it, so the fleet
	// panel could not show how close a VETTING provider was to its
	// VettingMinPasses gate. No server change was needed to add the
	// column — only this field and renderFleet's use of it.
	ConsecutiveAuditPasses int        `json:"consecutive_audit_passes"`
	Frozen                 bool       `json:"frozen"`
	DeclaredStorageGB      int        `json:"declared_storage_gb"`
	DepartedAt             *time.Time `json:"departed_at"`
}

type adminProvidersResponse struct {
	Total     int                 `json:"total"`
	Providers []providerAdminItem `json:"providers"`
}

type repairJobAdminItem struct {
	JobID               string  `json:"job_id"`
	ChunkID             string  `json:"chunk_id"`
	Priority            string  `json:"priority"`
	Status              string  `json:"status"`
	AvailableShardCount int     `json:"available_shard_count"`
	ProviderID          *string `json:"provider_id"`
}

type repairQueueAdminResponse struct {
	TotalQueued              int                  `json:"total_queued"`
	EmergencyQueued          int                  `json:"emergency_queued"`
	PermanentDepartureQueued int                  `json:"permanent_departure_queued"`
	PreWarningQueued         int                  `json:"pre_warning_queued"`
	Jobs                     []repairJobAdminItem `json:"jobs"`
}

type auditStatsResultsAdmin struct {
	Pass    int64 `json:"pass"`
	Fail    int64 `json:"fail"`
	Timeout int64 `json:"timeout"`
	Pending int64 `json:"pending"`
}

type auditStatsAdminResponse struct {
	WindowStart time.Time              `json:"window_start"`
	WindowEnd   time.Time              `json:"window_end"`
	Challenges  int64                  `json:"challenges_issued"`
	Results     auditStatsResultsAdmin `json:"results"`
	PassRate    float64                `json:"pass_rate"`
	TimeoutRate float64                `json:"timeout_rate"`
}

type vettingStatusAdminResponse struct {
	TotalVettingProviders         int   `json:"total_vetting_providers"`
	TotalSyntheticChunksActive    int64 `json:"total_synthetic_chunks_active"`
	TotalSyntheticChunksPendingGC int   `json:"total_synthetic_chunks_pending_gc"`
}

// ── The five new adminClient methods (Session 17.6.2) ──────────────────

func (c *adminClient) fetchReadiness(ctx context.Context) (readinessAdminResponse, error) {
	var resp readinessAdminResponse
	err := c.doGet(ctx, "/api/v1/admin/readiness", &resp)
	return resp, err
}

func (c *adminClient) fetchProviders(ctx context.Context) (adminProvidersResponse, error) {
	var resp adminProvidersResponse
	err := c.doGet(ctx, "/api/v1/admin/providers", &resp)
	return resp, err
}

func (c *adminClient) fetchRepairQueue(ctx context.Context) (repairQueueAdminResponse, error) {
	var resp repairQueueAdminResponse
	err := c.doGet(ctx, "/api/v1/admin/repair/queue", &resp)
	return resp, err
}

func (c *adminClient) fetchAuditStats(ctx context.Context) (auditStatsAdminResponse, error) {
	var resp auditStatsAdminResponse
	err := c.doGet(ctx, "/api/v1/admin/audit/stats", &resp)
	return resp, err
}

func (c *adminClient) fetchVettingStatus(ctx context.Context) (vettingStatusAdminResponse, error) {
	var resp vettingStatusAdminResponse
	err := c.doGet(ctx, "/api/v1/admin/vetting/status", &resp)
	return resp, err
}

// ═══════════════════════════════════════════════════════════════════════
// watchSnapshot — the one serializable shape both View() (rendered as
// panels) and --json (task item 5) are built from. 17.8.2 asserts on
// exactly this shape (task item 5's own wording), so its JSON tags are
// this session's real, load-bearing wire contract even though nothing
// server-side parses it back.
// ═══════════════════════════════════════════════════════════════════════

type watchSnapshot struct {
	Timestamp     time.Time                   `json:"timestamp"`
	Readiness     *readinessAdminResponse     `json:"readiness,omitempty"`
	Providers     *adminProvidersResponse     `json:"providers,omitempty"`
	RepairQueue   *repairQueueAdminResponse   `json:"repair_queue,omitempty"`
	AuditStats    *auditStatsAdminResponse    `json:"audit_stats,omitempty"`
	VettingStatus *vettingStatusAdminResponse `json:"vetting_status,omitempty"`
	// FetchErrors: task item text gives no ADR-specified shape for
	// reporting a partial fan-out failure, so this is this session's own
	// design choice — one string per failed endpoint, rather than
	// aborting the whole snapshot when only one of five calls fails
	// (TestUpdateHandlesFetchErrorWithoutPanicking's whole point: a
	// single failed endpoint degrades that one panel, not the console).
	FetchErrors []string `json:"fetch_errors,omitempty"`
}

// eventFeedEntry is one line in the Event feed panel (D-2's "rolling log
// of node entry, status transition, transfer, repair, audit, and payment
// events"). transfer/payment entries are not produced by this session —
// there is no live escrow/payout data source until Session 17.6.3's
// `operator payout` snapshot exists (the same gap the Escrow & release
// panel's money fields disclose, see panels.go). node-entry,
// status-transition, repair, and audit entries ARE produced, from real
// deltas between consecutive fetch cycles.
type eventFeedEntry struct {
	At      time.Time
	Kind    string // "node_entry" | "status_transition" | "repair" | "audit"
	Message string
}

const maxEventFeedEntries = 20

// ═══════════════════════════════════════════════════════════════════════
// Bubble Tea Model
// ═══════════════════════════════════════════════════════════════════════

const tickInterval = 1 * time.Second

// fanOutEndpointCount is the number of admin endpoints fetchCmd polls
// concurrently each cycle (task item 1's own five: readiness, providers,
// repair queue, audit stats, vetting status) — named so wg.Add's argument
// isn't a bare literal that could silently drift from the actual number of
// goroutines launched below.
const fanOutEndpointCount = 5

// fetchTimeout bounds one fan-out cycle so a single unreachable endpoint
// cannot stall the console indefinitely — five times tickInterval gives
// each cycle room to complete well before the next tick fires.
const fetchTimeout = 5 * time.Second

// pageScrollLines is how far PgUp/PgDn move in one press — enough to skip
// past a whole panel, not just nudge past a couple of rows.
const pageScrollLines = 10

type tickMsg time.Time

// fetchResultMsg carries one fan-out cycle's results. Fields are pointers
// (nil on that endpoint's own failure) precisely so one bad endpoint does
// not blank the whole snapshot — see watchSnapshot.FetchErrors above.
type fetchResultMsg struct {
	at            time.Time
	readiness     *readinessAdminResponse
	providers     *adminProvidersResponse
	repairQueue   *repairQueueAdminResponse
	auditStats    *auditStatsAdminResponse
	vettingStatus *vettingStatusAdminResponse
	errs          []string
}

type watchModel struct {
	client  *adminClient
	profile config.NetworkProfile

	width, height int
	quitting      bool

	// now is the model's own notion of "the current time" — set only from
	// tickMsg's own timestamp, never time.Now(), so Update/View stay pure
	// functions of state (this file's header note).
	now time.Time

	snapshot    watchSnapshot
	haveData    bool // false until the first successful fetch cycle lands
	prevSnap    watchSnapshot
	events      []eventFeedEntry
	fetchCycles int

	// focus is 0 for the normal seven-panel grid, or 1-7 to render a
	// single panel full-width — panelIndex below is the one place that
	// ordering (and the digit each panel answers to) is defined. showHelp
	// overlays the '?' legend on top of whichever view is current.
	// scrollOffset is a line count into the rendered body, clamped in
	// View so scrolling can never run off either end; it resets to 0 on
	// every focus/help toggle so switching views never starts pre-scrolled.
	focus        int
	showHelp     bool
	scrollOffset int
}

func newWatchModel(client *adminClient, profile config.NetworkProfile) watchModel {
	return watchModel{client: client, profile: profile, now: time.Now()}
}

func (m watchModel) Init() tea.Cmd {
	return tea.Batch(fetchCmd(m.client), tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(tickInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// fetchCmd runs the fan-out fetch across all five endpoints concurrently
// (task item 1) and reports a single fetchResultMsg. Each endpoint's own
// error is captured independently — one slow or failing endpoint never
// blocks or blanks the other four (TestUpdateHandlesFetchErrorWithoutPanicking).
func fetchCmd(client *adminClient) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
		defer cancel()

		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			msg  fetchResultMsg
			errs []string
		)
		msg.at = time.Now()

		fetch := func(name string, f func() error) {
			defer wg.Done()
			if err := f(); err != nil {
				mu.Lock()
				errs = append(errs, name+": "+err.Error())
				mu.Unlock()
			}
		}

		wg.Add(fanOutEndpointCount)
		go fetch("readiness", func() error {
			resp, err := client.fetchReadiness(ctx)
			if err != nil {
				return err
			}
			mu.Lock()
			msg.readiness = &resp
			mu.Unlock()
			return nil
		})
		go fetch("providers", func() error {
			resp, err := client.fetchProviders(ctx)
			if err != nil {
				return err
			}
			mu.Lock()
			msg.providers = &resp
			mu.Unlock()
			return nil
		})
		go fetch("repair_queue", func() error {
			resp, err := client.fetchRepairQueue(ctx)
			if err != nil {
				return err
			}
			mu.Lock()
			msg.repairQueue = &resp
			mu.Unlock()
			return nil
		})
		go fetch("audit_stats", func() error {
			resp, err := client.fetchAuditStats(ctx)
			if err != nil {
				return err
			}
			mu.Lock()
			msg.auditStats = &resp
			mu.Unlock()
			return nil
		})
		go fetch("vetting_status", func() error {
			resp, err := client.fetchVettingStatus(ctx)
			if err != nil {
				return err
			}
			mu.Lock()
			msg.vettingStatus = &resp
			mu.Unlock()
			return nil
		})
		wg.Wait()

		msg.errs = errs
		return msg
	}
}

func (m watchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		key := msg.String()
		switch {
		case key == "q" || key == "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case key == "?":
			// The legend is a read-only overlay, not a view of its own —
			// toggling it never touches focus or scroll, so closing it
			// always returns exactly where the audience was looking.
			m.showHelp = !m.showHelp
			return m, nil

		case key == "esc" || key == "0":
			// esc/0 always means "back to the grid", from focus, from
			// help, or both at once — one key the audience never has to
			// think about mid-demo.
			m.focus = 0
			m.showHelp = false
			m.scrollOffset = 0
			return m, nil

		case len(key) == 1 && key[0] >= '1' && key[0] <= '7':
			n := int(key[0] - '0')
			if m.focus == n {
				m.focus = 0 // pressing the same digit again un-zooms
			} else {
				m.focus = n
			}
			m.scrollOffset = 0
			return m, nil

		case key == "up" || key == "k":
			if m.scrollOffset > 0 {
				m.scrollOffset--
			}
			return m, nil

		case key == "down" || key == "j":
			m.scrollOffset++ // View clamps this against actual content height
			return m, nil

		case key == "pgup":
			m.scrollOffset -= pageScrollLines
			if m.scrollOffset < 0 {
				m.scrollOffset = 0
			}
			return m, nil

		case key == "pgdown":
			m.scrollOffset += pageScrollLines
			return m, nil
		}
		return m, nil

	case tickMsg:
		// Advances the model's own clock and schedules both the next
		// tick and the next fetch — TestUpdateAdvancesStateOnTickMsg
		// asserts m.now moves forward on exactly this message, with no
		// wall-clock read inside Update itself.
		m.now = time.Time(msg)
		return m, tea.Batch(fetchCmd(m.client), tickCmd())

	case fetchResultMsg:
		m.applyFetchResult(msg)
		return m, nil

	default:
		return m, nil
	}
}

// applyFetchResult folds one fetch cycle into the model: updates the
// snapshot (per-endpoint — a nil field on this cycle keeps the previous
// cycle's value rather than blanking that panel), appends any derived
// event-feed entries, and records fetch errors. Never panics on a partial
// or fully-failed cycle (TestUpdateHandlesFetchErrorWithoutPanicking) —
// every field access here is nil-checked.
func (m *watchModel) applyFetchResult(msg fetchResultMsg) {
	m.fetchCycles++
	m.prevSnap = m.snapshot

	next := m.snapshot
	next.Timestamp = msg.at
	next.FetchErrors = msg.errs
	if msg.readiness != nil {
		next.Readiness = msg.readiness
	}
	if msg.providers != nil {
		next.Providers = msg.providers
	}
	if msg.repairQueue != nil {
		next.RepairQueue = msg.repairQueue
	}
	if msg.auditStats != nil {
		next.AuditStats = msg.auditStats
	}
	if msg.vettingStatus != nil {
		next.VettingStatus = msg.vettingStatus
	}
	m.snapshot = next

	if msg.readiness != nil || msg.providers != nil || msg.repairQueue != nil ||
		msg.auditStats != nil || msg.vettingStatus != nil {
		m.haveData = true
	}

	m.appendDerivedEvents(msg.at)
}

// appendDerivedEvents diffs m.prevSnap against m.snapshot to produce
// node-entry, status-transition, repair, and audit feed entries — see
// eventFeedEntry's own doc comment on why transfer/payment entries are not
// produced here.
func (m *watchModel) appendDerivedEvents(at time.Time) {
	add := func(kind, msgText string) {
		m.events = append(m.events, eventFeedEntry{At: at, Kind: kind, Message: msgText})
		if len(m.events) > maxEventFeedEntries {
			m.events = m.events[len(m.events)-maxEventFeedEntries:]
		}
	}

	if m.snapshot.Providers != nil {
		prevByID := map[string]providerAdminItem{}
		if m.prevSnap.Providers != nil {
			for _, p := range m.prevSnap.Providers.Providers {
				prevByID[p.ProviderID] = p
			}
		}
		for _, p := range m.snapshot.Providers.Providers {
			old, existed := prevByID[p.ProviderID]
			switch {
			case !existed && m.prevSnap.Providers != nil:
				add("node_entry", "provider "+p.ProviderID+" joined ("+p.Status+")")
			case existed && old.Status != p.Status:
				add("status_transition", "provider "+p.ProviderID+": "+old.Status+" -> "+p.Status)
			}
		}
	}

	if m.snapshot.RepairQueue != nil && m.prevSnap.RepairQueue != nil {
		prevByID := map[string]string{}
		for _, j := range m.prevSnap.RepairQueue.Jobs {
			prevByID[j.JobID] = j.Status
		}
		for _, j := range m.snapshot.RepairQueue.Jobs {
			if oldStatus, existed := prevByID[j.JobID]; existed && oldStatus != j.Status {
				add("repair", "repair job "+j.JobID+": "+oldStatus+" -> "+j.Status)
			}
		}
	}

	if m.snapshot.AuditStats != nil && m.prevSnap.AuditStats != nil {
		if delta := m.snapshot.AuditStats.Challenges - m.prevSnap.AuditStats.Challenges; delta > 0 {
			add("audit", pluralCount(delta, "new audit challenge issued", "new audit challenges issued"))
		}
	}
}

// pluralCount is a tiny int64-aware pluraliser — no fmt.Sprintf("%d ...")
// needed at call sites that already have the count as text.
func pluralCount(n int64, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.FormatInt(n, 10) + " " + plural
}

// View renders the header bar and either the seven-panel grid, one focused
// panel, or the legend overlay — exactly one of those three, never a
// composite of two, since compositing an overlay ON TOP of live content
// without a terminal library's absolute positioning support is the kind of
// thing that looks fine in testing and tears on a real terminal size this
// wasn't tried against. A pure function of m: no wall-clock read, no I/O —
// everything it needs is already in the model from the last
// tickMsg/fetchResultMsg (this file's header note).
//
// [Redesigned, Session 18.1.3] Previously a flat top-to-bottom stack of all
// seven panels with no way to see more than one screen's worth at once, no
// way to enlarge any single panel, and inline prose cluttering several
// panel bodies (moved to the legend — see panels.go's renderLegend and each
// panel's own [Trimmed, Session 18.1.3] note for where its explanation went).
func (m watchModel) View() string {
	if m.quitting {
		return ""
	}

	header := headerBarStyle.Render(fmt.Sprintf("VYOMANAUT OPERATOR CONSOLE \u2014 mode=%s", m.profile.Mode))
	if !m.haveData {
		return header + "\n\n" + dimStyle.Render("waiting for first fetch...") + "\n\n" + footerStyle.Render("[q] quit")
	}

	if m.showHelp {
		body, hint := m.applyScroll(legendStyle.Render(renderLegend(m.profile)), false)
		return header + "\n" + body + "\n" + footerStyle.Render("[?] or [esc] close legend"+hint)
	}

	var errLine string
	if len(m.snapshot.FetchErrors) > 0 {
		errLine = "\n" + statusStyle(severityWarn).Render(fmt.Sprintf("fetch errors: %s", strings.Join(m.snapshot.FetchErrors, "; ")))
	}

	body, hint := m.applyScroll(m.bodyForFocus(), errLine != "")

	return header + "\n" + body + errLine + "\n" + footerStyle.Render(m.footerHint()+hint)
}

// bodyForFocus renders either the full seven-panel grid (m.focus == 0) or
// one panel alone at m.focus (1-7, in the same top-to-bottom reading order
// the grid uses: Readiness, Fleet, ASN diversity, Repair, Audit, Escrow,
// Event feed — the digit a key press answers to is defined nowhere else).
//
// The event feed's line budget differs between the two paths because its
// competition for vertical space differs: in the grid it shares the screen
// with six other panels (eventFeedBudget subtracts their rendered height);
// focused, it IS the screen, so it gets everything but the chrome around it
// (focusedEventFeedBudget).
func (m watchModel) bodyForFocus() string {
	readiness := renderReadiness(m.profile, m.snapshot.Readiness)
	fleet := renderFleet(m.profile, m.snapshot.Providers, m.snapshot.Readiness, m.now)
	asn := renderASNCap(m.profile, m.snapshot.Providers)
	repair := renderRepair(m.profile, m.snapshot.RepairQueue)
	audit := renderAudit(m.profile, m.snapshot.AuditStats, m.now)
	escrow := renderEscrow(m.profile)

	switch m.focus {
	case 1:
		return readiness
	case 2:
		return fleet
	case 3:
		return asn
	case 4:
		return repair
	case 5:
		return audit
	case 6:
		return escrow
	case 7:
		return renderEventsWithin(m.events, m.now, m.focusedEventFeedBudget())
	}

	// Grid: two compact status panels side by side, the wide provider
	// table on its own row, two more compact panels side by side, escrow
	// on its own row (short, but not worth crowding against the others'
	// widths), and the event feed last with whatever budget remains.
	row1 := lipgloss.JoinHorizontal(lipgloss.Top, readiness, asn)
	row3 := lipgloss.JoinHorizontal(lipgloss.Top, repair, audit)
	fixedRows := []string{row1, fleet, row3, escrow}
	events := renderEventsWithin(m.events, m.now, m.eventFeedBudget(fixedRows))

	return strings.Join(append(fixedRows, events), "\n")
}

// footerHint names the keys that matter for whatever m.focus currently is
// — the grid's full key list is more than a focused view needs to repeat.
func (m watchModel) footerHint() string {
	if m.focus > 0 {
		return fmt.Sprintf("[%d] or [esc] back to grid  [\u2191/\u2193] scroll  [?] legend  [q] quit", m.focus)
	}
	return "[1-7] focus a panel  [\u2191/\u2193 j/k] scroll  [?] legend  [q] quit"
}

// applyScroll windows body down to what m.height actually has room for,
// returning the visible slice and a "[lines a-b/n]" hint for the footer
// (empty when nothing was cut). It never mutates m.scrollOffset — Update is
// the only place that changes, and clamping here on every render is what
// keeps scrolling from running off either end without View needing to
// write state back (this file's header note on Update/View purity).
func (m watchModel) applyScroll(body string, hasErrLine bool) (string, string) {
	if m.height <= 0 {
		return body, ""
	}

	lines := strings.Split(body, "\n")
	chromeLines := 2 // header + footer
	if hasErrLine {
		chromeLines++
	}
	viewport := m.height - chromeLines
	if viewport < 1 || len(lines) <= viewport {
		return body, ""
	}

	maxOffset := len(lines) - viewport
	offset := m.scrollOffset
	if offset > maxOffset {
		offset = maxOffset
	}
	if offset < 0 {
		offset = 0
	}

	visible := lines[offset : offset+viewport]
	hint := fmt.Sprintf("  [lines %d-%d/%d]", offset+1, offset+viewport, len(lines))
	return strings.Join(visible, "\n"), hint
}

// eventFeedBudget returns how many event lines will fit under the panels
// already rendered, given the terminal height last reported by
// tea.WindowSizeMsg. m.height is 0 before the first resize message arrives
// (and in every test, which never sends one), in which case the feed keeps
// its full default depth — the previous behaviour exactly, so nothing that
// works today changes on a terminal tall enough not to need trimming.
func (m watchModel) eventFeedBudget(fixed []string) int {
	if m.height <= 0 {
		return eventFeedDisplayDepth
	}

	// One line for the header, one for the footer, one for a possible
	// fetch-error line, plus the event panel's own border and title.
	const chromeLines = 3
	const eventPanelChrome = 3

	used := chromeLines + eventPanelChrome
	for _, p := range fixed {
		used += strings.Count(p, "\n") + 1
	}

	budget := m.height - used
	if budget > eventFeedDisplayDepth {
		budget = eventFeedDisplayDepth
	}
	return budget
}

// focusedEventFeedBudget is eventFeedBudget's counterpart when the event
// feed is the ONLY panel on screen (m.focus == 7) — no sibling panels to
// subtract, just the header/footer/panel chrome around it, and no ceiling
// at eventFeedDisplayDepth since a dedicated full screen can reasonably
// show more history than the grid's shared one can.
func (m watchModel) focusedEventFeedBudget() int {
	if m.height <= 0 {
		return eventFeedDisplayDepth
	}
	const chromeLines = 2
	const eventPanelChrome = 3
	budget := m.height - chromeLines - eventPanelChrome
	if budget < minEventFeedDisplayDepth {
		budget = minEventFeedDisplayDepth
	}
	return budget
}

// percentageScale converts a 0..1 fraction to a whole-number percentage —
// shared by scoreLabel below and by panels.go's ASN-cap and audit panels,
// so "100" as the fraction-to-percentage multiplier is named once rather
// than repeated as a bare literal at each call site.
const percentageScale = 100

// asnShardCap returns floor(TotalShards × ASNCapFraction) — ADR-014's own
// per-ASN shard cap, and the ASN-cap panel's governing constant (task item
// 2's table). Deliberately kept in this file rather than panels.go: this
// is the one place in the package that needs an int/float conversion to
// compute it, and panels.go/money.go's own file-scoped convention (this
// session's NFR-038 money discipline extended to the whole rendering
// layer) is to never write a floating-point conversion at all — the ASN
// cap panel calls this function and works only with the resulting int.
func asnShardCap(profile config.NetworkProfile) int {
	return int(profile.ASNCapFraction * float64(profile.TotalShards))
}

// scoreLabel renders a provider score as a whole-number-out-of-100
// percentage. Lives here rather than panels.go for the same reason
// asnShardCap does — its own parameter type is the one place this
// package's scoring value needs to be named, and panels.go's file-scoped
// convention (this session's NFR-038 money discipline extended to the
// whole rendering layer, not just the escrow panel) never spells that
// type out. panels.go only ever calls this function.
func scoreLabel(score *float64) string {
	if score == nil {
		return "\u2014"
	}
	return fmt.Sprintf("%d%%", int(*score*percentageScale))
}
