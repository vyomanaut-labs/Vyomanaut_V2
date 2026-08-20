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
}

type providerAdminItem struct {
	ProviderID        string     `json:"provider_id"`
	PhoneNumber       string     `json:"phone_number"`
	Status            string     `json:"status"`
	ASN               string     `json:"asn"`
	Region            string     `json:"region"`
	LastHeartbeatTS   *time.Time `json:"last_heartbeat_ts"`
	ScoreComposite    *float64   `json:"score_composite"`
	StoredChunks      int        `json:"stored_chunks"`
	Frozen            bool       `json:"frozen"`
	DeclaredStorageGB int        `json:"declared_storage_gb"`
	DepartedAt        *time.Time `json:"departed_at"`
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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

		wg.Add(5)
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
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
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

// View renders the header bar and all seven panels (SEVEN_PANELS_PRESENT
// counts render(Readiness|Fleet|ASNCap|Repair|Audit|Escrow|Events) in
// panels.go directly, not through this function, but this is where every
// one of the seven is actually called for a live run). A pure function of
// m: no wall-clock read, no I/O — everything it needs is already in the
// model from the last tickMsg/fetchResultMsg (this file's header note).
func (m watchModel) View() string {
	if m.quitting {
		return ""
	}

	header := headerBarStyle.Render(fmt.Sprintf("VYOMANAUT OPERATOR CONSOLE \u2014 mode=%s", m.profile.Mode))
	if !m.haveData {
		return header + "\n\n" + dimStyle.Render("waiting for first fetch...") + "\n\n" + dimStyle.Render("press q to quit")
	}

	panels := []string{
		renderReadiness(m.profile, m.snapshot.Readiness),
		renderFleet(m.profile, m.snapshot.Providers, m.now),
		renderASNCap(m.profile, m.snapshot.Providers),
		renderRepair(m.profile, m.snapshot.RepairQueue),
		renderAudit(m.profile, m.snapshot.AuditStats, m.now),
		renderEscrow(m.profile),
		renderEvents(m.events, m.now),
	}

	var errLine string
	if len(m.snapshot.FetchErrors) > 0 {
		errLine = "\n" + statusStyle(severityWarn).Render(fmt.Sprintf("fetch errors: %s", strings.Join(m.snapshot.FetchErrors, "; ")))
	}

	return header + "\n" + strings.Join(panels, "\n") + errLine + "\n" + dimStyle.Render("press q to quit")
}

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
	return fmt.Sprintf("%d%%", int(*score*100))
}
