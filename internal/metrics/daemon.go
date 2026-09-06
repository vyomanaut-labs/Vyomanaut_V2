// Package metrics is declared in microservice.go. This file implements the
// provider daemon's local-status metrics (NFR-026): chunks stored, audit
// response volume/latency, vLog append latency, content hash failures,
// heartbeat volume, and RAM-constrained state — exposed on a loopback-only
// HTTP server FR-029's CLI status view reads directly.
//
// [Decision — OBS.2.1] NFR-046 states every microservice AND provider-daemon
// metric name follows vyomanaut_{subsystem}_{name}_{unit} with unit ==
// OpenMetrics base units (_seconds for histograms) — but this session's own
// frozen table spells both daemon histograms below with _milliseconds. Kept
// exactly as frozen (build.md Session OBS.2.1 is this file's contract)
// rather than silently renamed to _seconds: these two histograms feed
// FR-029's human-facing CLI status display on a local-only,
// non-Prometheus-scraped endpoint (see daemonStatusAddr below), not the
// microservice's Grafana-scraped /metrics — milliseconds are more directly
// useful there, and neither OBS.3.1's Grafana dashboard nor OBS.4.1's
// orphan-name CI gate reference daemon metrics at all. Flagging for
// Karma: either amend NFR-046 to scope its unit rule to the microservice's
// public endpoint, or add an ADR addendum documenting this as an
// intentional exception.
//
// [Decision — OBS.2.1] NFR-026 also lists "pending earnings in paise" as a
// required local-status field; this session's frozen table (and ARCH §23's
// own provider-daemon metrics list) has no such metric. Not added here
// silently — a provider daemon self-reporting its own earnings via a
// locally-exposed Prometheus gauge would let a malicious operator simply
// lie about what they're owed, so the authoritative figure almost
// certainly belongs on the microservice side (internal/payment's escrow
// ledger, already queried by providerBalance in ledger.go) rather than in
// this daemon-local file — but that's a real gap between NFR-026 and both
// ARCH §23 and this frozen table, not resolved here. Flagging for Karma.
package metrics

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// daemonStatusAddr is the provider daemon's local-only metrics/status bind
// address (NFR-026). Loopback only, deliberately never 0.0.0.0 — this
// endpoint has no auth of its own (no daemon-status auth contract exists in
// IC), so publicly exposing it would leak a provider's audit response
// timings, content-hash-failure history, and RAM pressure state to anyone
// who can reach the host.
const daemonStatusAddr = "127.0.0.1:9091"

var (
	// DaemonChunksStoredTotal counts every chunk-store operation this
	// daemon has ever completed — a cumulative activity counter, not a
	// live "chunks currently held" gauge. NFR-026 lists "stored chunk
	// count" as a status-view field; FR-029's CLI derives the *current*
	// count from the local storage engine directly (RocksDB/BadgerDB row
	// count), not from this Prometheus counter, which instead answers
	// "how much storage activity has this daemon done, ever."
	DaemonChunksStoredTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vyomanaut_daemon_chunks_stored_total",
		Help: "Total number of chunk-store operations this daemon has completed.",
	})

	// DaemonAuditResponsesSentTotal counts every audit challenge response
	// this daemon has sent back to the microservice (ARCH §23: "Challenge
	// volume").
	DaemonAuditResponsesSentTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vyomanaut_daemon_audit_responses_sent_total",
		Help: "Total number of audit challenge responses sent.",
	})

	// DaemonAuditResponseLatencyMilliseconds is the distribution of this
	// daemon's own audit-response latency — a local, daemon-side
	// measurement distinct from the microservice-side
	// vyomanaut_db_read_latency_seconds signal (ARCH §23: "Response time
	// distribution"). [Decision — OBS.2.1] Bucket boundaries aren't
	// specified by this session's text; chosen to span a fast local
	// response (10ms) through the ~5s RTO fallback constant Phase 12.1's
	// computeRTO uses during network bootstrap.
	DaemonAuditResponseLatencyMilliseconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vyomanaut_daemon_audit_response_latency_milliseconds",
		Help:    "Distribution of audit challenge response latency in milliseconds.",
		Buckets: []float64{10, 50, 100, 250, 500, 1000, 2500, 5000},
	})

	// DaemonVlogAppendLatencyMilliseconds is the distribution of local
	// append-only vLog write latency (ARCH §23: "Write performance").
	// [Decision — OBS.2.1] Bucket boundaries aren't specified by this
	// session's text; chosen to span a fast SSD append (sub-millisecond)
	// through a visibly slow/contended disk (250ms).
	DaemonVlogAppendLatencyMilliseconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vyomanaut_daemon_vlog_append_latency_milliseconds",
		Help:    "Distribution of append-only vLog write latency in milliseconds.",
		Buckets: []float64{0.5, 1, 5, 10, 25, 50, 100, 250},
	})

	// DaemonContentHashFailuresTotal counts detected silent-corruption
	// events (content hash mismatch on a local read) — the source metric
	// behind the NFR-027 ContentHashFailureDetected alert (ARCH §23:
	// "Silent disk corruption events").
	DaemonContentHashFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vyomanaut_daemon_content_hash_failures_total",
		Help: "Total number of content hash verification failures detected.",
	})

	// DaemonHeartbeatSentTotal counts heartbeats sent to the microservice
	// — this daemon's connectivity signal (ARCH §23: "Connectivity to
	// microservice").
	DaemonHeartbeatSentTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vyomanaut_daemon_heartbeat_sent_total",
		Help: "Total number of heartbeats sent to the microservice.",
	})

	// DaemonRAMConstrained is 1 while this daemon is currently operating
	// under RAM pressure and 0 otherwise (consumed by Session 13.6.1,
	// A1). A plain boolean-valued Gauge rather than a labelled one: this
	// session's "Gauge (`constrained`)" table entry describes what the
	// single value means, not an additional label dimension — there is
	// only ever one series here, one daemon reporting its own state.
	DaemonRAMConstrained = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vyomanaut_daemon_ram_constrained",
		Help: "1 if this daemon is currently operating under RAM pressure, 0 otherwise.",
	})
)

// StartDaemonMetricsServer exposes every metric registered in this file at
// /metrics on daemonStatusAddr (127.0.0.1:9091 — NFR-026's "local status
// interface"). FR-029's CLI status view reads this endpoint directly rather
// than the daemon maintaining any separate in-memory state for it. Returns
// the underlying *http.Server so the daemon's own startup/shutdown sequence
// can manage its lifecycle, plus a channel reporting a non-clean listen
// failure.
// StartDaemonMetricsServer binds daemonStatusAddr (127.0.0.1:9091).
// Prefer this. It preserves NFR-026's loopback-only guarantee.
func StartDaemonMetricsServer() (*http.Server, <-chan error) {
	return StartDaemonMetricsServerOn(daemonStatusAddr)
}

// StartDaemonMetricsServerOn binds an explicitly supplied address.
//
// [Added, M18 Stage 3] Exists solely so a multi-machine rig can be scraped
// by a Prometheus running on another host, which is impossible against a
// loopback bind. It is deliberately a SEPARATE function with an explicit
// argument rather than a mutable package variable, so that every caller
// that leaves loopback behind is visible in a grep for this name.
//
// SECURITY — read before using it. daemonStatusAddr's own comment (above)
// records why loopback is the default: this endpoint has NO authentication
// of any kind, because IC defines no auth contract for daemon status. Any
// address that is not loopback publishes this provider's audit response
// timings, content-hash-failure history, and RAM pressure state to
// everyone who can reach the host. On the isolated, no-uplink demo rig
// that is an acceptable trade for real observability. On any network with
// an uplink it is not, and nothing here enforces the difference — the
// caller does, via an explicit opt-in flag the operator has to type.
func StartDaemonMetricsServerOn(addr string) (*http.Server, <-chan error) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("metrics: daemon status server on %s: %w", addr, err)
			return
		}
		errCh <- nil
	}()

	return srv, errCh
}

// ShutdownDaemonMetricsServer is a small convenience wrapper so the
// provider daemon's shutdown sequence doesn't need its own import of
// net/http just to call Shutdown on the server this package started.
func ShutdownDaemonMetricsServer(ctx context.Context, srv *http.Server) error {
	if srv == nil {
		return nil
	}
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("metrics: shutdown daemon status server: %w", err)
	}
	return nil
}
