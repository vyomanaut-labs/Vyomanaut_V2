// Package metrics registers every Prometheus metric the microservice
// (NFR-025) and provider daemon (NFR-026) expose, under the frozen naming
// contract in NFR-046: vyomanaut_{subsystem}_{name}_{unit}, where
// {subsystem} is drawn from a fixed allow-list rather than an arbitrary
// internal/ package name (A6) so the leaf never has to import the packages
// it instruments (A2).
//
// internal/metrics has zero internal/ imports by design — see window.go's
// doc comment and IC §9 (A2/Option A: this package is an importable leaf).
//
// [Confirmed, C6 dry run] Being one leaf package cuts both ways: cmd/provider
// imports it for daemon.go's collectors (handler_upload.go, handler_audit.go,
// main.go) and cmd/microservice imports it for microservice.go's collectors
// (audit_dispatch.go and others). Every promauto.New*() call in this package
// runs unconditionally at package init, on the DEFAULT Prometheus registerer
// — there is no per-binary split. So importing either half of this package
// registers ALL of it, in both binaries: every provider daemon also exposes
// microservice.go's coordinator-only metrics (repair, audit-issued, escrow,
// cluster, storage-assignment), stuck at their zero value since the code
// that updates them never runs inside cmd/provider; symmetrically, the
// coordinator exposes every daemon-only metric (chunks stored, audit
// responses, vLog latency, content-hash failures, heartbeats, RAM
// constrained) stuck at zero under its own desk label ("COORDINATOR" in
// targets/microservice.json).
//
// This is invisible until a dashboard panel queries one of these metrics
// without aggregating it down or filtering by job: Prometheus happily
// returns the real series plus one dead, always-zero series per target on
// the WRONG job, each carrying that target's own desk/instance labels. The
// Grafana panels affected by this were fixed to either sum() the metric away
// entirely (coordinator-only panels with no per-desk intent) or add an
// explicit job="vyomanaut-providers"/"vyomanaut-microservice" filter
// (per-desk panels, and the $desk template variable itself, which was
// built on a daemon-only metric and so silently offered "COORDINATOR" as a
// selectable desk). The dead series themselves are still there on both
// binaries' /metrics output — this only stops them from reaching a panel.
//
// The clean fix is a separate prometheus.Registry per binary (promauto.With
// per collector, registering only what that binary actually updates) rather
// than the shared default registerer. That is a larger change than this dry
// run's timeline allows and touches both cmd/provider's and
// cmd/microservice's wiring, not just this package — worth a decision, not
// something to take unilaterally this close to a run. Filed the same way as
// the unused StartMicroserviceMetricsServer note in prometheus.yml: real
// tech debt, not a blocker.
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// DefaultAdminMetricsPort is the microservice's default /metrics scrape
// port (NFR-025's "configurable admin port (default 9090)"). Callers that
// need a non-default port (e.g. multiple microservice replicas on one
// host during local dev) pass their own port to
// StartMicroserviceMetricsServer instead of this constant.
const DefaultAdminMetricsPort = 9090

// dbReadLatencyBuckets are the vyomanaut_db_read_latency_seconds histogram
// bucket boundaries (ADR-033). 0.05s is the NFR-028 throttle threshold;
// 0.04s is ADR-033's added early-warning bucket so the throttle loop's
// high-water approach is visible in the histogram one bucket before it
// actually fires.
var dbReadLatencyBuckets = []float64{0.01, 0.025, 0.04, 0.05, 0.1}

// scoreHistogramBuckets covers internal/scoring's ProviderScore range.
// [Decision — OBS.1.1] Not specified by this session's text (only
// db_read_latency_seconds' buckets were); internal/scoring.ProviderScore
// (score.go) is a 0.0-1.0 weighted composite (see Score30dBasisPoints /
// Score7dBasisPoints, which multiply by 10000 — i.e. the underlying score
// is normalized to [0,1]), so linear deciles across that range are the
// natural fit for a reliability-distribution dashboard.
const (
	scoreHistogramBucketSize  = 0.1
	scoreHistogramBucketCount = 11
)

var scoreHistogramBuckets = prometheus.LinearBuckets(
	0,
	scoreHistogramBucketSize,
	scoreHistogramBucketCount,
)

var (
	// AuditChallengesIssuedTotal counts every audit challenge the
	// microservice has issued (audit subsystem, NFR-025).
	AuditChallengesIssuedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vyomanaut_audit_challenges_issued_total",
		Help: "Total number of audit challenges issued to providers.",
	})

	// AuditResultsTotal counts audit outcomes by result
	// (PASS|FAIL|TIMEOUT), the NFR-027 TIMEOUT-rate alert's numerator and
	// denominator.
	AuditResultsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vyomanaut_audit_results_total",
		Help: "Total number of audit results by outcome.",
	}, []string{"result"})

	// ScoringProviderScore is the distribution of computed provider
	// reliability scores (scoring subsystem, NFR-025).
	ScoringProviderScore = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vyomanaut_scoring_provider_score",
		Help:    "Distribution of computed provider reliability scores.",
		Buckets: scoreHistogramBuckets,
	})

	// RepairQueueDepth is the current repair job backlog (repair
	// subsystem). The NFR-027 alert fires above 1,000.
	RepairQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vyomanaut_repair_queue_depth",
		Help: "Current number of jobs in the repair queue.",
	})

	// RepairJobsCompletedTotal counts completed repair jobs (repair
	// subsystem, NFR-025).
	RepairJobsCompletedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vyomanaut_repair_jobs_completed_total",
		Help: "Total number of repair jobs completed.",
	})

	// RepairJobDurationSeconds is the wall-clock time from a job's
	// created_at (EnqueueJob) to its completed_at (MarkJobComplete) —
	// queue wait plus execution together, the same quantity the morning
	// run's repair review had to reconstruct by eye from two
	// RepairQueueDepth screenshots (a 132-job spike draining over roughly
	// 8-9 minutes). Buckets span a fast single-chunk reconstruction (a few
	// seconds) through a queue backed up under load (tens of minutes) —
	// not to the profile's PromisedDowntimeMaximum/DepartureThreshold
	// scale, since a job that old has almost certainly been superseded or
	// abandoned rather than genuinely still running.
	//
	// [Added — Stage 3 final test] Recorded regardless of success/failure,
	// same reasoning as RepairJobsCompletedTotal just above: this is a
	// throughput/latency signal, paired with RepairQueueDepth, not a
	// quality signal.
	RepairJobDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vyomanaut_repair_job_duration_seconds",
		Help:    "Wall-clock time from a repair job's creation to its completion (success or failure), in seconds.",
		Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600, 1200, 1800},
	})

	// StorageChunkAssignmentsTotal counts chunk_assignments rows created
	// by the upload assign path. This is a BOOKKEEPING counter: a row
	// exists the moment the assign transaction commits, before any byte
	// reaches the provider. Compared against the fleet's confirmed-store
	// counter (vyomanaut_daemon_chunks_stored_total), the difference is
	// the assignment/delivery gap that the "Assignment vs confirmed
	// delivery" and "Cumulative assignment/delivery gap" dashboard panels
	// chart.
	//
	// [Decision - NFR-046/A6 naming] Named vyomanaut_storage_chunk_assignments_total
	// rather than an "upload"-prefixed name (the originally proposed one):
	// {subsystem} is drawn from a fixed allow-list (this file's own
	// package doc, A6; enforced mechanically by scripts/ci/grep_checks.sh's
	// NO_ORPHAN_METRIC_NAME gate), and "upload" is not on it - "storage"
	// is, and was otherwise unused. The metric's meaning is unchanged;
	// only the wire name moved to stay inside the frozen naming contract.
	//
	// [Caveat, carried into the dashboard panel descriptions] The
	// comparison is only clean during an upload window once the fleet is
	// fully ACTIVE: cmd/provider/handler_upload.go's chunks-stored
	// increment fires from the single wire-identical
	// /vyomanaut/chunk-upload/1.0.0 stream handler regardless of whether
	// the push is a real upload, a synthetic vetting chunk
	// (internal/vettingchunk/generator.go), or a repair-driven shard
	// re-placement (internal/repair/executor.go) - DM §4.5: "The provider
	// daemon has no visibility into [is_vetting_chunk]; it stores and
	// serves audits for synthetic chunks through the identical code paths
	// as real shards." StorageChunkAssignmentsTotal itself is scoped to
	// this file's assign path only, so any concurrent vetting or repair
	// traffic inflates the "stored" side without a matching "assigned"
	// row and must be excluded from the comparison window.
	StorageChunkAssignmentsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vyomanaut_storage_chunk_assignments_total",
		Help: "Total chunk_assignments rows created by the upload assign path (bookkeeping, not confirmed delivery).",
	})

	// PaymentEscrowEventsTotal counts escrow events by type
	// (DEPOSIT|RELEASE|SEIZURE|REVERSAL), the payment subsystem's volume
	// signal (NFR-025).
	PaymentEscrowEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vyomanaut_payment_escrow_events_total",
		Help: "Total number of escrow events by type.",
	}, []string{"type"})

	// ClusterReplicaCount is the microservice replica count by health
	// state (healthy|degraded). The NFR-027 quorum alert fires when the
	// healthy count drops below 3.
	ClusterReplicaCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vyomanaut_cluster_replica_count",
		Help: "Microservice replica count by health state.",
	}, []string{"state"})

	// dbReadLatencySeconds is the cumulative, dashboard-facing histogram
	// of foreground DB read latency (ADR-033). It is the system of
	// record for NFR-025's exported metric and for Grafana/alerting; it
	// is deliberately NOT what the NFR-028 throttle loop reads (see
	// ForegroundReadP99Window in window.go) because a cumulative
	// histogram's quantile reflects the process's entire lifetime, not
	// the last 60 seconds. [A11] carries no quantile-name label —
	// Prometheus histograms expose quantiles via histogram_quantile() over
	// the bucket boundaries, not via a label dimension.
	dbReadLatencySeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vyomanaut_db_read_latency_seconds",
		Help:    "Foreground DB read latency in seconds.",
		Buckets: dbReadLatencyBuckets,
	})
)

// foregroundReadLatency is the ADR-033 windowed signal: every foreground DB
// read on the audit hot path observes its latency here, which updates both
// the dashboard-facing dbReadLatencySeconds histogram and the NFR-028
// throttle's trailing-window estimator from a single call site.
type foregroundReadLatencyRecorder struct{}

// Observe records one foreground DB read latency sample. It updates the
// cumulative Prometheus histogram (dashboards, NFR-025) and the ADR-033
// sliding window (NFR-028 throttle) together, so callers never have to
// remember to feed both.
func (foregroundReadLatencyRecorder) Observe(d time.Duration) {
	dbReadLatencySeconds.Observe(d.Seconds())
	foregroundWindow.Observe(d)
}

// ForegroundReadLatency is the call site internal/audit's hot path uses
// (Session OBS.1.2) to report foreground DB read latency. See
// ForegroundReadP99Window (window.go) for the corresponding read side.
var ForegroundReadLatency foregroundReadLatencyRecorder

// StartMicroserviceMetricsServer exposes every metric registered in this
// file at /metrics on the given port (NFR-025's "configurable admin
// port"). It returns the underlying *http.Server so cmd/microservice's
// startup sequence can hold onto it for graceful shutdown; the caller is
// responsible for calling Shutdown. Serving errors other than a clean
// shutdown are reported on the returned channel so main() can decide how
// to react (fail startup vs. log-and-continue) rather than this leaf
// package making that call itself.
func StartMicroserviceMetricsServer(port int) (*http.Server, <-chan error) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("metrics: admin server on port %d: %w", port, err)
			return
		}
		errCh <- nil
	}()

	return srv, errCh
}

// ShutdownMicroserviceMetricsServer is a small convenience wrapper so
// cmd/microservice's shutdown sequence doesn't need its own import of
// net/http just to call Shutdown on the server this package started.
func ShutdownMicroserviceMetricsServer(ctx context.Context, srv *http.Server) error {
	if srv == nil {
		return nil
	}
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("metrics: shutdown admin server: %w", err)
	}
	return nil
}
