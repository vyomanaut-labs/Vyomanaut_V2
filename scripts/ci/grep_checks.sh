#!/usr/bin/env bash
  set -euo pipefail
  REPO_ROOT="$(git rev-parse --show-toplevel)"
  FAIL=0

  check() {
    local name="$1"; local pattern="$2"; local scope="$3"
    if grep -rn --include="*.go" --include="*.sql" --exclude="doc.go" --exclude="payment_test.go" \
         -E "$pattern" "$REPO_ROOT/$scope" 2>/dev/null | grep -q .; then
      echo "FAIL [$name]: pattern '$pattern' found in '$scope':"
      grep -rn --include="*.go" --include="*.sql" --exclude="doc.go" --exclude="payment_test.go" \
           -E "$pattern" "$REPO_ROOT/$scope"
      FAIL=1
    else
      echo "PASS [$name]"
    fi
  }

  # require() is check()'s positive-assertion companion (M17-E Session
  # 17.8.2, build_part3.md Phase 17.8 task item 7): check() fails when a
  # pattern IS found; require() fails when a pattern is ABSENT. Used below
  # to register each of the eleven founding-requirement integration tests
  # (demo_requirements_test.go, demo_departure_test.go's own TestReqD07) by
  # name, so a future session that deletes one breaks CI instead of
  # passing quietly — ADR-084-demo-presentation-surface.md's own
  # Consequences section names this exact guarantee.
  require() {
    local name="$1"; local pattern="$2"; local scope="$3"
    if grep -rn --include="*.go" -E "$pattern" "$REPO_ROOT/$scope" 2>/dev/null | grep -q .; then
      echo "PASS [$name]"
    else
      echo "FAIL [$name]: required pattern '$pattern' NOT found in '$scope'"
      FAIL=1
    fi
  }

  # The eleven founding requirements (ADR-084-demo-presentation-surface.md
  # Appendix A) — each acquires a named integration test, registered here.
  require "REQD01_PRESENT" "func TestReqD01OwnerUploadsLocalFile\(" "scripts/test"
  require "REQD02_PRESENT" "func TestReqD02SevenProvidersVolunteerAndReachActive\(" "scripts/test"
  require "REQD03_PRESENT" "func TestReqD03FileIsEncryptedAndDistributedAcrossDistinctASNs\(" "scripts/test"
  require "REQD04_PRESENT" "func TestReqD04OperatorSeesNetworkStateAndCannotDecode\(" "scripts/test"
  require "REQD05_PRESENT" "func TestReqD05ProviderLocalStorageIsCiphertext\(" "scripts/test"
  require "REQD06_PRESENT" "func TestReqD06HeartbeatMarksProviderOnline\(" "scripts/test"
  require "REQD07_PRESENT" "func TestReqD07FileRetrievableAfterProviderLossAndRepair\(" "scripts/test"
  require "REQD08_PRESENT" "func TestReqD08RetrievedBytesIdenticalToUploaded\(" "scripts/test"
  require "REQD09_PRESENT" "func TestReqD09AuditChallengeVerifiesProviderStorage\(" "scripts/test"
  require "REQD10_PRESENT" "func TestReqD10PaymentSplitsEquallyAcrossProviders\(" "scripts/test"
  require "REQD11_PRESENT" "func TestReqD11ProviderAllocationIsHonoured\(" "scripts/test"

  # Check 8: challenge_nonce must be BYTEA(33), never BYTEA(32)
  check "NONCE_LENGTH" \
    " octet_length\(challenge_nonce\)\s*=\s*32\b" \
    "."

  # Check 9: no float types in payment package
  check "NO_FLOAT_PAYMENT" \
    "(float64|float32|FLOAT|DECIMAL|NUMERIC)" \
    "internal/payment"

  # Check 10: no references to ADRs beyond the current known ceiling.
  # Pattern matches 001-099 and 100
  # This is done deliberately because the project in under development and constant research, making the ADR count highly volatile. To avoid constant clashes in the count a safe ceiling of 100 is chosen. Update it only after the project reaches production
  check "ADR_REFERENCE" \
    "ADR-(0[0-9][1-9]|0[1-9]0|100)" \
    "."

  # Check 11: no UPI Collect API endpoint calls
  check "NO_UPI_COLLECT" \
    "virtual_accounts|upi/collect|collect/request" \
    "internal"

  # Supplementary check (not one of the 16 numbered CI gates — add alongside them)
  # Session 7.1.1: ChallengeNonce returns [33]byte, never [32]byte. Catches a
  # call site that narrows the result to [32]byte at the Go level — the
  # source-level complement to check 8's BYTEA(33) schema check.
  check "NONCE_TRUNCATION_GO" \
    "\[32\]byte.*ChallengeNonce\(|ChallengeNonce\([^)]*\).*\[32\]byte" \
    "internal"

  # Supplementary check (not one of the 16 numbered CI gates — add alongside
  # them, same as NONCE_TRUNCATION_GO above). Originally written in
  # OBS.3.1 as "Check 16"; renumbered off that label once OBS.4.1's
  # official orphan-name gate below claimed the real Check 16 (build.md's
  # own Phase OBS.4 header registers it as such). Kept as a standing,
  # narrower dashboard-only check rather than removed: it duplicates part
  # of that gate's forward direction, but a second, independently-written
  # check covering the same drift class is cheap defense in depth, not
  # redundant risk.
  #
  # [Decision — OBS.3.1] A Prometheus Histogram is exposed under three
  # wire-format series — <name>_bucket, <name>_sum, <name>_count — none of
  # which is ever written literally in internal/metrics/*.go; only the
  # base name is. A real dashboard PromQL query against a histogram (e.g.
  # histogram_quantile(...vyomanaut_db_read_latency_seconds_bucket...))
  # necessarily uses one of those suffixed names, so a naive exact-string
  # lookup against the registry would flag every histogram panel as an
  # orphan. This check strips a trailing _bucket/_sum/_count before
  # comparing against the registry, exactly mirroring how Prometheus
  # itself derives those series names from a Histogram's base name.
  check_grafana_dashboard_metric_names() {
    local dashboard="$REPO_ROOT/deployments/grafana/dashboards/vyomanaut.json"
    local registry_dir="$REPO_ROOT/internal/metrics"
    local orphan_found=0

    if [[ ! -f "$dashboard" ]]; then
      echo "FAIL [GRAFANA_DASHBOARD_METRIC_NAMES]: $dashboard not found"
      FAIL=1
      return
    fi

    while read -r name; do
      [[ -z "$name" ]] && continue
      local base="${name%_bucket}"
      base="${base%_sum}"
      base="${base%_count}"
      if ! grep -rq -- "$base" "$registry_dir"/*.go 2>/dev/null; then
        echo "FAIL [GRAFANA_DASHBOARD_METRIC_NAMES]: orphan metric name: $name — update metrics/*.go and dashboards simultaneously"
        orphan_found=1
      fi
    done < <(grep -oE "vyomanaut_[a-z_]+" "$dashboard" | sort -u)

    if [[ "$orphan_found" -eq 0 ]]; then
      echo "PASS [GRAFANA_DASHBOARD_METRIC_NAMES]"
    else
      FAIL=1
    fi
  }
  check_grafana_dashboard_metric_names

  # Check 16: TestNoOrphanMetricName (OBS.4.1) — NFR-046's stable-name
  # gate. Extracts every vyomanaut_ metric name from BOTH the dashboard
  # JSON and the alerts YAML (BIDIRECTIONAL_SOURCES) and checks it three
  # ways:
  #   1. Forward: every name found in dashboards/alerts must exist in the
  #      internal/metrics/*.go registry — catches a typo, or a stale
  #      reference to a metric that was renamed or removed.
  #   2. Allow-list (A6): every {subsystem} extracted from a
  #      vyomanaut_{subsystem}_{name}_{unit} name must be one of audit,
  #      scoring, repair, payment, cluster, storage, daemon, db.
  #   3. Reverse: every metric registered in
  #      internal/metrics/microservice.go — the microservice's
  #      centrally-scraped /metrics surface — must be referenced somewhere
  #      in the dashboard or the alerts, catching a newly-added metric
  #      nobody wired into observability.
  #
  # [Decision — OBS.4.1] The reverse direction (3) is deliberately scoped
  # to microservice.go only, excluding internal/metrics/daemon.go. Daemon
  # metrics are registered on each provider's local-only 127.0.0.1:9091
  # endpoint (OBS.2.1) with no fleet-wide aggregation path into the
  # central Grafana instance this dashboard represents (flagged, unsolved,
  # in OBS.3.1's ContentHashFailureDetected alert annotation) — six of the
  # seven daemon metrics correctly have no dashboard/alert reference yet,
  # and enforcing reverse coverage on them would fail this gate on a real
  # architectural gap rather than a genuine orphan. (The seventh,
  # content_hash_failures_total, IS referenced via alerts.yaml and is
  # covered either way.) Narrowing the reverse check to microservice.go
  # keeps the gate meaningful without asserting a fleet-aggregation path
  # that doesn't exist yet.
  #
  # Reuses OBS.3.1's _bucket/_sum/_count stripping (see
  # check_grafana_dashboard_metric_names above) for the same reason: a
  # real PromQL histogram_quantile() query can't avoid one of those wire
  # suffixes, so a naive exact-string lookup would flag every histogram
  # panel as a false orphan in both directions.
  check_no_orphan_metric_name() {
    local dashboard="$REPO_ROOT/deployments/grafana/dashboards/vyomanaut.json"
    local alerts="$REPO_ROOT/deployments/grafana/alerts.yaml"
    local registry_dir="$REPO_ROOT/internal/metrics"
    local allowlist="audit scoring repair payment cluster storage daemon db"
    local bad=0

    strip_suffix() {
      local n="$1"
      n="${n%_bucket}"; n="${n%_sum}"; n="${n%_count}"
      printf '%s' "$n"
    }

    subsystem_of() {
      local n="${1#vyomanaut_}"
      printf '%s' "${n%%_*}"
    }

    in_allowlist() {
      local s="$1" a
      for a in $allowlist; do
        [[ "$s" == "$a" ]] && return 0
      done
      return 1
    }

    # --- forward + allow-list: every name in dashboards/alerts.yaml must
    # resolve to a registered metric with an allow-listed subsystem ---
    while read -r name; do
      [[ -z "$name" ]] && continue
      local base; base="$(strip_suffix "$name")"
      if ! grep -rq -- "$base" "$registry_dir"/*.go 2>/dev/null; then
        echo "FAIL [NO_ORPHAN_METRIC_NAME]: orphan metric name: $name — update metrics/*.go and dashboards simultaneously"
        bad=1
      fi
      local sub; sub="$(subsystem_of "$base")"
      if ! in_allowlist "$sub"; then
        echo "FAIL [NO_ORPHAN_METRIC_NAME]: orphan metric name: $name — update metrics/*.go and dashboards simultaneously (subsystem '$sub' not in A6 allow-list)"
        bad=1
      fi
    done < <( { grep -oE "vyomanaut_[a-z_]+" "$dashboard" 2>/dev/null; \
                grep -oE "vyomanaut_[a-z_]+" "$alerts" 2>/dev/null; } | sort -u )

    # --- reverse: every microservice.go metric must be reachable from the
    # dashboard or the alerts (see [Decision] above for the daemon.go
    # scoping) ---
    while read -r name; do
      [[ -z "$name" ]] && continue
      if ! grep -q -- "$name" "$dashboard" "$alerts" 2>/dev/null; then
        echo "FAIL [NO_ORPHAN_METRIC_NAME]: orphan metric name: $name — update metrics/*.go and dashboards simultaneously"
        bad=1
      fi
    done < <(grep -oE "vyomanaut_[a-z_]+" "$registry_dir/microservice.go" 2>/dev/null | sort -u)

    if [[ "$bad" -eq 0 ]]; then
      echo "PASS [NO_ORPHAN_METRIC_NAME]"
    else
      FAIL=1
    fi
  }
  check_no_orphan_metric_name

  exit $FAIL
  