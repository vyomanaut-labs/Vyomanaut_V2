#!/usr/bin/env bash
  set -euo pipefail
  REPO_ROOT="$(git rev-parse --show-toplevel)"
  FAIL=0

  # [M11 audit remediation, Finding 8 — found while fixing it, broader than
  # the audit's own report] check() previously piped its detection grep
  # straight into `grep -q .` for the pass/fail test:
  #   if grep -rn ... "$pattern" ... | grep -q .; then FAIL; else PASS; fi
  # Under `set -o pipefail` (line 2), this silently false-PASSES whenever
  # the upstream grep has enough matching output that `grep -q .` exits
  # (after its first match) before the upstream grep finishes writing:
  # the upstream process gets SIGPIPE, exits 141, and pipefail reports the
  # *pipeline's* status as that 141 — a non-zero status — so the `if`
  # branches to the else (PASS) branch even though a match was genuinely
  # found. Reproduced concretely: running the unpatched ADR_REFERENCE
  # check's exact grep command stand-alone found real matches and exited 0,
  # but running it through this piped `if` construct printed PASS. This
  # affected every check using this helper (not just ADR_REFERENCE),
  # non-deterministically (it depends on pipe-buffer timing, i.e. how much
  # matching output exists) — a forbidden-pattern gate that can silently
  # not-fire is worse than not having it, since it looks green. Fixed by
  # capturing the grep's output into a variable first and testing that
  # directly, with no second process to race against.
  check() {
    local name="$1"; local pattern="$2"; local scope="$3"
    local matches
    matches="$(grep -rn --include="*.go" --include="*.sql" --exclude="doc.go" --exclude="payment_test.go" \
         -E "$pattern" "$REPO_ROOT/$scope" 2>/dev/null || true)"
    if [[ -n "$matches" ]]; then
      echo "FAIL [$name]: pattern '$pattern' found in '$scope':"
      echo "$matches"
      FAIL=1
    else
      echo "PASS [$name]"
    fi
  }

  # Check 8: challenge_nonce must be BYTEA(33), never BYTEA(32)
  check "NONCE_LENGTH" \
    " octet_length\(challenge_nonce\)\s*=\s*32\b" \
    "."

  # Check 9: no float types in payment package
  check "NO_FLOAT_PAYMENT" \
    "(float64|float32|FLOAT|DECIMAL|NUMERIC)" \
    "internal/payment"

  # Check 10: no references to ADRs beyond the current known ceiling.
  #
  # [M11 audit remediation, Finding 8] The version this replaces —
  # `ADR-(0[0-9][1-9]|0[1-9]0|100)` — matched ADR-001 through ADR-100
  # inclusive, the *opposite* of a ceiling: it should have been flagging
  # references *above* a limit, not every reference *below* one. Given the
  # SIGPIPE bug above, this had been silently never firing regardless.
  #
  # build.md's own Session 0.2.2 (see that section's "Flagged" note)
  # prescribes deriving the ceiling dynamically via
  # `ls "$REPO_ROOT"/docs/decisions/ADR-*.md` instead of hand-maintaining a
  # number. That doesn't apply verbatim in *this* repository: ADR documents
  # live in the separate Vyomanaut_Research repo, which CI never checks out
  # here (confirmed against .github/workflows/ci.yml — a single
  # actions/checkout@v7 of this repo only, no submodule, no second
  # checkout) — `ls "$REPO_ROOT"/docs/decisions/ADR-*.md` finds nothing in
  # this repo, so $MAX_ADR would be empty, and awk's numeric comparison
  # against an empty string treats it as 0 — every single ADR citation in
  # the codebase would then compare as "above the ceiling" and fail CI
  # outright. Verified this empirically before writing the fix below,
  # rather than copying build.md's script as-is.
  #
  # What's kept from build.md's version: the robust numeric-comparison
  # logic (extract every cited ADR-NNN, compare arithmetically against the
  # ceiling) instead of a hand-rolled regex range, which is what actually
  # made the old ceiling brittle — every previous bump required re-deriving
  # a new regex range by hand. What's changed: the ceiling itself is a
  # single named constant local to this repo, since the authoritative ADR
  # list isn't available here. Bump MAX_KNOWN_ADR the same day a PR first
  # cites a newly-adopted ADR; nothing else in this check needs to change
  # when that happens.
  #
  # [M11 audit remediation, Finding 8 — corrected at application time] The
  # original remediation set this to 61, correct against the repo state it
  # was written against. By the time this fix actually landed, the codebase
  # already cited ADR-064 and ADR-070 through ADR-075 (M12-M16 work) — so
  # applying 61 here verbatim would have fixed the SIGPIPE bug above and
  # then immediately broken CI on every one of those legitimate citations,
  # the same day this fix shipped. Verified via `grep -rhoE "ADR-0*[0-9]+"
  # --include="*.go" --include="*.sql" ... | sort -nu | tail` against this
  # repo before setting the value below — re-run that same command before
  # ever lowering this constant.
  MAX_KNOWN_ADR=77
  bad_adrs="$(grep -rhoE "ADR-0*[0-9]+" --include="*.go" --include="*.sql" --exclude="doc.go" --exclude="payment_test.go" \
      "$REPO_ROOT" 2>/dev/null | sed -E 's/ADR-0*([0-9]+)/\1/' | sort -nu | awk -v max="$MAX_KNOWN_ADR" '$1 > max' || true)"
  if [[ -n "$bad_adrs" ]]; then
    echo "FAIL [ADR_REFERENCE]: reference(s) above current known ceiling ADR-$MAX_KNOWN_ADR found: $bad_adrs"
    FAIL=1
  else
    echo "PASS [ADR_REFERENCE] (ceiling: ADR-$MAX_KNOWN_ADR)"
  fi

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
  