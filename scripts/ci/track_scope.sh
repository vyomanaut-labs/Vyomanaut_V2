#!/usr/bin/env bash
# scripts/ci/track_scope.sh — MVP §8.4 check 17 (demo track).
#
# Registered in .github/workflows/ci.yml as check-20, not check-17: the
# workflow's job labels and MVP §8.4's check numbers are separate sequences and
# have been since M2 (check-17 is the arm64 cross-build, check-18 and check-19
# are the two native-runner platform-coverage jobs). MVP §8.4 records the same
# note so neither sequence can be mistaken for the other.
#
# Added by build_part3.md Session 18.1.1, closing N-05 and implementing
# ADR-062 §1 and §3 (mandatory, machine-checkable track tagging) together with
# ADR-063 §3 (N-05's three checks are restated, not weakened).
#
# WHY THIS EXISTS. Three verification claims in this repository assert real
# properties of a stack that is not present. internal/p2p/doc.go records that
# go-libp2p was never imported: the transport is stdlib TLS 1.3 over TCP, the
# DHT is a from-scratch Kademlia, and AutoNAT / DCUtR / Circuit Relay v2 are
# hand-rolled. The checks are not wrong — but their stated rationales name
# mechanisms that do not exist here, and a check that passes for a reason
# nobody wrote down is how a false certification survives a repository fork.
# This script makes both halves of the fix non-optional.
#
# ASSERTION 1 — every numbered check in MVP §8.4 carries a Track value.
# ASSERTION 2 — every Go test file whose comments name go-libp2p, QUIC, Noise
#               or Circuit Relay also carries a `TRACK:` marker or a restated
#               demo-track rationale.
#
# Exit 0 on pass, 1 on failure.
#
# [REF: MVP §8.4, ADR-062 §1/§3/§6, ADR-063 §2/§3, build_part3.md Session
# 18.1.1, internal/p2p/doc.go]
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
FAIL=0

pass() { echo "PASS [$1]"; }
fail() { echo "FAIL [$1]: $2"; FAIL=1; }
note() { echo "NOTE [$1]: $2"; }

# ─────────────────────────────────────────────────────────────────────────
# Locating mvp.md.
#
# The system-design documents live in the Vyomanaut_Research repository, not
# in this one — ADR-062 §2 keeps the research corpus shared and unforked
# precisely so the ADR series is not split. This repository therefore cannot
# assume mvp.md is on disk, and must not fail CI when it is not: a check that
# goes red on a clean clone teaches people to ignore it.
#
# Resolution order, first hit wins:
#   1. $VYOMANAUT_DOCS_ROOT              — explicit override
#   2. $REPO_ROOT/docs/system-design     — if the docs are ever vendored in
#   3. sibling checkout of Vyomanaut_Research
#
# When none resolves, assertion 1 reports NOTE and is skipped; assertion 2 is
# fully local and always runs hard. Run this script with the research repo
# checked out beside this one to exercise both halves.
# ─────────────────────────────────────────────────────────────────────────
find_mvp() {
  local candidates=(
    "${VYOMANAUT_DOCS_ROOT:-}/mvp.md"
    "$REPO_ROOT/docs/system-design/mvp.md"
    "$REPO_ROOT/../Vyomanaut_Research/docs/system-design/mvp.md"
  )
  local c
  for c in "${candidates[@]}"; do
    [[ "$c" == "/mvp.md" ]] && continue
    if [[ -f "$c" ]]; then
      printf '%s' "$c"
      return 0
    fi
  done
  return 1
}

# ─────────────────────────────────────────────────────────────────────────
# Assertion 1 — every numbered row of MVP §8.4's check table carries a Track.
#
# The table's shape is `| # | Check | Track | Note |`, so with `|` as the field
# separator the Track cell is field 4 (field 1 is the empty string before the
# leading pipe). A row whose Track cell holds neither DEMO+LTS nor LTS is an
# untagged check, which ADR-062 §3 makes a hard failure.
# ─────────────────────────────────────────────────────────────────────────
check_every_check_has_a_track_value() {
  local name="EVERY_CHECK_HAS_A_TRACK_VALUE"
  local mvp
  if ! mvp="$(find_mvp)"; then
    note "$name" "mvp.md not found — set VYOMANAUT_DOCS_ROOT to Vyomanaut_Research/docs/system-design, or check that repo out beside this one, to enforce this assertion"
    return
  fi

  local untagged
  untagged="$(awk -F'|' '/^\| *[0-9]+ *\|/ {
      if ($4 !~ /(DEMO\+LTS|LTS)/) { gsub(/^ +| +$/, "", $2); print $2 }
    }' "$mvp")"

  if [[ -n "$untagged" ]]; then
    local row
    while read -r row; do
      [[ -z "$row" ]] && continue
      fail "$name" "MVP §8.4 check $row carries no Track value (expected DEMO+LTS or LTS) — ADR-062 §3"
    done <<< "$untagged"
    return
  fi

  local rows
  rows="$(grep -cE '^\| *([1-9]|1[0-6]) *\|' "$mvp" || true)"
  if [[ "$rows" -ne 16 ]]; then
    fail "$name" "expected 16 numbered rows in MVP §8.4's check table, found $rows in $mvp"
    return
  fi

  pass "$name"
}

# ─────────────────────────────────────────────────────────────────────────
# Assertion 2 — no test file names an absent mechanism without restating it.
#
# Scope is deliberately *_test.go, per Session 18.1.1's own wording. The
# non-test files that name these mechanisms are describing the substitution
# rather than asserting a verification claim on top of it, and
# internal/p2p/doc.go is the authoritative record for all of them; a count of
# those files is printed as a NOTE so the inventory stays visible without
# turning ADR-063's own substitution record into a CI failure.
# ─────────────────────────────────────────────────────────────────────────
ABSENT_MECHANISMS='go-libp2p|QUIC|Noise|Circuit Relay'
RESTATEMENT_MARKERS='TRACK: LTS|TRACK: DEMO\+LTS|does not exist on the demo track|Not QUIC|not measurable on the demo track'

check_libp2p_dependent_tests_carry_restated_rationale() {
  local name="LIBP2P_DEPENDENT_TESTS_CARRY_RESTATED_RATIONALE"
  local unrestated=0
  local f

  while read -r f; do
    [[ -z "$f" ]] && continue
    if ! grep -qE "$RESTATEMENT_MARKERS" "$f"; then
      fail "$name" "$f names an absent mechanism (go-libp2p / QUIC / Noise / Circuit Relay) with no TRACK marker or restated demo-track rationale — ADR-063 §3"
      unrestated=1
    fi
  done < <(grep -rlE "$ABSENT_MECHANISMS" --include='*_test.go' "$REPO_ROOT" 2>/dev/null | sort)

  if [[ "$unrestated" -eq 0 ]]; then
    pass "$name"
  fi

  local nontest
  nontest="$(grep -rlE "$ABSENT_MECHANISMS" --include='*.go' "$REPO_ROOT" 2>/dev/null \
    | grep -cv '_test\.go$' || true)"
  note "$name" "$nontest non-test Go files also name these mechanisms; internal/p2p/doc.go is their authoritative substitution record (ADR-063 §1), so they are inventoried here, not gated"
}

# ─────────────────────────────────────────────────────────────────────────
# Assertion 3 — the two unnumbered claims keep their demo-track restatement.
#
# NFR-016's named test (TestTransportAuthentication) does not exist on this
# track, and NFR-006's relay budget is not measurable on it. Both restatements
# live in internal/p2p/host_test.go. Deleting them would silently restore the
# original, wrong grounds, so their presence is asserted directly.
# ─────────────────────────────────────────────────────────────────────────
check_unnumbered_claims_restated() {
  local name="UNNUMBERED_CLAIMS_RESTATED"
  local f="$REPO_ROOT/internal/p2p/host_test.go"

  if [[ ! -f "$f" ]]; then
    fail "$name" "$f not found"
    return
  fi

  local missing=0
  if ! grep -q 'NFR-016' "$f"; then
    fail "$name" "NFR-016's demo-track restatement is missing from host_test.go — MVP §8.4, ADR-063 §3"
    missing=1
  fi
  if ! grep -qE 'NFR-006' "$f"; then
    fail "$name" "NFR-006's unmeasured-on-demo-track restatement is missing from host_test.go — MVP §8.4"
    missing=1
  fi

  if [[ "$missing" -eq 0 ]]; then
    pass "$name"
  fi
}

check_every_check_has_a_track_value
check_libp2p_dependent_tests_carry_restated_rationale
check_unnumbered_claims_restated

exit "$FAIL"
