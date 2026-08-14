// cmd/microservice — see main.go's package doc comment.
//
// This file implements regenerateProviderScoresView (this session's step 5,
// MVP §5.5): mv_provider_scores is DROPPED and RECREATED at every
// microservice startup using profile.ScoreWindow{Short,Medium,Long} in place
// of migrations/001_initial_schema.sql's hardcoded '24 hours' / '7 days' /
// '30 days' interval literals — an application-layer step, not a migration
// (MVP §5.5's own framing).
//
// The view text below is copied from the migration verbatim except for
// those three interval substitutions, so the JIT-penalty logic (ARCH §20,
// DM §7) and score-composite weighting stay byte-for-byte identical to what
// Milestone 4's migration already defines and Milestone 7/8's audit/scoring
// packages already depend on.
//
// [Decision] ARCH §20's JIT penalty is framed as "did a qualifying 7-day
// window occur at any point in the last 30 days" — no NetworkProfile field
// is dedicated to this lookback independently of the score windows
// themselves, so this file maps it onto the two windows that already exist
// for that purpose: the JIT streak's inner sub-window uses
// profile.ScoreWindowMedium (7 days in production, matching the migration's
// hardcoded '7 days'), and its outer lookback uses profile.ScoreWindowLong
// (30 days in production, matching '30 days'). This keeps demo mode's
// already-compressed windows (6 min / 20 min) consistent with production's
// relative proportions, rather than leaving the JIT lookback at real-world
// day-scale durations while every other window compresses to minutes.
//
// [REF: MVP §5.5, DM §7, ARCH §20, build.md Milestone 12 Phase 12.1
// Session 12.1.1]
package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// providerScoresViewTemplate mirrors migrations/001_initial_schema.sql's
// mv_provider_scores definition exactly, except that every hardcoded
// interval literal is replaced with an explicit %[n]s positional verb:
// %[1]s = ScoreWindowShort (was '24 hours', 2 occurrences),
// %[2]s = ScoreWindowMedium (was '7 days', 3 occurrences: the JIT CTE's
// correlated sub-window plus pass_7d/total_7d), %[3]s = ScoreWindowLong (was
// '30 days', 3 occurrences: the JIT CTE's outer filter plus
// pass_30d/total_30d).
// [Bug fix, post-Phase-12.1] DROP MATERIALIZED VIEW followed by CREATE
// produces a brand-new database object with a new OID — it does NOT
// inherit the original migration's "GRANT SELECT ON mv_provider_scores TO
// vyomanaut_app" (migrations/001_initial_schema.sql), because that GRANT
// was bound to the object CREATE MATERIALIZED VIEW made at migration time,
// not to the view's name. Without reissuing it, the first call to this
// function against any given database (this session's own
// TestRegenerateProviderScoresView included) silently revokes every
// vyomanaut_app-authenticated query's ability to read scores at all —
// scoring.GetScore, scoring.GetScoreFromPrimary,
// repair.SelectReplacementProvider, and every HTTP handler that calls them,
// all failing with "pq: permission denied for materialized view
// mv_provider_scores (42501)". Caught in CI and reproduced locally: this
// showed up across internal/api, internal/payment, internal/repair, and
// internal/scoring immediately after cmd/microservice's own test suite ran
// (and silently stripped the grant) against a database CI's
// `go test -p 1 ./...` shares across every package, in alphabetical package
// order — cmd/ always runs, and always struck the grant, before any
// internal/* package's tests did. providerScoresViewTemplate's final
// statement now reissues it every time.
const providerScoresViewTemplate = `
CREATE MATERIALIZED VIEW mv_provider_scores AS
WITH jit_penalized AS (
    SELECT DISTINCT ar.provider_id
    FROM audit_receipts ar
    WHERE ar.jit_flag = TRUE
      AND ar.abandoned_at IS NULL
      AND ar.server_challenge_ts >= NOW() - %[3]s::interval
      AND (
          SELECT COUNT(*)
          FROM audit_receipts ar2
          WHERE ar2.provider_id = ar.provider_id
            AND ar2.jit_flag = TRUE
            AND ar2.abandoned_at IS NULL
            AND ar2.server_challenge_ts BETWEEN ar.server_challenge_ts - %[2]s::interval AND ar.server_challenge_ts
      ) >= 3
)
SELECT
    provider_id,
    score_24h,
    score_7d,
    score_30d,
    (
        COALESCE(score_24h, 0) * 0.5 +
        COALESCE(score_7d,  0) * 0.3 +
        COALESCE(score_30d, 0) * 0.2
    ) AS score_composite,
    NOW() AS scores_as_of
FROM (
    SELECT
        sub.provider_id,
        (sub.pass_24h * (CASE WHEN jp.provider_id IS NOT NULL THEN 0.5 ELSE 1.0 END))
        / NULLIF(sub.total_24h, 0)
        AS score_24h,
        sub.pass_7d::FLOAT / NULLIF(sub.total_7d, 0) AS score_7d,
        sub.pass_30d::FLOAT / NULLIF(sub.total_30d, 0) AS score_30d
    FROM (
        SELECT
            provider_id,
            SUM(CASE WHEN server_challenge_ts >= NOW() - %[1]s::interval
                    AND audit_result = 'PASS' THEN 1 ELSE 0 END) AS pass_24h,
            SUM(CASE WHEN server_challenge_ts >= NOW() - %[1]s::interval
                    AND audit_result IS NOT NULL THEN 1 ELSE 0 END) AS total_24h,
            SUM(CASE WHEN server_challenge_ts >= NOW() - %[2]s::interval
                    AND audit_result = 'PASS' THEN 1 ELSE 0 END) AS pass_7d,
            SUM(CASE WHEN server_challenge_ts >= NOW() - %[2]s::interval
                    AND audit_result IS NOT NULL THEN 1 ELSE 0 END) AS total_7d,
            SUM(CASE WHEN server_challenge_ts >= NOW() - %[3]s::interval
                    AND audit_result = 'PASS' THEN 1 ELSE 0 END) AS pass_30d,
            SUM(CASE WHEN server_challenge_ts >= NOW() - %[3]s::interval
                    AND audit_result IS NOT NULL THEN 1 ELSE 0 END) AS total_30d
        FROM audit_receipts
        WHERE abandoned_at IS NULL
        GROUP BY provider_id
    ) sub
    LEFT JOIN jit_penalized jp ON jp.provider_id = sub.provider_id
) scores;

CREATE UNIQUE INDEX ON mv_provider_scores (provider_id);

-- [Bug fix, post-Phase-12.1 — see this file's header note] Reissue the
-- grant DROP+CREATE just silently destroyed.
GRANT SELECT ON mv_provider_scores TO vyomanaut_app;
`

// intervalLiteral formats d as a Postgres interval literal string, e.g.
// "'86400.000000 seconds'" — the same "%f seconds" pattern already used by
// internal/repair's own interval-formatting call sites (departure.go,
// queue.go), quoted here since it is substituted directly into SQL text
// rather than passed as a placeholder argument.
func intervalLiteral(d time.Duration) string {
	return fmt.Sprintf("'%f seconds'", d.Seconds())
}

// regenerateProviderScoresView implements this session's step 5 (MVP §5.5):
// drop and recreate mv_provider_scores using the active profile's scoring
// windows. Safe to call on every startup — CREATE MATERIALIZED VIEW is not
// incremental; this always fully rebuilds it from audit_receipts.
func regenerateProviderScoresView(ctx context.Context, db *sql.DB, profile config.NetworkProfile) error {
	if _, err := db.ExecContext(ctx, `DROP MATERIALIZED VIEW IF EXISTS mv_provider_scores`); err != nil {
		return fmt.Errorf("regenerateProviderScoresView: drop: %w", err)
	}
	stmt := fmt.Sprintf(providerScoresViewTemplate,
		intervalLiteral(profile.ScoreWindowShort),
		intervalLiteral(profile.ScoreWindowMedium),
		intervalLiteral(profile.ScoreWindowLong),
	)
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("regenerateProviderScoresView: create: %w", err)
	}
	return nil
}
