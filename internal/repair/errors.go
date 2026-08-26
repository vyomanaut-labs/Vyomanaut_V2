// Package repair is declared in doc.go.
// This file defines all sentinel errors exported by the repair package.
// Callers must compare using errors.Is; never construct these values inline.
// This is the single accumulating home for every sentinel error the repair
// package exports across Milestone 9 (mirrors internal/audit/errors.go and
// internal/scoring/errors.go's accumulating pattern) — later sessions append
// further sentinels here.
//
// [REF: IC §5.7]

package repair

import "errors"

var (
	// ErrShardCountOutOfRange is returned by EnqueueJob when availableShardCount
	// falls outside [profile.DataShards, profile.TotalShards] (DM §4.10).
	ErrShardCountOutOfRange = errors.New("repair: availableShardCount outside [DataShards, TotalShards] for active profile")

	// [Removed, M9 review Finding #5 — cleanup] ErrJobQueueEmpty was declared
	// but never returned anywhere: DequeueNextJob correctly returns (nil, nil)
	// for an empty queue per IC §5.7 — a nil job with no error is the
	// documented "nothing to do right now" signal, not an error condition a
	// caller should retry-with-backoff on. The sentinel's own doc comment
	// claimed it WAS DequeueNextJob's empty-queue signal, which was simply
	// wrong. Removed rather than wired up, since (nil, nil) is the correct
	// contract and introducing a second, unused error path would only invite
	// a future caller to check for the wrong thing.

	// ErrNoEligibleReplacement is returned by SelectReplacementProvider when
	// every candidate drawn within the bounded retry budget would violate the
	// 20% ASN cap (FR-045, ADR-014).
	ErrNoEligibleReplacement = errors.New("repair: no ASN-cap-eligible replacement provider found after bounded retries")

	// ErrReplacementStorageFull is returned (wrapped) by uploadShard when the replacement provider
	// responds with IC §4.1 status 0x04 (STORAGE_FULL). [Added, M9 review
	// Optional Fix A] ExecuteRepairJob catches this specifically to free
	// the claimed assignment slot and retry against a different candidate,
	// bounded by maxRepairReplacementRetries — the same self-healing
	// treatment SelectReplacementProvider already gives an ASN-cap loser,
	// extended to a single unlucky capacity draw.
	ErrReplacementStorageFull = errors.New("repair: replacement provider reported storage full (IC §4.1 status 0x04)")

	// [Added, design council verdict on TestReplacementProviderDepartsMidRepair]
	// ErrReplacementUnreachable is returned (wrapped) by uploadShard when the
	// candidate could not be reached at all — stream open, write, or
	// response-read failure, i.e. anything before a wire status byte is ever
	// read. Deliberately distinct from a wire-level status code: this
	// sentinel means the candidate was never actually asked, so retrying
	// against a *different* candidate risks nothing about the shard data
	// itself, exactly like ErrReplacementStorageFull. A wire-level status
	// code other than STORAGE_FULL is NOT wrapped in this sentinel and
	// remains a hard failure — that response was actually considered by the
	// candidate, and blind retry there could mask a genuine data- or
	// encode-side bug rather than a simple unreachable-candidate case. Live
	// evidence: TestReplacementProviderDepartsMidRepair killed the chosen
	// replacement mid-transfer; the resulting "connection reset by peer" at
	// stream-open was, before this fix, indistinguishable from any other
	// upload error and failed the job permanently with no retry. Bounded by
	// the same maxRepairReplacementRetries as ErrReplacementStorageFull —
	// this narrows the window this specific failure mode leaves open, it
	// does not close it: exhausting all bounded retries is still a terminal
	// FAILED job, and no periodic mechanism yet re-examines a chunk that
	// ends up there. That residual gap is tracked as an open LTS research
	// question, not silently accepted — see Vyomanaut_Research's finding on
	// this session's design council verdict.
	ErrReplacementUnreachable = errors.New("repair: replacement provider unreachable (connection failed before a wire response was read)")
)
