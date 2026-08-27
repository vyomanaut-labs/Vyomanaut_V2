// Package main — `operator audit <provider_id> <chunk_id>` (M17-E Session
// 17.6.3, requirement 9: "on demand, in front of an audience").
//
// [Engineering Review] The session task text names this command
// `operator audit <provider_id>`, but POST /api/v1/audit/challenge's own
// request body (internal/api/audit.go's auditChallengeDispatchRequestBody)
// requires BOTH provider_id and chunk_id — there is no admin endpoint that
// enumerates "the chunks this provider holds" for this command to resolve
// a chunk_id on its own (I-DEMO-1 forbids a database lookup to find one),
// and `operator shards <file_id>` already gives an operator the exact
// chunk_id/provider_id pairs to challenge. This command therefore takes
// both as positional arguments; the task text's single argument is read as
// shorthand for "identify which provider" rather than a literal one-arg
// CLI contract the underlying wire protocol cannot satisfy.
//
// [Flagged, not fabricated] internal/api/audit.go's own file header states
// the endpoint's scope precisely: it writes a PENDING audit_receipts row
// and returns 202 with only challenge_nonce/server_challenge_ts/
// deadline_ms. No network dispatch to the provider and no receipt
// adjudication exist anywhere in this codebase yet (that file's own words:
// "a later milestone"). So "the provider's response status, and the signed
// receipt" this session's task text asks to print do not have a live data
// source beyond the one true fact this endpoint's response really
// contains: the receipt was just written and its status is PENDING. This
// command renders exactly that, labelled honestly, rather than inventing a
// response status or receipt this milestone cannot produce — the same
// judgment call already established at auditStatsHandler's
// content_hash_failures and providerStatusResponseBody's
// held_earnings_paise (internal/api/admin.go, internal/api/provider.go).
//
// [REF: FR-037, ADR-002, ADR-006, ADR-084 requirement 9; internal/api/audit.go
// Session 11.9.1; build_M17E.md Phase 17.6 Session 17.6.3]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
)

const auditArgCount = 2

// auditReceiptStatusPending is the one truthful status this command can
// ever render: a freshly-dispatched challenge's audit_receipts row is
// always PENDING (audit.WriteReceiptPhase1), and this codebase has no path
// — yet — for that row to ever be observed transitioning past PENDING from
// an admin-key caller with no database of its own.
const auditReceiptStatusPending = "PENDING"

func dispatchAudit(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("operator audit", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	g.adminAPIKey = resolveAdminAPIKey(g.adminAPIKey)
	if err := validateGlobalFlags(g); err != nil {
		fprintln(errOut, err)
		return exitUsage
	}

	rest := fs.Args()
	if len(rest) != auditArgCount {
		fprintln(errOut, "usage: operator audit <provider_id> <chunk_id> [flags]")
		return exitUsage
	}
	providerID, chunkID := rest[0], rest[1]

	client := newAdminClient(g.microserviceURL, g.adminAPIKey)
	resp, err := client.dispatchAuditChallenge(context.Background(), providerID, chunkID)
	if err != nil {
		fprintf(errOut, "vyomanaut operator audit: %v\n", err)
		return 1
	}

	renderAuditChallenge(out, providerID, chunkID, resp, g.json)
	return 0
}

// auditRenderResult is the shape --json emits — a superset of the wire
// response with the provider_id/chunk_id echoed back (the wire response
// carries neither) and the honest, flagged status/receipt fields the
// header comment above explains.
type auditRenderResult struct {
	ProviderID        string `json:"provider_id"`
	ChunkID           string `json:"chunk_id"`
	ChallengeNonce    string `json:"challenge_nonce"`
	ServerChallengeTS string `json:"server_challenge_ts"`
	DeadlineMs        int64  `json:"deadline_ms"`
	ResponseStatus    string `json:"response_status"`
	SignedReceipt     string `json:"signed_receipt"`
}

func renderAuditChallenge(out io.Writer, providerID, chunkID string, resp auditChallengeResponseBody, jsonOutput bool) {
	result := auditRenderResult{
		ProviderID:        providerID,
		ChunkID:           chunkID,
		ChallengeNonce:    resp.ChallengeNonce,
		ServerChallengeTS: resp.ServerChallengeTS.Format(rfc3339Milli),
		DeadlineMs:        resp.DeadlineMs,
		ResponseStatus:    auditReceiptStatusPending,
		SignedReceipt:     "",
	}

	if jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}

	fprintf(out, "Audit challenge dispatched\n")
	fprintf(out, "  provider:        %s\n", providerID)
	fprintf(out, "  chunk:           %s\n", chunkID)
	fprintf(out, "  challenge nonce: %s\n", result.ChallengeNonce)
	fprintf(out, "  dispatched at:   %s\n", result.ServerChallengeTS)
	fprintf(out, "  deadline:        %dms\n", result.DeadlineMs)
	fprintf(out, "  response status: %s\n", result.ResponseStatus)
	fprintln(out, "  signed receipt:  (not available — challenge/response network dispatch is not implemented in this milestone; see internal/api/audit.go)")
}

const rfc3339Milli = "2006-01-02T15:04:05.000Z07:00"
