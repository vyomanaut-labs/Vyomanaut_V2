// cmd/operator's HTTP client for the microservice's AdminApiKey-gated
// endpoints (OAS AdminApiKey security scheme). This is the ENTIRE authority
// this package has — I-DEMO-1 (ADR-084 §D-2a) forbids any database
// connection of its own, so every fact the CLI displays, in this session
// and in Sessions 17.6.2/17.6.3, arrives through doGet below.
//
// This file deliberately does NOT import internal/api. Every response
// shape below is a local mirror of the server's own OAS-defined wire
// contract — the same convention cmd/provider's onboard.go/earnings.go
// already establish, and for the identical reason given there: a real,
// independent exercise of the actual wire protocol, not a shared-code
// shortcut that could silently drift out of sync with the server on only
// one side.
//
// [REF: ADR-084 D-2a; internal/api/admin.go Session 17.6.1 (getFileShards);
// build_M17E.md Phase 17.6 Session 17.6.1]
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const operatorHTTPClientTimeout = 10 * time.Second

// maxErrorBodyBytes caps error-response bytes read for diagnostics, the
// same value and purpose as cmd/provider's own constant of the same name.
const maxErrorBodyBytes = 4096

// adminClient calls the microservice's AdminApiKey-gated endpoints. apiKey
// is sent as X-Admin-API-Key on every request — the header name and scheme
// router.go's adminAuthMiddleware enforces server-side.
type adminClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func newAdminClient(baseURL, apiKey string) *adminClient {
	return &adminClient{baseURL: baseURL, apiKey: apiKey, http: &http.Client{Timeout: operatorHTTPClientTimeout}}
}

// doPost performs an authenticated POST with a JSON-encoded body against
// path (relative to baseURL) and decodes the response body into out.
// `operator audit` (Session 17.6.3) is this file's first caller — every
// other subcommand so far has needed only doGet's GET.
func (c *adminClient) doPost(ctx context.Context, path string, body, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("X-Admin-API-Key", c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The audit-challenge endpoint's own success status is 202 Accepted
	// (internal/api/audit.go: "Phase 1" only, receipt arrives later, if
	// ever, over a dispatch path this milestone does not build) — doGet's
	// 200-only check does not fit this one caller, so this method accepts
	// 200 OR 202 as success, matching each endpoint's own documented
	// contract rather than picking one status for both.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return fmt.Errorf("%s returned HTTP %d: %s", path, resp.StatusCode, errBody)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// doGet performs an authenticated GET against path (relative to baseURL)
// and decodes a 200 JSON body into out. Every admin subcommand this
// package builds — shards now, audit/payout in Sessions 17.6.2/17.6.3 —
// shares this one call path, so a future session adding a POST variant is
// the only place this file would need to grow a sibling method.
func (c *adminClient) doGet(ctx context.Context, path string, out any) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("X-Admin-API-Key", c.apiKey)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return fmt.Errorf("%s returned HTTP %d: %s", path, resp.StatusCode, errBody)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// ── GET /api/v1/admin/file/{file_id}/shards (ADR-084 §D-2a) ─────────────
// Local mirrors of internal/api/admin.go's adminFileShardsResponseBody /
// adminFileShardItem (Session 17.6.1) — see this file's header note on why
// this package keeps its own copy rather than importing internal/api.

type shardsAdminChunkItem struct {
	ChunkID    string `json:"chunk_id"`
	SegmentID  string `json:"segment_id"`
	ShardIndex int    `json:"shard_index"`
	ProviderID string `json:"provider_id"`
	ASN        string `json:"asn"`
	SizeBytes  int    `json:"size_bytes"`
}

// shardsAdminResponseBody's DisplayNameCiphertext mirrors the server's own
// hex-encoded string field exactly — never decoded, never will be by this
// package (ADR-020; I-DEMO-1).
type shardsAdminResponseBody struct {
	FileID                string                 `json:"file_id"`
	OriginalSizeBytes     int64                  `json:"original_size_bytes"`
	DisplayNameCiphertext *string                `json:"display_name_ciphertext,omitempty"`
	Shards                []shardsAdminChunkItem `json:"shards"`
}

// fetchFileShards calls GET /api/v1/admin/file/{file_id}/shards.
func (c *adminClient) fetchFileShards(ctx context.Context, fileID string) (shardsAdminResponseBody, error) {
	var resp shardsAdminResponseBody
	if err := c.doGet(ctx, "/api/v1/admin/file/"+fileID+"/shards", &resp); err != nil {
		return shardsAdminResponseBody{}, err
	}
	return resp, nil
}

// ── POST /api/v1/audit/challenge (Session 17.6.3, requirement 9) ────────
// Local mirror of internal/api/audit.go's auditChallengeDispatchRequestBody
// / auditChallengeDispatchResponseBody. This endpoint's own scope note
// (audit.go's file header) is load-bearing for what this package can
// honestly render: it authorises the request, writes a PENDING
// audit_receipts row, and returns 202 with only the nonce/timestamp/
// deadline — no network dispatch to the provider and no receipt
// adjudication exist anywhere in this codebase yet, so "the provider's
// response status" this session's task text names is, truthfully, always
// PENDING right after a fresh dispatch; there is no live source for
// anything past that (no signed receipt to show) until a later milestone
// builds the dispatch/adjudication path. auditRenderStatus below is the
// flagged-not-fabricated label this package shows instead of inventing one.

type auditChallengeRequestBody struct {
	ProviderID string `json:"provider_id"`
	ChunkID    string `json:"chunk_id"`
}

type auditChallengeResponseBody struct {
	ChallengeNonce    string    `json:"challenge_nonce"`
	ServerChallengeTS time.Time `json:"server_challenge_ts"`
	DeadlineMs        int64     `json:"deadline_ms"`
}

// dispatchAuditChallenge calls POST /api/v1/audit/challenge.
func (c *adminClient) dispatchAuditChallenge(ctx context.Context, providerID, chunkID string) (auditChallengeResponseBody, error) {
	var resp auditChallengeResponseBody
	req := auditChallengeRequestBody{ProviderID: providerID, ChunkID: chunkID}
	if err := c.doPost(ctx, "/api/v1/audit/challenge", req, &resp); err != nil {
		return auditChallengeResponseBody{}, err
	}
	return resp, nil
}

// ── GET /api/v1/admin/payout/preview (Session 17.6.3, ADR-084 addendum A) ─
// Local mirror of internal/api/admin.go's adminPayoutPreviewResponseBody /
// adminPayoutPreviewProviderItem. ReleasePaise*10000 + RemainderBP always
// equals BalancePaise*MultiplierBP exactly — see that file's own doc
// comment on the reconciliation identity this mirrors.

type payoutPreviewProviderItem struct {
	ProviderID   string `json:"provider_id"`
	BalancePaise int64  `json:"balance_paise"`
	MultiplierBP int64  `json:"multiplier_bp"`
	ReleasePaise int64  `json:"release_paise"`
	RemainderBP  int64  `json:"remainder_bp"`
	ScoreStale   bool   `json:"score_stale"`
}

type payoutPreviewResponseBody struct {
	BillingPeriod string                      `json:"billing_period"`
	Providers     []payoutPreviewProviderItem `json:"providers"`
}

// fetchPayoutPreview calls GET /api/v1/admin/payout/preview.
func (c *adminClient) fetchPayoutPreview(ctx context.Context) (payoutPreviewResponseBody, error) {
	var resp payoutPreviewResponseBody
	if err := c.doGet(ctx, "/api/v1/admin/payout/preview", &resp); err != nil {
		return payoutPreviewResponseBody{}, err
	}
	return resp, nil
}
