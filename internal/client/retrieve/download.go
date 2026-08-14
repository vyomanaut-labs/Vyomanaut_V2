// Package retrieve is declared in doc.go.
// This file implements parallel shard download (TASK step 2, FR-016).
//
// ⚠ [MAJOR FLAG — genuine architecture gap, not an implementation detail]
// There is no documented, ratified protocol anywhere in IC §4 for a DATA
// OWNER CLIENT to download its own shard from a provider daemon:
//   - IC §4.1 (chunk-upload) is write-only.
//   - IC §4.2 (audit-challenge) returns only a response_hash proof, never
//     raw chunk data.
//   - IC §4.4.1 (repair-download) explicitly authenticates the caller as
//     THE MICROSERVICE specifically ("the provider daemon must verify that
//     the requesting Peer ID is registered as a microservice replica...
//     requests from unregistered Peer IDs are rejected immediately with
//     status 0x02 NOT_AUTHORISED") — a data-owner client's Peer ID is not,
//     and must not be, on that list.
//   - IC §4.5 (vetting-gc) is a deletion instruction, not a data path.
// Separately, pointerFileSegment (pointer.go) only carries provider_id +
// chunk_id — never multiaddrs, correctly so, since multiaddrs stored once
// at upload time would go stale by retrieval time. No OAS endpoint resolves
// provider_id → current multiaddrs for a client either:
// GET /api/v1/provider/{provider_id}/status requires the caller's own JWT
// `sub` to match the target provider_id (a provider's own self-status
// call), and its response schema has no multiaddr field regardless.
//
// FR-016 and IC §5.9's RetrieveFile are both real, intended requirements —
// this is a genuine hole between "requirements level" and "protocol/API
// level" for retrieval specifically, not something resolvable by a locally
// scoped interpretation the way (for example) the AONT-overhead padding
// math in the upload package was. This is exactly the class of "BUILD
// BLOCKER that doesn't resolve from IC/DM/ARCH alone" the project's own
// design-council process exists for — recommended before either proposal
// below is treated as anything more than a placeholder to unblock this
// session mechanically.
//
// Two PROPOSED, NOT YET RATIFIED additions are implemented below purely so
// this session has something concrete and testable to build and verify
// against:
//  1. POST /api/v1/providers/resolve — resolveProviderAddresses below —
//     mirrors the shape ShardAssignment.multiaddrs already uses elsewhere
//     in the OAS, minimally extended to arbitrary provider_ids.
//  2. /vyomanaut/chunk-download/1.0.0 — a new libp2p protocol, deliberately
//     as close to the existing repair-download frame shape (IC §4.4.1) as
//     the different (no microservice-only) auth model allows: a bare
//     chunk_id request, relying on content-addressing itself as the access
//     gate (an owner needs the pointer file's chunk_ids to ask at all) —
//     the same "knowledge of the hash is the capability" model several
//     real content-addressed P2P storage systems already use. This is a
//     genuine security-relevant decision, not a detail, and belongs in
//     front of the design council, not decided unilaterally here.
//
// [REF: FR-016, IC §5.9 RetrieveFile, IC §4.1/4.2/4.4.1/4.5 (for what does
// NOT apply here), MVP §8.2 Phase 15.3 Session 15.3.1]

package retrieve

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// ── PROPOSED: /vyomanaut/chunk-download/1.0.0 (NOT ratified) ──────────────

const (
	chunkDownloadProtocolID = p2p.ProtocolID("/vyomanaut/chunk-download/1.0.0") // PROPOSED
	chunkDownloadTimeout    = 10 * time.Second                                  // mirrors repair-download's 10s (cold disk reads), IC §4.4.1

	downloadLengthPrefixSize = 4
	downloadChunkIDSize      = 32
)

// ChunkDownloadResponse status codes (PROPOSED — mirrors repair-download's
// status shape, IC §4.4.1, minus NOT_AUTHORISED since this protocol has no
// authentication step to fail).
const (
	downloadStatusOK            = 0x00
	downloadStatusNotFound      = 0x01
	downloadStatusCorruption    = 0x02
	downloadStatusInternalError = 0x03
)

// ── PROPOSED: POST /api/v1/providers/resolve (NOT ratified) ───────────────

type resolveProvidersRequest struct {
	ProviderIDs []uuid.UUID `json:"provider_ids"`
}

type providerAddress struct {
	ProviderID uuid.UUID `json:"provider_id"`
	Multiaddrs []string  `json:"multiaddrs"`
}

type resolveProvidersResponse struct {
	Providers []providerAddress `json:"providers"`
}

// resolveProviderAddresses calls the PROPOSED POST /api/v1/providers/resolve
// endpoint (see this file's header comment) to map provider_id → current
// multiaddrs for a batch of providers.
func (o *Orchestrator) resolveProviderAddresses(ctx context.Context, providerIDs []uuid.UUID) (map[uuid.UUID][]string, error) {
	var resp resolveProvidersResponse
	httpResp, rawBody, err := o.api.doJSON(ctx, http.MethodPost, "/api/v1/providers/resolve", resolveProvidersRequest{ProviderIDs: providerIDs}, &resp)
	if err != nil {
		return nil, fmt.Errorf("retrieve: resolveProviderAddresses: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return nil, fmt.Errorf("retrieve: resolveProviderAddresses: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return nil, fmt.Errorf("retrieve: resolveProviderAddresses: unexpected status %d", httpResp.StatusCode)
	}
	out := make(map[uuid.UUID][]string, len(resp.Providers))
	for _, p := range resp.Providers {
		out[p.ProviderID] = p.Multiaddrs
	}
	return out, nil
}

// ── Parallel dial-cancel-at-k download (FR-016) ────────────────────────────

type shardFetchResult struct {
	shardIndex int
	data       []byte
}

// downloadSegment dials every provider in seg.ProviderIDs in parallel and
// returns the first profile.DataShards shards whose content address
// verifies (TASK step 2), cancelling the remaining in-flight dials once
// that threshold is reached (FR-016's "fastest-responding, cancel-on-k"
// pattern — never hardcoded to 16; demo mode cancels at
// config.DemoProfile.DataShards = 3). Returns ErrTooFewShards if fewer than
// profile.DataShards succeed once every dial has settled.
func (o *Orchestrator) downloadSegment(ctx context.Context, seg pointerFileSegment) ([][]byte, error) {
	addrsByProvider, err := o.resolveProviderAddresses(ctx, seg.ProviderIDs)
	if err != nil {
		return nil, fmt.Errorf("downloadSegment: %w", err)
	}

	need := o.profile.DataShards
	dlCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan shardFetchResult, len(seg.ProviderIDs))
	var wg sync.WaitGroup
	for shardIdx := range seg.ProviderIDs {
		wg.Add(1)
		go func(shardIdx int) {
			defer wg.Done()
			providerID := seg.ProviderIDs[shardIdx]
			data, err := o.fetchOneShard(dlCtx, providerID, addrsByProvider[providerID], seg.ChunkIDs[shardIdx])
			if err != nil {
				return // dropped: downloadSegment only needs `need` successes total
			}
			select {
			case results <- shardFetchResult{shardIndex: shardIdx, data: data}:
			case <-dlCtx.Done():
			}
		}(shardIdx)
	}
	go func() { wg.Wait(); close(results) }()

	shards := make([][]byte, len(seg.ProviderIDs))
	got := 0
	for r := range results {
		if shards[r.shardIndex] == nil {
			shards[r.shardIndex] = r.data
			got++
		}
		if got >= need {
			cancel() // FR-016: cancel remaining dials once k = profile.DataShards responses received
			break
		}
	}
	// Drain any further sends so goroutines still selecting on
	// `results <- ...` after cancel() don't block forever waiting for a
	// receiver — each one also selects on dlCtx.Done(), so this drain plus
	// the cancellation together guarantee every goroutine can exit.
	go func() {
		for range results {
		}
	}()

	if got < need {
		return nil, fmt.Errorf("downloadSegment: only %d of %d required shards retrieved: %w", got, need, ErrTooFewShards)
	}
	return shards, nil
}

// fetchOneShard resolves a peer, connects, opens the PROPOSED
// chunk-download stream, and verifies the shard's content address BEFORE
// returning it (TASK step 2: "before it is handed to RS decode").
func (o *Orchestrator) fetchOneShard(ctx context.Context, providerID uuid.UUID, multiaddrs []string, chunkIDHex string) ([]byte, error) {
	chunkIDBytes, err := hex.DecodeString(chunkIDHex)
	if err != nil || len(chunkIDBytes) != downloadChunkIDSize {
		return nil, fmt.Errorf("provider %s: malformed chunk_id", providerID)
	}
	var chunkID [32]byte
	copy(chunkID[:], chunkIDBytes)

	peerID, addrs, err := resolveDownloadPeer(providerID, multiaddrs)
	if err != nil {
		return nil, fmt.Errorf("provider %s: %w", providerID, err)
	}
	if err := o.host.Connect(ctx, peerID, addrs); err != nil {
		return nil, fmt.Errorf("provider %s: connect: %w", providerID, err)
	}
	stream, err := o.host.NewStream(ctx, peerID, chunkDownloadProtocolID)
	if err != nil {
		return nil, fmt.Errorf("provider %s: open chunk-download stream: %w", providerID, err)
	}
	defer func() { _ = stream.Close() }()
	if err := stream.SetDeadline(time.Now().Add(chunkDownloadTimeout)); err != nil {
		return nil, fmt.Errorf("provider %s: set deadline: %w", providerID, err)
	}

	if err := writeChunkDownloadRequest(stream, chunkID); err != nil {
		return nil, fmt.Errorf("provider %s: %w", providerID, err)
	}
	status, data, err := readChunkDownloadResponse(stream)
	if err != nil {
		return nil, fmt.Errorf("provider %s: %w", providerID, err)
	}
	if status != downloadStatusOK {
		return nil, fmt.Errorf("provider %s: status 0x%02x", providerID, status)
	}

	// TASK step 2: verify content address before handing to RS decode.
	if sha256.Sum256(data) != chunkID {
		return nil, fmt.Errorf("provider %s: content address mismatch (SHA-256(shard_data) != chunk_id)", providerID)
	}
	return data, nil
}

// resolveDownloadPeer extracts a dialable p2p.PeerID + []p2p.Multiaddr from
// a resolved provider's multiaddrs. A package-local twin of
// internal/client/upload/transfer.go's resolveShardPeer (Session 15.2.1) —
// see that file's header comment for why internal/p2p's ParseMultiaddr
// silently drops the trailing /p2p/<PeerID> segment the OAS's own Multiaddr
// example shows, requiring this file to extract it independently.
func resolveDownloadPeer(providerID uuid.UUID, multiaddrs []string) (p2p.PeerID, []p2p.Multiaddr, error) {
	if len(multiaddrs) == 0 {
		return "", nil, fmt.Errorf("no multiaddrs resolved")
	}
	var (
		peerID p2p.PeerID
		addrs  []p2p.Multiaddr
	)
	for _, raw := range multiaddrs {
		addr, err := p2p.ParseMultiaddr(raw)
		if err != nil {
			continue
		}
		addrs = append(addrs, addr)
		if peerID == "" {
			if id, ok := extractPeerIDFromMultiaddr(raw); ok {
				peerID = id
			}
		}
	}
	if len(addrs) == 0 {
		return "", nil, fmt.Errorf("no parseable multiaddrs among %d resolved", len(multiaddrs))
	}
	if peerID == "" {
		return "", nil, fmt.Errorf("no /p2p/<PeerID> segment found in any resolved multiaddr")
	}
	return peerID, addrs, nil
}

func extractPeerIDFromMultiaddr(raw string) (p2p.PeerID, bool) {
	const marker = "/p2p/"
	idx := strings.LastIndex(raw, marker)
	if idx == -1 {
		return "", false
	}
	id := strings.Trim(raw[idx+len(marker):], "/")
	if id == "" {
		return "", false
	}
	return p2p.PeerID(id), true
}

// writeChunkDownloadRequest writes the PROPOSED Frame 1 —
// ChunkDownloadRequest: length(4) || chunk_id(32).
func writeChunkDownloadRequest(s p2p.Stream, chunkID [32]byte) error {
	frame := make([]byte, downloadLengthPrefixSize+downloadChunkIDSize)
	binary.BigEndian.PutUint32(frame[0:downloadLengthPrefixSize], downloadChunkIDSize)
	copy(frame[downloadLengthPrefixSize:], chunkID[:])
	_, err := s.Write(frame)
	return err
}

// readChunkDownloadResponse reads the PROPOSED Frame 2 —
// ChunkDownloadResponse: length(4) || status(1) || chunk_data(present only
// on status = 0x00).
func readChunkDownloadResponse(s p2p.Stream) (status byte, data []byte, err error) {
	var lengthBuf [downloadLengthPrefixSize]byte
	if _, err := io.ReadFull(s, lengthBuf[:]); err != nil {
		return 0, nil, fmt.Errorf("read ChunkDownloadResponse length: %w", err)
	}
	length := binary.BigEndian.Uint32(lengthBuf[:])
	body := make([]byte, length)
	if _, err := io.ReadFull(s, body); err != nil {
		return 0, nil, fmt.Errorf("read ChunkDownloadResponse body: %w", err)
	}
	if len(body) < 1 {
		return 0, nil, fmt.Errorf("ChunkDownloadResponse: empty body")
	}
	status = body[0]
	if status == downloadStatusOK {
		data = body[1:]
	}
	return status, data, nil
}
