// Package retrieve is declared in doc.go.
// This file implements parallel shard download (TASK step 2, FR-016), on
// the retrieval protocol ratified by ADR-080.
//
// [Resolved, M17 — history preserved for context] Until ADR-080, IC §4 had
// no ratified protocol for a data owner client to download its own shard:
// upload (§4.1) is write-only, audit (§4.2) returns only a proof, repair
// download (§4.4.1) authenticates the caller AS the microservice
// specifically, and vetting-gc (§4.5) is a deletion instruction. This file
// originally implemented two PROPOSED, NOT-YET-RATIFIED placeholders
// against that gap — a bare-chunk_id "knowledge of the hash is the
// capability" download protocol, and a provider-resolve endpoint — which
// were never built server-side and had never once executed successfully
// live. A Design Council session ("Data Owner File Retrieval", M17
// Session 17.2.1 live verification) considered both proposals and
// rejected the bare-chunk_id one: it is stable and identical across all
// 56 holders for a file's entire lifetime, which makes it unrevocable
// (breaks `rm`'s delete guarantee) and conflates an integrity identifier
// with an authorization secret. ADR-080 is the resulting decision, now
// implemented below.
//
// AUTHORIZATION (ADR-080 §1). Every shard fetch below carries a download
// capability token — the same 72-byte Ed25519-signed shape IC §4.1's
// upload capability_token already uses, with a distinct domain-separation
// prefix so the two can never be replayed as each other. The client never
// constructs or signs this token; it only forwards, verbatim, what
// resolveFileForRetrieval (below) received from the microservice.
//
// RESOLUTION (ADR-080 §2). resolveFileForRetrieval calls POST
// /api/v1/owner/files/{file_id}/retrieve/resolve ONCE for the entire file,
// not per segment — at prod parameters a 1 GB file is ~1,365 segments,
// and per-segment resolution would be over a thousand serial REST
// round-trips before any shard data moved.
//
// [REF: ADR-080, FR-016, IC §5.9 RetrieveFile, IC §4.1/4.2/4.4.1/4.5,
// MVP §8.2 Phase 15.3 Session 15.3.1]

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

// ── /vyomanaut/chunk-download/1.0.0 (ADR-080 §3, Accepted) ────────────────

const (
	chunkDownloadProtocolID = p2p.ProtocolID("/vyomanaut/chunk-download/1.0.0")
	chunkDownloadTimeout    = 10 * time.Second // mirrors repair-download's 10s (cold disk reads), IC §4.4.1

	downloadLengthPrefixSize = 4
	downloadChunkIDSize      = 32
	// downloadExpirySize/downloadCapSigSize/downloadFrame1PayloadBytes:
	// Frame 1 is chunk_id(32) || expiry_unix_ms(8) || cap_sig(64) = 104
	// bytes (ADR-080 §3) — every signed field transmitted, per the
	// REPAIR-AUTH-TS-GAP discipline cmd/provider/handler_repair.go's own
	// header explains. Must match
	// cmd/provider/handler_chunk_download.go's identical constants
	// exactly; a mismatch on either side is a wire break.
	downloadExpirySize         = 8
	downloadCapSigSize         = 64
	downloadFrame1PayloadBytes = downloadChunkIDSize + downloadExpirySize + downloadCapSigSize // 104

	// downloadTokenByteLen is the server-issued token's own length
	// (expiry_unix_ms(8) || cap_sig(64) = 72), the same 72-byte shape IC
	// §4.1's upload capability_token uses — chunk_id is NOT part of the
	// token itself; it travels separately in Frame 1 (and is already
	// known client-side from the pointer file), exactly mirroring how
	// upload's UploadRequest frame carries chunk_id and capability_token
	// as sibling fields rather than nesting one inside the other.
	downloadTokenByteLen = 72
)

// ChunkDownloadResponse status codes (ADR-080 §3, mirrors IC §4.4.1
// exactly). NOT_AUTHORISED IS present — unlike the earlier PROPOSED draft
// assumed, this protocol has a real authentication step (the download
// token), and ADR-080 §4 makes the status-code semantics deliberate: a
// token that fails to verify returns NOT_AUTHORISED regardless of whether
// the chunk is present, so an unauthenticated prober learns nothing about
// a provider's holder-set from the code alone.
const (
	downloadStatusOK            = 0x00
	downloadStatusNotFound      = 0x01
	downloadStatusNotAuthorised = 0x02
	downloadStatusCorruption    = 0x03
	downloadStatusInternalError = 0x04
)

// ── POST /api/v1/owner/files/{file_id}/retrieve/resolve (ADR-080 §2) ──────
//
// One call per file, not per segment: at prod parameters a 1 GB file is
// ~1,365 segments, and per-segment resolution would be ~1,365 serial REST
// round-trips before any shard data moves. The client already holds the
// full decrypted pointer file (and therefore every provider_id) before
// this is called, so there is no reason to resolve incrementally.

type retrieveResolveShardBody struct {
	ShardIndex     int       `json:"shard_index"`
	ProviderID     uuid.UUID `json:"provider_id"`
	ChunkID        string    `json:"chunk_id"`
	Multiaddrs     []string  `json:"multiaddrs"`
	MultiaddrStale bool      `json:"multiaddr_stale"`
	DownloadToken  string    `json:"download_token"`
}

type retrieveResolveSegmentBody struct {
	SegmentIndex int                        `json:"segment_index"`
	SegmentID    uuid.UUID                  `json:"segment_id"`
	Shards       []retrieveResolveShardBody `json:"shards"`
}

type retrieveResolveResponseBody struct {
	FileID   uuid.UUID                    `json:"file_id"`
	Segments []retrieveResolveSegmentBody `json:"segments"`
}

// resolvedShard is one shard's dial + authorization information, keyed by
// chunk_id_hex in the map resolveFileForRetrieval returns — chunk_id is a
// 256-bit content address (ADR-073), globally unique per shard, so it is
// sufficient as a map key on its own without also carrying segment/shard
// index.
type resolvedShard struct {
	multiaddrs     []string
	multiaddrStale bool
	downloadToken  string // hex, downloadTokenByteLen bytes when decoded
}

// resolveFileForRetrieval calls POST
// /api/v1/owner/files/{file_id}/retrieve/resolve ONCE for the whole file
// (ADR-080 §2) and returns every shard's resolution keyed by chunk_id_hex.
func (o *Orchestrator) resolveFileForRetrieval(ctx context.Context, fileID uuid.UUID) (map[string]resolvedShard, error) {
	var resp retrieveResolveResponseBody
	path := fmt.Sprintf("/api/v1/owner/files/%s/retrieve/resolve", fileID)
	httpResp, rawBody, err := o.api.doJSON(ctx, http.MethodPost, path, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("retrieve: resolveFileForRetrieval: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return nil, fmt.Errorf("retrieve: resolveFileForRetrieval: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return nil, fmt.Errorf("retrieve: resolveFileForRetrieval: unexpected status %d", httpResp.StatusCode)
	}

	out := make(map[string]resolvedShard)
	for _, seg := range resp.Segments {
		for _, shard := range seg.Shards {
			out[shard.ChunkID] = resolvedShard{
				multiaddrs:     shard.Multiaddrs,
				multiaddrStale: shard.MultiaddrStale,
				downloadToken:  shard.DownloadToken,
			}
		}
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
func (o *Orchestrator) downloadSegment(ctx context.Context, seg pointerFileSegment, resolved map[string]resolvedShard) ([][]byte, error) {
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
			chunkIDHex := seg.ChunkIDs[shardIdx]
			data, err := o.fetchOneShard(dlCtx, providerID, chunkIDHex, resolved[chunkIDHex])
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

// fetchOneShard resolves a peer, connects, opens the chunk-download
// stream, and verifies the shard's content address BEFORE returning it
// (TASK step 2: "before it is handed to RS decode").
func (o *Orchestrator) fetchOneShard(ctx context.Context, providerID uuid.UUID, chunkIDHex string, shard resolvedShard) ([]byte, error) {
	chunkIDBytes, err := hex.DecodeString(chunkIDHex)
	if err != nil || len(chunkIDBytes) != downloadChunkIDSize {
		return nil, fmt.Errorf("provider %s: malformed chunk_id", providerID)
	}
	var chunkID [32]byte
	copy(chunkID[:], chunkIDBytes)

	tokenBytes, err := hex.DecodeString(shard.downloadToken)
	if err != nil || len(tokenBytes) != downloadTokenByteLen {
		return nil, fmt.Errorf("provider %s: malformed download_token", providerID)
	}
	var expiryBytes [downloadExpirySize]byte
	copy(expiryBytes[:], tokenBytes[0:downloadExpirySize])
	var capSig [downloadCapSigSize]byte
	copy(capSig[:], tokenBytes[downloadExpirySize:downloadTokenByteLen])

	peerID, addrs, err := resolveDownloadPeer(providerID, shard.multiaddrs)
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

	if err := writeChunkDownloadRequest(stream, chunkID, expiryBytes, capSig); err != nil {
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

// writeChunkDownloadRequest writes Frame 1 — ChunkDownloadRequest
// (ADR-080 §3): length(4) || chunk_id(32) || expiry_unix_ms(8) ||
// cap_sig(64) = 104 bytes total. expiryBytes and capSig come directly
// from the server-issued download_token (fetchOneShard splits the
// 72-byte token into these two fields) — nothing is recomputed
// client-side; the client only ever forwards what the microservice signed.
func writeChunkDownloadRequest(s p2p.Stream, chunkID [32]byte, expiryBytes [downloadExpirySize]byte, capSig [downloadCapSigSize]byte) error {
	frame := make([]byte, downloadLengthPrefixSize+downloadFrame1PayloadBytes)
	binary.BigEndian.PutUint32(frame[0:downloadLengthPrefixSize], downloadFrame1PayloadBytes)
	offset := downloadLengthPrefixSize
	copy(frame[offset:offset+downloadChunkIDSize], chunkID[:])
	offset += downloadChunkIDSize
	copy(frame[offset:offset+downloadExpirySize], expiryBytes[:])
	offset += downloadExpirySize
	copy(frame[offset:offset+downloadCapSigSize], capSig[:])
	_, err := s.Write(frame)
	return err
}

// readChunkDownloadResponse reads Frame 2 — ChunkDownloadResponse
// (ADR-080 §3, mirrors IC §4.4.1): length(4) || status(1) ||
// chunk_data(present only
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
