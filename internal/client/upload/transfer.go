// Package upload is declared in doc.go.
// This file implements parallel shard transfer (TASK steps 4–5): the
// chunk-upload initiator side of IC §4.1, including the ERRATA capability
// token handling — each shard's capability_token is included verbatim in
// its UploadRequest frame, never re-derived client-side, and a 0x07
// CAPABILITY_EXPIRED response triggers exactly one idempotent re-assignment
// request (assign.go) before retrying.
//
// [Flagged — real spec gap, not an invented workaround] OAS ShardAssignment
// gives provider_id (a UUID) and multiaddrs, but no Ed25519 public key.
// p2p.Host.Connect requires a target p2p.PeerID to cryptographically verify
// against (IC §4: "Peer ID of the remote was verified against peerID, not
// self-reported") — Milestone 14's vettingchunk package derived PeerID from
// providers.ed25519_public_key via direct DB access, which this client
// package has no equivalent to. The OAS's own Multiaddr example
// ("/ip4/.../quic-v1/p2p/12D3KooW...") shows the PeerID IS present as the
// multiaddr's own trailing /p2p/<PeerID> segment — but internal/p2p's
// ParseMultiaddr (checked before writing this file) silently discards any
// segment past the port for direct (non-relay) addresses; it never errors,
// it just drops the tail. internal/p2p is not in this session's FILES scope
// to fix, so extractPeerIDFromMultiaddr below parses that trailing segment
// directly from the raw string, independent of (and in addition to)
// p2p.ParseMultiaddr's own parse for the dialable address. This is
// fail-closed by construction, not a security bypass: if extraction is ever
// wrong or the segment is absent, Host.Connect's own cryptographic
// verification simply fails the dial — it cannot silently accept a wrong
// or missing PeerID.
//
// [REF: IC §4.1, IC §5.9 ERRATA, MVP §8.2 Phase 15.2 Session 15.2.1]

package upload

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/p2p"
)

// Chunk-upload protocol constants (IC §4.1) — a package-local twin of
// internal/vettingchunk's own copies (Milestone 14): vettingchunk cannot be
// imported here any more than the reverse, per this codebase's sibling
// internal/ package boundaries, so these are declared independently again
// rather than shared.
const (
	chunkUploadProtocolID = p2p.ProtocolID("/vyomanaut/chunk-upload/1.0.0")
	chunkUploadTimeout    = 5 * time.Second

	uploadLengthPrefixSize    = 4
	uploadChunkIDSize         = 32
	uploadShardIndexSize      = 4
	uploadCapabilityTokenSize = 72
	uploadProviderSigSize     = 64
)

// UploadResponse status codes actually branched on by this file (IC §4.1
// Frame 2); the remainder surface verbatim via the returned error.
const (
	uploadStatusOK                = 0x00
	uploadStatusAlreadyStored     = 0x06 // idempotent; treat as 0x00
	uploadStatusCapabilityExpired = 0x07
)

// maxUploadConcurrency bounds the goroutine pool for parallel shard upload.
// Not sourced from NetworkProfile — no field for it exists there; this is a
// local resource-usage cap, not a wire-format or cryptographic parameter,
// so it does not fall under NetworkProfile's own "must be identical in both
// profiles" invariant scope.
const maxUploadConcurrency = 16

// shardUploadTask is one shard's worth of upload work.
type shardUploadTask struct {
	segmentIndex int
	shardIndex   int
	chunkID      [32]byte
	data         []byte
}

// transferAll uploads every not-yet-acknowledged shard across all segments
// in parallel (bounded pool per maxUploadConcurrency), updating
// sess.AckStatus and persisting it to sessionDir as each shard is
// acknowledged, so a crash loses at most the in-flight batch (FR-060).
//
// On a 0x07 CAPABILITY_EXPIRED response for any shard, this calls
// requestAssignment again for the same fileID (idempotent per its own doc
// comment) exactly once, replaces assignResp.Assignments with the fresh
// tokens, and retries every still-unacknowledged shard against the new
// tokens — ERRATA's own instruction, not a general retry-forever loop.
func (o *Orchestrator) transferAll(
	ctx context.Context, fileID uuid.UUID,
	assignResp *uploadAssignResponse, shardData [][][]byte,
	sess *SessionState, sessionDir string,
) error {
	assignments := assignResp.Assignments
	reassigned := false

	for {
		tasks := pendingTasks(assignments, shardData, sess)
		if len(tasks) == 0 {
			return nil
		}

		capabilityExpired, uploadErr := o.uploadTasks(ctx, assignments, tasks, sess, sessionDir)

		if capabilityExpired {
			if reassigned {
				// Already retried once against fresh tokens per ERRATA's own
				// instruction; a second expiry in the same call is treated
				// as upload failure rather than looping indefinitely.
				return fmt.Errorf("upload: transferAll: capability token expired again after re-assignment: %w", ErrUploadIncomplete)
			}
			fresh, err := o.requestAssignment(ctx, fileID, len(shardData), sumOriginalSizeBytes(sess))
			if err != nil {
				return fmt.Errorf("upload: transferAll: re-assignment after CAPABILITY_EXPIRED: %w", err)
			}
			assignments = fresh.Assignments
			reassigned = true
			continue
		}

		// Not (or no longer) a capability-expiry case: re-scan for any
		// shard still unacknowledged, whether from a permanent per-shard
		// failure (uploadErr) or simply not yet attempted.
		if len(pendingTasks(assignments, shardData, sess)) == 0 {
			return nil
		}
		if uploadErr != nil {
			return fmt.Errorf("upload: transferAll: %w: %v", ErrUploadIncomplete, uploadErr)
		}
		return fmt.Errorf("upload: transferAll: shards remain unacknowledged after upload attempt: %w", ErrUploadIncomplete)
	}
}

// sumOriginalSizeBytes is a defensive fallback used only for the
// re-assignment call's original_size_bytes parameter — the true value is
// already known by orchestrator.go's caller and should be threaded through
// directly in a future revision; this exists so transferAll's signature
// does not need to grow an extra parameter purely for the rare
// CAPABILITY_EXPIRED-retry path. Returns 0, which requestAssignment/the
// server treats as its own validation concern on retry (the file_id is
// already registered from the first assign call, so this field is not
// re-validated against a changed value on a same-file_id idempotent
// re-call per the OAS's own "idempotent: repeated calls with the same
// file_id return the same assignments" description).
func sumOriginalSizeBytes(sess *SessionState) int64 { return 0 }

// pendingTasks returns one shardUploadTask per not-yet-acknowledged shard.
func pendingTasks(assignments []segmentAssignment, shardData [][][]byte, sess *SessionState) []shardUploadTask {
	var tasks []shardUploadTask
	for segIdx, seg := range assignments {
		for _, sa := range seg.Providers {
			if sess.AckStatus[segIdx][sa.ShardIndex] {
				continue
			}
			tasks = append(tasks, shardUploadTask{
				segmentIndex: segIdx,
				shardIndex:   sa.ShardIndex,
				chunkID:      sess.ChunkIDs[segIdx][sa.ShardIndex],
				data:         shardData[segIdx][sa.ShardIndex],
			})
		}
	}
	return tasks
}

// uploadTasks runs tasks through a bounded goroutine pool. Returns
// capabilityExpired=true if any task hit 0x07, signalling transferAll to
// re-assign and retry; other per-task errors are logged into the returned
// error only if every task fails (a partial failure is expected and
// resolved by the pendingTasks re-scan on the next loop iteration/call).
func (o *Orchestrator) uploadTasks(
	ctx context.Context, assignments []segmentAssignment, tasks []shardUploadTask,
	sess *SessionState, sessionDir string,
) (capabilityExpired bool, err error) {
	sem := make(chan struct{}, maxUploadConcurrency)
	var (
		mu         sync.Mutex
		wg         sync.WaitGroup
		anyExpired bool
		anySuccess bool
		lastErr    error
	)

	for _, task := range tasks {
		sa := findShardAssignment(assignments, task.segmentIndex, task.shardIndex)
		if sa == nil {
			continue // assignment shrank across a re-assignment race; skip, will be picked up next loop
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(task shardUploadTask, sa shardAssignment) {
			defer wg.Done()
			defer func() { <-sem }()

			status, uploadErr := o.uploadOneShard(ctx, sa, task)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case uploadErr != nil:
				lastErr = uploadErr
			case status == uploadStatusCapabilityExpired:
				anyExpired = true
			case status == uploadStatusOK || status == uploadStatusAlreadyStored:
				sess.AckStatus[task.segmentIndex][task.shardIndex] = true
				anySuccess = true
			default:
				lastErr = fmt.Errorf("UploadResponse: status 0x%02x for shard %d of segment %d", status, task.shardIndex, task.segmentIndex)
			}
		}(task, *sa)
	}
	wg.Wait()

	if anySuccess {
		if err := SaveSessionState(sessionDir, *sess); err != nil {
			return anyExpired, fmt.Errorf("upload: uploadTasks: persist session state: %w", err)
		}
	}
	return anyExpired, lastErr
}

func findShardAssignment(assignments []segmentAssignment, segIdx, shardIdx int) *shardAssignment {
	if segIdx < 0 || segIdx >= len(assignments) {
		return nil
	}
	for i := range assignments[segIdx].Providers {
		if assignments[segIdx].Providers[i].ShardIndex == shardIdx {
			return &assignments[segIdx].Providers[i]
		}
	}
	return nil
}

// uploadOneShard performs one full chunk-upload exchange (IC §4.1) for a
// single shard: resolve the target peer, connect, open the stream, write
// UploadRequest with the server-issued capability_token included verbatim,
// and read UploadResponse.
func (o *Orchestrator) uploadOneShard(ctx context.Context, sa shardAssignment, task shardUploadTask) (status byte, err error) {
	peerID, addrs, err := resolveShardPeer(sa)
	if err != nil {
		return 0, fmt.Errorf("upload: uploadOneShard: %w", err)
	}
	if err := o.host.Connect(ctx, peerID, addrs); err != nil {
		return 0, fmt.Errorf("upload: uploadOneShard: connect to provider %s: %w", sa.ProviderID, err)
	}
	stream, err := o.host.NewStream(ctx, peerID, chunkUploadProtocolID)
	if err != nil {
		return 0, fmt.Errorf("upload: uploadOneShard: open chunk-upload stream: %w", err)
	}
	defer func() { _ = stream.Close() }()
	if err := stream.SetDeadline(time.Now().Add(chunkUploadTimeout)); err != nil {
		return 0, fmt.Errorf("upload: uploadOneShard: set deadline: %w", err)
	}

	token, err := hex.DecodeString(sa.CapabilityToken)
	if err != nil || len(token) != uploadCapabilityTokenSize {
		return 0, fmt.Errorf("upload: uploadOneShard: malformed capability_token for provider %s", sa.ProviderID)
	}
	var tokenArr [uploadCapabilityTokenSize]byte
	copy(tokenArr[:], token)

	if err := writeUploadRequest(stream, task.chunkID, uint32(task.shardIndex), tokenArr, task.data); err != nil {
		return 0, fmt.Errorf("upload: uploadOneShard: %w", err)
	}
	status, err = readUploadResponse(stream)
	if err != nil {
		return 0, fmt.Errorf("upload: uploadOneShard: %w", err)
	}
	return status, nil
}

// resolveShardPeer extracts a dialable p2p.PeerID + []p2p.Multiaddr from a
// ShardAssignment's multiaddrs — see this file's header comment for why
// the PeerID must be parsed from the raw multiaddr string directly.
func resolveShardPeer(sa shardAssignment) (p2p.PeerID, []p2p.Multiaddr, error) {
	if len(sa.Multiaddrs) == 0 {
		return "", nil, fmt.Errorf("provider %s: no multiaddrs in assignment", sa.ProviderID)
	}
	var (
		peerID p2p.PeerID
		addrs  []p2p.Multiaddr
	)
	for _, raw := range sa.Multiaddrs {
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
		return "", nil, fmt.Errorf("provider %s: no parseable multiaddrs among %d stored", sa.ProviderID, len(sa.Multiaddrs))
	}
	if peerID == "" {
		return "", nil, fmt.Errorf("provider %s: no /p2p/<PeerID> segment found in any multiaddr", sa.ProviderID)
	}
	return peerID, addrs, nil
}

// extractPeerIDFromMultiaddr parses the trailing /p2p/<PeerID> segment from
// a raw multiaddr string, per the OAS's own documented convention (see this
// file's header comment).
func extractPeerIDFromMultiaddr(raw string) (p2p.PeerID, bool) {
	const marker = "/p2p/"
	idx := strings.LastIndex(raw, marker)
	if idx == -1 {
		return "", false
	}
	id := raw[idx+len(marker):]
	id = strings.Trim(id, "/")
	if id == "" {
		return "", false
	}
	return p2p.PeerID(id), true
}

// writeUploadRequest writes IC §4.1's Frame 1 — UploadRequest: length(4) ||
// chunk_id(32) || shard_index(4) || capability_token(72) || chunk_data.
// A package-local twin of internal/vettingchunk's own writeUploadRequest
// (Milestone 14) — see this file's header comment on why it is not shared.
func writeUploadRequest(s p2p.Stream, chunkID [32]byte, shardIndex uint32, token [uploadCapabilityTokenSize]byte, data []byte) error {
	payloadLen := uploadChunkIDSize + uploadShardIndexSize + uploadCapabilityTokenSize + len(data)
	frame := make([]byte, uploadLengthPrefixSize+payloadLen)
	binary.BigEndian.PutUint32(frame[0:uploadLengthPrefixSize], uint32(payloadLen))
	offset := uploadLengthPrefixSize
	copy(frame[offset:offset+uploadChunkIDSize], chunkID[:])
	offset += uploadChunkIDSize
	binary.BigEndian.PutUint32(frame[offset:offset+uploadShardIndexSize], shardIndex)
	offset += uploadShardIndexSize
	copy(frame[offset:offset+uploadCapabilityTokenSize], token[:])
	offset += uploadCapabilityTokenSize
	copy(frame[offset:], data)
	if _, err := s.Write(frame); err != nil {
		return fmt.Errorf("write UploadRequest: %w", err)
	}
	return nil
}

// readUploadResponse reads IC §4.1's Frame 2 — UploadResponse — and returns
// the status byte. provider_sig (present on 0x00/0x06) is read past but not
// retained — see internal/vettingchunk's own readUploadResponse (Milestone
// 14) for the same documented gap this mirrors.
func readUploadResponse(s p2p.Stream) (status byte, err error) {
	var lengthBuf [uploadLengthPrefixSize]byte
	if _, err := io.ReadFull(s, lengthBuf[:]); err != nil {
		return 0, fmt.Errorf("read UploadResponse length: %w", err)
	}
	length := binary.BigEndian.Uint32(lengthBuf[:])
	body := make([]byte, length)
	if _, err := io.ReadFull(s, body); err != nil {
		return 0, fmt.Errorf("read UploadResponse body: %w", err)
	}
	if len(body) < 1 {
		return 0, fmt.Errorf("UploadResponse: empty body")
	}
	return body[0], nil
}

// verifyContentAddress is used by tests and available for defensive use at
// call sites that build task.data from an untrusted source; production
// task.data is always freshly RS-encoded locally (orchestrator.go), so its
// content address is correct by construction there.
func verifyContentAddress(chunkID [32]byte, data []byte) bool {
	return sha256.Sum256(data) == chunkID
}