// Package retrieve is declared in doc.go.
// This file implements RetrieveFile() (TASK step 4) and declares this
// package's exported interface and sentinel errors.
//
// [Design note — package split] Same split as internal/client/upload
// (Session 15.2.1's own header comment): IC §5.9 sketches one "package
// client" bundling UploadFile/ResumeUpload/RetrieveFile into a single
// UploadOrchestrator interface. mvp.md §8.2's actual file layout (A-7)
// splits RetrieveFile into this separate package instead. This file
// declares its own RetrieveOrchestrator interface containing just
// RetrieveFile, preserving IC §5.9's exact method signature and all three
// sentinel error texts verbatim — including the "client:" message prefix
// and ErrTooFewShards' literal "16" (both given exactly as IC §5.9 states
// them, even though this now lives in package retrieve and even though
// "16" is a production-only figure inconsistent with demo mode's
// DataShards=3, the same class of stale-figure issue already flagged
// elsewhere in this milestone — not silently corrected here since the
// message text was given verbatim as the contract).
//
// [REF: IC §5.9, IC §5.1, FR-016, FR-018, MVP §8.2 Phase 15.3
// Session 15.3.1]

package retrieve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// RetrieveOrchestrator downloads and decodes a file (IC §5.9). See this
// file's header comment on the package split from IC §5.9's original
// single-package sketch.
type RetrieveOrchestrator interface {
	// RetrieveFile downloads and decodes a file.
	//
	// Pre-conditions:
	//   - masterSecret is the 32-byte master secret
	//   - fileID identifies an ACTIVE file owned by ownerID
	// Post-conditions (on nil error):
	//   - returned plaintext is verified: Poly1305 tag passed, all shard
	//     content addresses verified, AONT canary verified
	//   - plaintext is exactly original_size_bytes (padding stripped)
	// Error semantics:
	//   - ErrPointerTagMismatch: Poly1305 verification failed; no
	//     plaintext returned
	//   - ErrTooFewShards: fewer than profile.DataShards providers
	//     reachable (FR-016 path exhausted)
	//   - ErrCanaryMismatch: AONT canary failed after decode; no plaintext
	//     returned (FR-018)
	// Goroutine-safe: yes.
	RetrieveFile(ctx context.Context,
		masterSecret [32]byte, ownerID, fileID uuid.UUID) (plaintext []byte, err error)
}

var (
	ErrPointerTagMismatch = errors.New("client: pointer file Poly1305 tag verification failed")
	ErrTooFewShards       = errors.New("client: fewer than 16 shards reachable for this segment")
	// ErrCanaryMismatch is declared here per IC §5.9's documented interface
	// contract, but decode.go's decodeSegment no longer actually returns
	// it (D-10, M17 Session 17.1.2): it now wraps crypto.ErrCanaryMismatch
	// directly, so errors.Is(err, crypto.ErrCanaryMismatch) — not this
	// sentinel — is the correct check above the client boundary. Left
	// declared, not removed, so this file's exported surface still matches
	// IC §5.9's documented contract; flagged here rather than silently
	// leaving a declared-but-unused-internally sentinel unexplained.
	ErrCanaryMismatch = errors.New("client: AONT canary mismatch after decode (segment corrupt)")
)

// Orchestrator implements RetrieveOrchestrator.
type Orchestrator struct {
	api     *apiClient
	host    p2p.Host
	engine  *erasure.Engine
	profile config.NetworkProfile
	aesNI   bool
}

var _ RetrieveOrchestrator = (*Orchestrator)(nil)

// NewOrchestrator constructs an Orchestrator.
func NewOrchestrator(
	baseURL, token string, httpClient *http.Client,
	host p2p.Host, engine *erasure.Engine, profile config.NetworkProfile,
) *Orchestrator {
	return &Orchestrator{
		api:     newAPIClient(baseURL, token, httpClient),
		host:    host,
		engine:  engine,
		profile: profile,
		aesNI:   crypto.DetectAESNI(),
	}
}

// RetrieveFile implements RetrieveOrchestrator.
func (o *Orchestrator) RetrieveFile(ctx context.Context, masterSecret [32]byte, ownerID, fileID uuid.UUID) ([]byte, error) {
	// TASK step 1: fetch and decrypt the pointer file (pointer.go).
	pointerPlaintext, originalSizeBytes, err := o.fetchAndDecryptPointerFile(ctx, masterSecret, ownerID, fileID)
	if err != nil {
		return nil, fmt.Errorf("retrieve: RetrieveFile: %w", err)
	}

	// TASK step 4: concatenate segments in segment_index order.
	segments := pointerPlaintext.Segments
	sort.Slice(segments, func(i, j int) bool { return segments[i].SegmentIndex < segments[j].SegmentIndex })

	// ADR-080 §2: resolve every segment's shard addresses and download
	// tokens in one call, before any shard is dialled — not per segment.
	resolved, err := o.resolveFileForRetrieval(ctx, fileID)
	if err != nil {
		return nil, fmt.Errorf("retrieve: RetrieveFile: %w", err)
	}

	var out []byte
	for _, seg := range segments {
		// TASK step 2: parallel dial-cancel-at-k download (download.go).
		shards, err := o.downloadSegment(ctx, seg, resolved)
		if err != nil {
			return nil, fmt.Errorf("retrieve: RetrieveFile: segment %d: %w", seg.SegmentIndex, err)
		}
		// TASK step 3: RS decode + AONT decode + canary check (decode.go).
		segPlain, err := o.decodeSegment(shards)
		if err != nil {
			return nil, fmt.Errorf("retrieve: RetrieveFile: segment %d: %w", seg.SegmentIndex, err)
		}
		out = append(out, segPlain...)
	}

	if int64(len(out)) < originalSizeBytes {
		return nil, fmt.Errorf("retrieve: RetrieveFile: decoded length %d shorter than original_size_bytes %d", len(out), originalSizeBytes)
	}
	return out[:originalSizeBytes], nil // strip AONT padding
}
