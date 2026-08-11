// Package vettingchunk is declared in doc.go.
// This file implements Generator (IC §5.10): synthetic vetting-chunk
// generation and upload via the standard /vyomanaut/chunk-upload/1.0.0
// protocol (IC §4.1) — identical wire format to a normal client upload.
// This mirrors IC §4.1's own repair-upload precedent (the repair package's
// executor.go uploadShard: "identical wire format to a normal client
// upload; the replacement provider cannot and must not be able to
// distinguish a repair upload from a normal one") for the same underlying
// reason DM §4.5 states for vetting chunks specifically: "The provider
// daemon has no visibility into [is_vetting_chunk]; it stores and serves
// audits for synthetic chunks through the identical code paths as real
// shards."
//
// [Decision — vettingchunk cannot import the repair package (IC §9), so the
// chunk-upload initiator logic (capability_token minting, Frame 1/Frame 2
// framing) is a package-local twin of the repair package's executor.go
// uploadShard/mintCapabilityToken, not a shared import. Likewise
// resolveProviderPeer below is a package-local twin of
// cmd/microservice/adapters.go's function of the same name — vettingchunk
// cannot import cmd/microservice either (cmd/* is wiring-only and not
// importable by internal/* per this codebase's dependency direction).]
//
// [REF: IC §5.10, IC §4.1, IC §9, DM §3 Invariant 6, DM §4.5, ADR-030,
// build.md Milestone 14 Phase 14.1 Session 14.1.1]

package vettingchunk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	localcrypto "github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
	"github.com/masamasaowl/Vyomanaut_V2/internal/p2p"
	"github.com/masamasaowl/Vyomanaut_V2/internal/storage"
)

// Generator produces synthetic vetting chunks for assignment to VETTING
// providers (IC §5.10, ADR-030).
type Generator interface {
	// GenerateChunk creates a single 256 KB random block and returns its
	// chunk ID. The generated data is immediately uploaded to the provider
	// via the standard chunk upload stream (/vyomanaut/chunk-upload/1.0.0).
	//
	// Pre-conditions:
	//   - providerID identifies a provider with status = 'VETTING'
	//   - The provider's current synthetic chunk count <
	//     floor(declared_storage_gb × 400) (cap enforcement is the caller's
	//     responsibility before invoking GenerateChunk; GenerateChunk also
	//     re-checks defensively — see its doc comment)
	// Post-conditions (on nil error):
	//   - 256 KB of crypto/rand data is generated, uploaded, and
	//     acknowledged by the provider
	//   - A chunk_assignments row is inserted with is_vetting_chunk = TRUE,
	//     segment_id = NULL, shard_index = NULL
	//   - The chunkID (SHA-256 of the generated data) is returned for
	//     record-keeping
	//
	// Note: the raw 256 KB data is NOT retained by the microservice after
	// upload confirmation.
	//
	// Goroutine-safe: yes.
	GenerateChunk(ctx context.Context, providerID uuid.UUID) (chunkID [32]byte, err error)

	// CurrentCount returns the number of ACTIVE synthetic chunks for a
	// provider. Used by the assignment service for cap enforcement.
	//
	// Goroutine-safe: yes.
	CurrentCount(ctx context.Context, db *sql.DB, providerID uuid.UUID) (int, error)

	// Cap returns the maximum allowed synthetic chunks for a provider.
	// cap = floor(declared_storage_gb × 400). Pure function of
	// declaredStorageGB; no database read required.
	Cap(declaredStorageGB int) int
}

// vettingCapPerGB is the vetting cap formula constant: Cap(declaredStorageGB)
// = floor(declaredStorageGB × 400). Distinct from the RAM-requirement
// formula constant in internal/storage/ram_requirement.go (Session 13.6.1)
// — the two govern unrelated resources (this one bounds synthetic
// vetting-chunk count; that one bounds daemon RAM) and must not be
// conflated.
const vettingCapPerGB = 400

// providerStatusVetting mirrors providers.status = 'VETTING' (DM §4 —
// provider_status enum).
const providerStatusVetting = "VETTING"

// chunk-upload protocol constants (IC §4.1). vettingchunk cannot import
// the repair package (IC §9), so these are declared independently here
// rather than shared with its executor.go's own copies.
const (
	chunkUploadProtocolID = p2p.ProtocolID("/vyomanaut/chunk-upload/1.0.0")
	chunkUploadTimeout    = 5 * time.Second
	capabilityTokenTTL    = 1 * time.Hour

	uploadLengthPrefixSize    = 4  // uint32 big-endian frame length prefix
	uploadChunkIDSize         = 32 // SHA-256 content address
	uploadShardIndexSize      = 4  // uint32 big-endian
	uploadCapabilityTokenSize = 72 // expiry_unix_ms(8) || Ed25519 sig(64)
	uploadProviderSigSize     = 64 // Ed25519 signature (present on 0x00/0x06)
)

// Upload response status codes actually consumed by this file (IC §4.1
// Frame 2); the remaining codes are non-retryable failures surfaced
// verbatim via the returned error rather than named here.
const (
	uploadStatusOK            = 0x00
	uploadStatusAlreadyStored = 0x06 // idempotent; treat as 0x00
)

// capabilityTokenDomainPrefix is IC §4.1's domain-separation prefix,
// matching internal/api/upload.go's own constant of the same value.
const capabilityTokenDomainPrefix = "vyomanaut-chunk-upload-cap-v1"

// syntheticChunkShardIndex is the placeholder wire-frame shard_index value
// for a synthetic vetting-chunk upload. IC §4.1's UploadRequest carries a
// shard_index field unconditionally, but a synthetic chunk has no RS shard
// slot (DM §4.5: shard_index is NULL in chunk_assignments for
// is_vetting_chunk = TRUE rows). The field is not otherwise consumed by the
// provider's upload handler (cmd/provider/handler_upload.go: "shardIndex
// ... not otherwise consumed by this handler"). 0 is used here as an
// explicit, documented placeholder rather than an invented meaning —
// consistent with this project's fail-closed-over-guessing convention for
// unspecified wire-format details.
const syntheticChunkShardIndex = 0

// generator implements Generator.
type generator struct {
	db         *sql.DB
	host       p2p.Host
	signingKey ed25519.PrivateKey // microservice signing key; mints capability_token
}

// NewGenerator constructs a Generator. signingKey is the microservice's own
// Ed25519 signing key — the same key used to sign JWTs and service_sig on
// audit receipts (IC §4.1).
func NewGenerator(db *sql.DB, host p2p.Host, signingKey ed25519.PrivateKey) Generator {
	return &generator{db: db, host: host, signingKey: signingKey}
}

// Cap implements Generator.
func (g *generator) Cap(declaredStorageGB int) int {
	return declaredStorageGB * vettingCapPerGB
}

// CurrentCount implements Generator.
func (g *generator) CurrentCount(ctx context.Context, db *sql.DB, providerID uuid.UUID) (int, error) {
	const query = `
SELECT COUNT(*) FROM chunk_assignments
WHERE provider_id = $1 AND is_vetting_chunk = TRUE AND status = 'ACTIVE'`
	var count int
	if err := db.QueryRowContext(ctx, query, providerID).Scan(&count); err != nil {
		return 0, fmt.Errorf("vettingchunk: CurrentCount: %w", err)
	}
	return count, nil
}

// GenerateChunk implements Generator.
func (g *generator) GenerateChunk(ctx context.Context, providerID uuid.UUID) (chunkID [32]byte, err error) {
	status, declaredStorageGB, pubKey, addrs, err := loadProviderForVetting(ctx, g.db, providerID)
	if err != nil {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: %w", err)
	}
	if status != providerStatusVetting {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: provider %s: %w", providerID, ErrNotVettingProvider)
	}

	// Defensive cap re-check (fail-closed): IC §5.10 states cap enforcement
	// is the caller's responsibility before invoking GenerateChunk, but a
	// cheap re-check here protects against a caller bug silently exceeding
	// the vetting cap rather than trusting the pre-condition blindly.
	count, err := g.CurrentCount(ctx, g.db, providerID)
	if err != nil {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: %w", err)
	}
	if count >= g.Cap(declaredStorageGB) {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: provider %s: %w", providerID, ErrCapExceeded)
	}

	data := make([]byte, storage.ChunkDataSize)
	if _, err := rand.Read(data); err != nil {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: generate random chunk: %w", err)
	}
	chunkID = sha256.Sum256(data)

	peerID, err := p2p.PeerIDFromEd25519PublicKey(pubKey)
	if err != nil {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: derive peer ID: %w", err)
	}
	if err := g.host.Connect(ctx, peerID, addrs); err != nil {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: connect to provider %s: %w", providerID, err)
	}
	stream, err := g.host.NewStream(ctx, peerID, chunkUploadProtocolID)
	if err != nil {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: open chunk-upload stream: %w", err)
	}
	defer func() { _ = stream.Close() }()
	if err := stream.SetDeadline(time.Now().Add(chunkUploadTimeout)); err != nil {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: set deadline: %w", err)
	}

	// fileID is uuid.Nil: a synthetic vetting chunk has no owning file (DM
	// §4.5). IC §4.1's capability_token signing_input always carries 16
	// file_id bytes regardless; the zero UUID is the natural "no file"
	// value here.
	token := mintCapabilityToken(g.signingKey, chunkID, providerID, capabilityTokenTTL)
	if err := writeUploadRequest(stream, chunkID, syntheticChunkShardIndex, token, data); err != nil {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: %w", err)
	}
	respStatus, err := readUploadResponse(stream)
	if err != nil {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: %w", err)
	}
	if respStatus != uploadStatusOK && respStatus != uploadStatusAlreadyStored {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: UploadResponse: status 0x%02x", respStatus)
	}

	if err := insertVettingChunkAssignment(ctx, g.db, chunkID, providerID); err != nil {
		return chunkID, fmt.Errorf("vettingchunk: GenerateChunk: %w", err)
	}
	return chunkID, nil
}

// loadProviderForVetting looks up providerID's status, declared_storage_gb,
// Ed25519 public key, and dialable multiaddrs in a single query.
func loadProviderForVetting(ctx context.Context, db *sql.DB, providerID uuid.UUID) (status string, declaredStorageGB int, pubKey ed25519.PublicKey, addrs []p2p.Multiaddr, err error) {
	const query = `
SELECT status, declared_storage_gb, ed25519_public_key, last_known_multiaddrs
FROM providers WHERE provider_id = $1`
	var (
		pubKeyBytes   []byte
		multiaddrsRaw []byte
	)
	if err := db.QueryRowContext(ctx, query, providerID).Scan(&status, &declaredStorageGB, &pubKeyBytes, &multiaddrsRaw); err != nil {
		return "", 0, nil, nil, fmt.Errorf("look up provider %s: %w", providerID, err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return "", 0, nil, nil, fmt.Errorf("provider %s: ed25519_public_key is %d bytes, want %d", providerID, len(pubKeyBytes), ed25519.PublicKeySize)
	}
	addrs, err = parseKnownMultiaddrs(multiaddrsRaw)
	if err != nil {
		return "", 0, nil, nil, fmt.Errorf("provider %s: %w", providerID, err)
	}
	return status, declaredStorageGB, ed25519.PublicKey(pubKeyBytes), addrs, nil
}

// resolveProviderPeer looks up providerID's Ed25519 public key and last
// known multiaddrs and derives a dialable p2p.PeerID + []p2p.Multiaddr.
// Shared by GCDelivery.DeliverGCInstruction (gc.go) — see this file's
// header comment for why this is a package-local twin of
// cmd/microservice/adapters.go's own resolveProviderPeer rather than a
// shared import.
func resolveProviderPeer(ctx context.Context, db *sql.DB, providerID uuid.UUID) (p2p.PeerID, []p2p.Multiaddr, error) {
	const query = `SELECT ed25519_public_key, last_known_multiaddrs FROM providers WHERE provider_id = $1`
	var (
		pubKey        []byte
		multiaddrsRaw []byte
	)
	if err := db.QueryRowContext(ctx, query, providerID).Scan(&pubKey, &multiaddrsRaw); err != nil {
		return "", nil, fmt.Errorf("resolveProviderPeer: look up provider %s: %w", providerID, err)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("resolveProviderPeer: provider %s: ed25519_public_key is %d bytes, want %d", providerID, len(pubKey), ed25519.PublicKeySize)
	}
	peerID, err := p2p.PeerIDFromEd25519PublicKey(pubKey)
	if err != nil {
		return "", nil, fmt.Errorf("resolveProviderPeer: provider %s: derive Peer ID: %w", providerID, err)
	}
	addrs, err := parseKnownMultiaddrs(multiaddrsRaw)
	if err != nil {
		return "", nil, fmt.Errorf("resolveProviderPeer: provider %s: %w", providerID, err)
	}
	return peerID, addrs, nil
}

// parseKnownMultiaddrs parses a providers.last_known_multiaddrs JSONB
// column value into dialable Multiaddrs, skipping unparseable entries.
// Mirrors cmd/microservice/adapters.go's resolveProviderPeer address
// parsing.
func parseKnownMultiaddrs(raw []byte) ([]p2p.Multiaddr, error) {
	var addrStrings []string
	if err := json.Unmarshal(raw, &addrStrings); err != nil {
		return nil, fmt.Errorf("parse last_known_multiaddrs: %w", err)
	}
	if len(addrStrings) == 0 {
		return nil, fmt.Errorf("no known multiaddrs")
	}
	addrs := make([]p2p.Multiaddr, 0, len(addrStrings))
	for _, s := range addrStrings {
		addr, err := p2p.ParseMultiaddr(s)
		if err != nil {
			continue // skip unparseable entries; try the rest before failing outright
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no parseable multiaddrs among %d stored", len(addrStrings))
	}
	return addrs, nil
}

// mintCapabilityToken builds the 72-byte capability_token (IC §4.1):
//
//	signing_input = SHA-256(
//	    "vyomanaut-chunk-upload-cap-v1"
//	    || chunk_id          (32 bytes)
//	    || provider_id       (16 bytes, UUID bytes, big-endian)
//	    || expiry_unix_ms    (8 bytes, int64 big-endian)
//	)
//	capability_token = expiry_unix_ms (8 B) || Ed25519_sign(microservice_signing_key, signing_input)
//
// file_id is deliberately NOT part of this signing input — Design Council
// verdict ("Capability Token: Drop file_id, Not Add It to the Wire
// Format", ADR-072): chunk_id is 256 bits of fresh, microservice-generated
// randomness minted once per assignment and never reused across files, so
// it already carries the exact binding file_id would have provided. This
// call site already passed uuid.Nil for vetting chunks (they have no
// file), so this removal has zero behavioral effect here — it's the
// upload.go/repair paths this closes a real gap for.
//
// Uses internal/crypto.SignBytes (IC §3.2's canonical hash-then-sign
// composition) rather than a manual sha256+ed25519.Sign call — vettingchunk
// is permitted to import internal/crypto (IC §9), so this reuses the
// project's own signing primitive instead of re-deriving it, matching
// internal/api/upload.go's own generateCapabilityToken.
func mintCapabilityToken(signingKey ed25519.PrivateKey, chunkID [32]byte, providerID uuid.UUID, ttl time.Duration) [uploadCapabilityTokenSize]byte {
	expiryUnixMs := time.Now().Add(ttl).UnixMilli()
	var expiryBytes [8]byte
	binary.BigEndian.PutUint64(expiryBytes[:], uint64(expiryUnixMs))

	input := make([]byte, 0, len(capabilityTokenDomainPrefix)+len(chunkID)+len(providerID)+len(expiryBytes))
	input = append(input, []byte(capabilityTokenDomainPrefix)...)
	input = append(input, chunkID[:]...)
	input = append(input, providerID[:]...)
	input = append(input, expiryBytes[:]...)

	sig := localcrypto.SignBytes(signingKey, input)

	var token [uploadCapabilityTokenSize]byte
	copy(token[0:8], expiryBytes[:])
	copy(token[8:uploadCapabilityTokenSize], sig[:])
	return token
}

// writeUploadRequest writes IC §4.1's Frame 1 — UploadRequest: length(4) ||
// chunk_id(32) || shard_index(4) || capability_token(72) || chunk_data(262144).
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
// retained: GenerateChunk's own contract (IC §5.10) only returns the
// chunkID for record-keeping, mirroring the same documented gap the repair
// package's executor.go uploadShard already flags for the repair upload
// path (no schema column exists anywhere to persist an upload receipt
// signature).
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

// insertVettingChunkAssignment INSERTs the chunk_assignments row for a
// newly-uploaded synthetic chunk (DM §3 Invariant 6, DM §4.5):
// is_vetting_chunk = TRUE, segment_id = NULL, shard_index = NULL.
func insertVettingChunkAssignment(ctx context.Context, db *sql.DB, chunkID [32]byte, providerID uuid.UUID) error {
	const insert = `
INSERT INTO chunk_assignments (chunk_id, is_vetting_chunk, segment_id, shard_index, provider_id, status)
VALUES ($1, TRUE, NULL, NULL, $2, 'ACTIVE')`
	if _, err := db.ExecContext(ctx, insert, chunkID[:], providerID); err != nil {
		return fmt.Errorf("insert chunk_assignments (vetting): %w", err)
	}
	return nil
}