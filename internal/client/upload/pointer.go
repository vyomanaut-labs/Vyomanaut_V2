// Package upload is declared in doc.go.
// This file implements pointer-file construction and registration (TASK
// steps 6–7): builds the PointerFilePlaintextSegment structure (OAS —
// informational schema, never transmitted; client-side reference only),
// AEAD-encrypts it, and POSTs FileRegisterRequest to
// /api/v1/file/register.
//
// owner_sig — fixed-layout, NOT canonical JSON (A-6, critical fix to the
// OAS's stale "canonical JSON, keys sorted" description, corrected in the
// same PR per A-6's own note):
//
//	owner_sig_input = SHA-256(
//	    "vyomanaut-file-register-v1"
//	    ‖ file_id
//	    ‖ SHA-256(pointer_ciphertext)
//	    ‖ pointer_nonce
//	    ‖ pointer_tag
//	    ‖ original_size_bytes(8,BE)
//	    ‖ display_name_present(1)
//	    ‖ SHA-256(display_name_ciphertext‖display_name_nonce‖display_name_tag)
//	    ‖ schema_version(4,BE)
//	)
//	owner_sig = Ed25519_sign(...)
//
// The two-step "compute owner_sig_input as a SHA-256 digest, then
// Ed25519-sign that digest" is exactly crypto.SignBytes' own composition
// (IC §3.2: Ed25519(priv, SHA-256(input))) — so this file builds the raw
// fixed-layout byte sequence and passes it to crypto.SignBytes directly,
// rather than pre-hashing it itself and risking a double-hash.
//
// [REF: A-6, IC §5.1 EncryptPointerFile/DecryptPointerFile, IC §3.2,
// OAS FileRegisterRequest/PointerFilePlaintextSegment, MVP §8.2 Phase 15.2
// Session 15.2.1, FR-019]

package upload

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"

	"github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
)

const poly1305TagSize = 16
const pointerFileNumSegmentsSize = 4

// ── PointerFilePlaintextSegment (OAS — informational, client-side only) ────

// erasureParamsInfo mirrors OAS ErasureParamsInfo. s/r/n are read from the
// active NetworkProfile (never hardcoded — the OAS's own enum constants
// assume production-only figures; see orchestrator.go's header comment on
// the demo/production shard-count discrepancy this flags).
type erasureParamsInfo struct {
	S       int
	R       int
	N       int
	LfBytes int
}

// pointerFileSegment mirrors OAS PointerFilePlaintextSegment. Never
// transmitted as-is — only its AEAD ciphertext (pointerCiphertext below)
// crosses the wire. No JSON tags: encoded by marshalPointerFilePlaintext's
// own fixed binary layout below, not encoding/json (see that function's
// doc comment).
type pointerFileSegment struct {
	SegmentID     uuid.UUID
	SegmentIndex  int
	FileKey       string // hex, 64 chars = 32 bytes
	ProviderIDs   []uuid.UUID
	ChunkIDs      []string // hex, one per shard, shard_index order
	ErasureParams erasureParamsInfo
}

// pointerFilePlaintext is the full plaintext structure this file encrypts:
// one pointerFileSegment per segment, in segment_index order.
type pointerFilePlaintext struct {
	Segments []pointerFileSegment
}

// ── owner_sig domain constant and helpers ──────────────────────────────────

const ownerSigDomainPrefix = "vyomanaut-file-register-v1"

// deriveFilenameKey derives the display-name AEAD key:
//
//	key = HKDF-SHA256(ikm=masterSecret, salt=ownerID, info="vyomanaut-filename-v1"||fileID)
//
// [Flagged] internal/crypto has no exported DeriveFilenameKey — only four
// fixed-purpose derive functions (DeriveFileKey, DerivePointerEncKey,
// DeriveKeystoreEncKey, DeriveDHTOwnerKey), none for "vyomanaut-filename-v1".
// Its internal hkdfSHA256 helper is unexported, and internal/crypto is not
// in this session's FILES scope to extend. This reimplements the identical
// HKDF-SHA256(ikm, salt, info) construction locally via
// golang.org/x/crypto/hkdf (already a transitive dependency of
// internal/crypto itself) rather than inventing a different derivation.
// Worth promoting to a real internal/crypto.DeriveFilenameKey in a future
// session for parity with the other four — flagged here, not fixed here.
func deriveFilenameKey(masterSecret, ownerID, fileID []byte) [32]byte {
	const prefix = "vyomanaut-filename-v1"
	info := make([]byte, 0, len(prefix)+len(fileID))
	info = append(info, prefix...)
	info = append(info, fileID...)
	r := hkdf.New(sha256.New, masterSecret, ownerID, info)
	var out [32]byte
	_, _ = r.Read(out[:]) // hkdf.Reader over SHA-256 never errors for a 32-byte read (< 255*32 limit)
	return out
}

// ── FileRegisterRequest (OAS) ───────────────────────────────────────────────

type fileRegisterRequest struct {
	FileID                uuid.UUID `json:"file_id"`
	PointerCiphertext     string    `json:"pointer_ciphertext"` // base64
	PointerNonce          string    `json:"pointer_nonce"`      // base64, 12 bytes
	PointerTag            string    `json:"pointer_tag"`        // base64, 16 bytes
	OriginalSizeBytes     int64     `json:"original_size_bytes"`
	DisplayNameCiphertext *string   `json:"display_name_ciphertext,omitempty"` // base64
	DisplayNameNonce      *string   `json:"display_name_nonce,omitempty"`      // base64, 12 bytes
	DisplayNameTag        *string   `json:"display_name_tag,omitempty"`        // base64, 16 bytes
	SchemaVersion         int       `json:"schema_version"`
	OwnerSig              string    `json:"owner_sig"` // hex, 128 chars = 64 bytes
}

type fileRegisterResponse struct {
	FileID     uuid.UUID `json:"file_id"`
	UploadedAt time.Time `json:"uploaded_at"`
}

// pointerFileSchemaVersion is OAS FileRegisterRequest.schema_version's only
// currently-valid value (enum: [1]).
const pointerFileSchemaVersion = 1

// registerPointerFile builds, encrypts, signs, and registers the pointer
// file for one completed upload (TASK steps 6–7). displayName is optional;
// pass "" to omit it (FR-019's display-name fields are all nullable).
func (o *Orchestrator) registerPointerFile(
	ctx context.Context,
	masterSecret [32]byte, ownerID, fileID uuid.UUID,
	segments []pointerFileSegment, originalSizeBytes int64, displayName string,
	signingKey ed25519.PrivateKey,
) error {
	plaintext, err := marshalPointerFilePlaintext(pointerFilePlaintext{Segments: segments})
	if err != nil {
		return fmt.Errorf("upload: registerPointerFile: %w", err)
	}

	pointerKey := crypto.DerivePointerEncKey(masterSecret[:], ownerID[:], fileID[:])
	// EncryptPointerFile requires the caller to increment the monotone
	// nonce counter BEFORE this call (IC §5.1). This orchestrator signs a
	// pointer file exactly once per UploadFile/ResumeUpload completion, so
	// nonceCounter starts fresh at 1 for this call — a real keystore-backed
	// counter (internal/client/account.Keystore.NonceCounter) is the
	// caller's responsibility to thread through in a future integration;
	// see this function's doc comment on that scope boundary.
	var nonce [12]byte
	nonce[len(nonce)-1] = 1
	pointerCiphertext, err := crypto.EncryptPointerFile(pointerKey, nonce, pointerAAD(ownerID, fileID), plaintext)
	if err != nil {
		return fmt.Errorf("upload: registerPointerFile: encrypt pointer file: %w", err)
	}
	// EncryptAEAD/EncryptPointerFile append the 16-byte Poly1305 tag to the
	// ciphertext; OAS transmits pointer_ciphertext and pointer_tag as
	// separate fields, so split them here.
	if len(pointerCiphertext) < poly1305TagSize {
		return fmt.Errorf("upload: registerPointerFile: pointer ciphertext shorter than the 16-byte tag")
	}
	pointerTag := pointerCiphertext[len(pointerCiphertext)-16:]
	pointerCiphertextOnly := pointerCiphertext[:len(pointerCiphertext)-16]

	var (
		displayNameCiphertext []byte
		displayNameNonce      [12]byte
		displayNameTag        []byte
		displayNamePresent    bool
	)
	if displayName != "" {
		displayNamePresent = true
		filenameKey := deriveFilenameKey(masterSecret[:], ownerID[:], fileID[:])
		displayNameNonce[len(displayNameNonce)-1] = 1
		full, err := crypto.EncryptAEAD(filenameKey, displayNameNonce, pointerAAD(ownerID, fileID), []byte(displayName))
		if err != nil {
			return fmt.Errorf("upload: registerPointerFile: encrypt display name: %w", err)
		}
		if len(full) < poly1305TagSize {
			return fmt.Errorf("upload: registerPointerFile: display name ciphertext shorter than the 16-byte tag")
		}
		displayNameTag = full[len(full)-16:]
		displayNameCiphertext = full[:len(full)-16]
	}

	ownerSig := computeOwnerSig(ownerSigInput{
		FileID:                fileID,
		PointerCiphertext:     pointerCiphertextOnly,
		PointerNonce:          nonce,
		PointerTag:            pointerTag,
		OriginalSizeBytes:     originalSizeBytes,
		DisplayNamePresent:    displayNamePresent,
		DisplayNameCiphertext: displayNameCiphertext,
		DisplayNameNonce:      displayNameNonce,
		DisplayNameTag:        displayNameTag,
		SchemaVersion:         pointerFileSchemaVersion,
	}, signingKey)

	reqBody := fileRegisterRequest{
		FileID:            fileID,
		PointerCiphertext: base64.StdEncoding.EncodeToString(pointerCiphertextOnly),
		PointerNonce:      base64.StdEncoding.EncodeToString(nonce[:]),
		PointerTag:        base64.StdEncoding.EncodeToString(pointerTag),
		OriginalSizeBytes: originalSizeBytes,
		SchemaVersion:     pointerFileSchemaVersion,
		OwnerSig:          fmt.Sprintf("%x", ownerSig),
	}
	if displayNamePresent {
		ct := base64.StdEncoding.EncodeToString(displayNameCiphertext)
		n := base64.StdEncoding.EncodeToString(displayNameNonce[:])
		tg := base64.StdEncoding.EncodeToString(displayNameTag)
		reqBody.DisplayNameCiphertext = &ct
		reqBody.DisplayNameNonce = &n
		reqBody.DisplayNameTag = &tg
	}

	var respBody fileRegisterResponse
	httpResp, rawBody, err := o.api.doJSON(ctx, http.MethodPost, "/api/v1/file/register", reqBody, &respBody)
	if err != nil {
		return fmt.Errorf("upload: registerPointerFile: FileRegisterRequest: %w", err)
	}
	switch httpResp.StatusCode {
	case http.StatusCreated:
		return nil
	default:
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return fmt.Errorf("upload: registerPointerFile: FileRegisterRequest: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return fmt.Errorf("upload: registerPointerFile: FileRegisterRequest: unexpected status %d", httpResp.StatusCode)
	}
}

// pointerAAD is the AEAD associated data for both the pointer file and the
// display-name ciphertext: len(aad) > 0 is EncryptPointerFile's own
// pre-condition ("must include ownerID || fileID || schemaVersion").
func pointerAAD(ownerID, fileID uuid.UUID) []byte {
	var schemaVersionBytes [4]byte
	aad := make([]byte, 0, len(ownerID)+len(fileID)+len(schemaVersionBytes))
	aad = append(aad, ownerID[:]...)
	aad = append(aad, fileID[:]...)
	binary.BigEndian.PutUint32(schemaVersionBytes[:], pointerFileSchemaVersion)
	aad = append(aad, schemaVersionBytes[:]...)
	return aad
}

// ownerSigInput holds every field that goes into owner_sig_input, exactly
// as A-6 lays it out.
type ownerSigInput struct {
	FileID                uuid.UUID
	PointerCiphertext     []byte
	PointerNonce          [12]byte
	PointerTag            []byte
	OriginalSizeBytes     int64
	DisplayNamePresent    bool
	DisplayNameCiphertext []byte
	DisplayNameNonce      [12]byte
	DisplayNameTag        []byte
	SchemaVersion         int
}

// computeOwnerSig builds the fixed-layout byte sequence A-6 specifies and
// signs it via crypto.SignBytes, which performs the
// "SHA-256 then Ed25519-sign that digest" composition A-6's own
// owner_sig_input/owner_sig two-step describes as a single operation.
func computeOwnerSig(in ownerSigInput, signingKey ed25519.PrivateKey) [64]byte {
	displayNameBlockHash := sha256.Sum256(concatBytes(in.DisplayNameCiphertext, in.DisplayNameNonce[:], in.DisplayNameTag))
	pointerCiphertextHash := sha256.Sum256(in.PointerCiphertext)

	var displayNamePresentByte [1]byte
	if in.DisplayNamePresent {
		displayNamePresentByte[0] = 1
	}
	var originalSizeBytes [8]byte
	binary.BigEndian.PutUint64(originalSizeBytes[:], uint64(in.OriginalSizeBytes))
	var schemaVersionBytes [4]byte
	binary.BigEndian.PutUint32(schemaVersionBytes[:], uint32(in.SchemaVersion))

	input := concatBytes(
		[]byte(ownerSigDomainPrefix),
		in.FileID[:],
		pointerCiphertextHash[:],
		in.PointerNonce[:],
		in.PointerTag,
		originalSizeBytes[:],
		displayNamePresentByte[:],
		displayNameBlockHash[:],
		schemaVersionBytes[:],
	)
	return crypto.SignBytes(signingKey, input)
}

func concatBytes(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// marshalPointerFilePlaintext encodes p as a fixed-layout binary blob, not
// JSON. The OAS marks PointerFilePlaintextSegment "informational... for
// client-side implementation reference" — the microservice never parses
// it, so its wire encoding inside the AEAD envelope is entirely this
// client's own choice. Using a fixed-layout encoding here too, rather than
// JSON for this one non-signing blob, keeps that discipline uniform across
// the whole file instead of drawing a fine "acceptable-here, not there"
// distinction next to owner_sig's own strict fixed-layout requirement (A-6). internal/client/retrieve (Phase 15.3) must decode this
// exact same layout on the read path.
//
// Layout (all integers big-endian):
//
//	num_segments(4)
//	segments[num_segments]:
//	  segment_id(16) segment_index(4) file_key(32)
//	  erasure_s(4) erasure_r(4) erasure_n(4) erasure_lf_bytes(4)
//	  provider_ids[erasure_n](16 bytes each, shard_index order)
//	  chunk_ids[erasure_n](32 bytes each, shard_index order)
func marshalPointerFilePlaintext(p pointerFilePlaintext) ([]byte, error) {
	buf := make([]byte, 0, pointerFileNumSegmentsSize+len(p.Segments)*128)

	var numSegBytes [4]byte
	binary.BigEndian.PutUint32(numSegBytes[:], uint32(len(p.Segments)))
	buf = append(buf, numSegBytes[:]...)

	for _, seg := range p.Segments {
		buf = append(buf, seg.SegmentID[:]...)

		var idxBytes [4]byte
		binary.BigEndian.PutUint32(idxBytes[:], uint32(seg.SegmentIndex))
		buf = append(buf, idxBytes[:]...)

		fileKeyBytes, err := hex.DecodeString(seg.FileKey)
		if err != nil || len(fileKeyBytes) != 32 {
			return nil, fmt.Errorf("marshalPointerFilePlaintext: segment %d: malformed file_key", seg.SegmentIndex)
		}
		buf = append(buf, fileKeyBytes...)

		var paramsBytes [16]byte
		binary.BigEndian.PutUint32(paramsBytes[0:4], uint32(seg.ErasureParams.S))
		binary.BigEndian.PutUint32(paramsBytes[4:8], uint32(seg.ErasureParams.R))
		binary.BigEndian.PutUint32(paramsBytes[8:12], uint32(seg.ErasureParams.N))
		binary.BigEndian.PutUint32(paramsBytes[12:16], uint32(seg.ErasureParams.LfBytes))
		buf = append(buf, paramsBytes[:]...)

		if len(seg.ProviderIDs) != seg.ErasureParams.N || len(seg.ChunkIDs) != seg.ErasureParams.N {
			return nil, fmt.Errorf("marshalPointerFilePlaintext: segment %d: provider/chunk ID count does not match erasure_params.n", seg.SegmentIndex)
		}
		for _, pid := range seg.ProviderIDs {
			buf = append(buf, pid[:]...)
		}
		for _, chunkIDHex := range seg.ChunkIDs {
			chunkIDBytes, err := hex.DecodeString(chunkIDHex)
			if err != nil || len(chunkIDBytes) != 32 {
				return nil, fmt.Errorf("marshalPointerFilePlaintext: segment %d: malformed chunk_id", seg.SegmentIndex)
			}
			buf = append(buf, chunkIDBytes...)
		}
	}
	return buf, nil
}
