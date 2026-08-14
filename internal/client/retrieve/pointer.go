// Package retrieve is declared in doc.go.
// This file implements pointer-file fetch and decryption (TASK step 1) and
// the small authenticated-JSON HTTP helper this package's REST calls share
// — a package-local twin of internal/client/upload's own apiClient
// (Milestone 15 Session 15.2.1): apiClient is unexported there, so it
// cannot be imported here even though the two packages are siblings; see
// that file's header comment for the same "no existing HTTP client
// convention anywhere in this codebase" note this mirrors.
//
// Also decodes the pointer-file plaintext blob back into segments — a
// package-local twin of internal/client/upload/pointer.go's
// marshalPointerFilePlaintext, in reverse. [Flagged] This is real, tight
// coupling, not superficial similarity: the two encodings MUST match
// byte-for-byte forever, and duplicating the layout logic in two packages
// (because upload's version is unexported and this session's FILES scope
// doesn't include editing upload/pointer.go to export it) carries a real
// drift risk if one side is ever changed without the other. Promoting this
// to one shared, exported definition is worth a future session.
//
// [REF: IC §5.9 RetrieveFile pre-conditions, IC §5.1 DerivePointerEncKey/
// DecryptPointerFile, OAS PointerFileResponse, MVP §8.2 Phase 15.3
// Session 15.3.1, FR-015]

package retrieve

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
)

// ── Shared authenticated-JSON HTTP client (package-local twin) ────────────

const (
	uuidSize              = 16
	uint32Size            = 4
	fileKeySize           = 32
	chunkIDSize           = 32
	numSegmentsHeaderSize = 4
)

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newAPIClient(baseURL, token string, httpClient *http.Client) *apiClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &apiClient{baseURL: baseURL, token: token, http: httpClient}
}

type apiError struct {
	ErrorCode  string `json:"error_code"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
	RetryAfter *int   `json:"retry_after"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s: %s (request_id=%s)", e.ErrorCode, e.Message, e.RequestID)
}

func (c *apiClient) doJSON(ctx context.Context, method, path string, reqBody, out any) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, nil, fmt.Errorf("retrieve: doJSON: encode request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("retrieve: doJSON: build request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("retrieve: doJSON: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("retrieve: doJSON: read response body: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp, respBody, fmt.Errorf("retrieve: doJSON: decode response: %w", err)
		}
	}
	return resp, respBody, nil
}

func decodeAPIError(body []byte) *apiError {
	var apiErr apiError
	if err := json.Unmarshal(body, &apiErr); err != nil || apiErr.ErrorCode == "" {
		return nil
	}
	return &apiErr
}

// ── pointer-file plaintext types (package-local twin of upload's) ─────────

type erasureParamsInfo struct {
	S       int
	R       int
	N       int
	LfBytes int
}

type pointerFileSegment struct {
	SegmentID     uuid.UUID
	SegmentIndex  int
	FileKey       string
	ProviderIDs   []uuid.UUID
	ChunkIDs      []string
	ErasureParams erasureParamsInfo
}

type pointerFilePlaintext struct {
	Segments []pointerFileSegment
}

// unmarshalPointerFilePlaintext decodes the fixed-layout binary blob
// internal/client/upload/pointer.go's marshalPointerFilePlaintext produces
// — see that function's doc comment for the exact layout this mirrors:
//
//	num_segments(4)
//	segments[num_segments]:
//	  segment_id(16) segment_index(4) file_key(32)
//	  erasure_s(4) erasure_r(4) erasure_n(4) erasure_lf_bytes(4)
//	  provider_ids[erasure_n](16 bytes each, shard_index order)
//	  chunk_ids[erasure_n](32 bytes each, shard_index order)
func unmarshalPointerFilePlaintext(data []byte) (pointerFilePlaintext, error) {
	if len(data) < numSegmentsHeaderSize {
		return pointerFilePlaintext{}, fmt.Errorf("unmarshalPointerFilePlaintext: too short for num_segments header")
	}
	numSegments := binary.BigEndian.Uint32(data[0:4])
	offset := numSegmentsHeaderSize

	segments := make([]pointerFileSegment, 0, numSegments)
	for i := uint32(0); i < numSegments; i++ {
		const fixedHeaderSize = uuidSize + uint32Size + fileKeySize + uint32Size + uint32Size + uint32Size + uint32Size
		if offset+fixedHeaderSize > len(data) {
			return pointerFilePlaintext{}, fmt.Errorf("unmarshalPointerFilePlaintext: segment %d: truncated fixed header", i)
		}
		var segID uuid.UUID
		copy(segID[:], data[offset:offset+16])
		offset += 16
		segIndex := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		fileKeyBytes := data[offset : offset+32]
		offset += 32
		s := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		r := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		n := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		lf := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		needed := int(n)*uuidSize + int(n)*chunkIDSize
		if offset+needed > len(data) {
			return pointerFilePlaintext{}, fmt.Errorf("unmarshalPointerFilePlaintext: segment %d: truncated provider/chunk IDs", i)
		}
		providerIDs := make([]uuid.UUID, n)
		for j := uint32(0); j < n; j++ {
			copy(providerIDs[j][:], data[offset:offset+16])
			offset += 16
		}
		chunkIDs := make([]string, n)
		for j := uint32(0); j < n; j++ {
			chunkIDs[j] = fmt.Sprintf("%x", data[offset:offset+32])
			offset += 32
		}

		segments = append(segments, pointerFileSegment{
			SegmentID:    segID,
			SegmentIndex: int(segIndex),
			FileKey:      fmt.Sprintf("%x", fileKeyBytes),
			ProviderIDs:  providerIDs,
			ChunkIDs:     chunkIDs,
			ErasureParams: erasureParamsInfo{
				S: int(s), R: int(r), N: int(n), LfBytes: int(lf),
			},
		})
	}
	return pointerFilePlaintext{Segments: segments}, nil
}

// ── GET /api/v1/file/{file_id}/pointer ─────────────────────────────────────

type pointerFileResponse struct {
	FileID                uuid.UUID `json:"file_id"`
	PointerCiphertext     string    `json:"pointer_ciphertext"`
	PointerNonce          string    `json:"pointer_nonce"`
	PointerTag            string    `json:"pointer_tag"`
	SchemaVersion         int       `json:"schema_version"`
	OriginalSizeBytes     int64     `json:"original_size_bytes"`
	DisplayNameCiphertext *string   `json:"display_name_ciphertext,omitempty"`
	DisplayNameNonce      *string   `json:"display_name_nonce,omitempty"`
	DisplayNameTag        *string   `json:"display_name_tag,omitempty"`
}

// pointerFileSchemaVersion mirrors upload/pointer.go's own constant — the
// AAD reconstruction below must use the SAME fixed value encryption used,
// not blindly trust whatever schema_version the server returns (a future
// schema_version > 1 should fail closed against an old client, not silently
// change what AAD this client reconstructs).
const pointerFileSchemaVersion = 1

// pointerAAD is the AEAD associated data — a package-local twin of
// upload/pointer.go's own pointerAAD; must match byte-for-byte or every
// decryption fails closed with ErrPointerTagMismatch (the whole point of
// an AAD binding).
func pointerAAD(ownerID, fileID uuid.UUID) []byte {
	var schemaVersionBytes [4]byte
	aad := make([]byte, 0, len(ownerID)+len(fileID)+len(schemaVersionBytes))
	aad = append(aad, ownerID[:]...)
	aad = append(aad, fileID[:]...)
	binary.BigEndian.PutUint32(schemaVersionBytes[:], pointerFileSchemaVersion)
	aad = append(aad, schemaVersionBytes[:]...)
	return aad
}

// fetchAndDecryptPointerFile calls GET /api/v1/file/{file_id}/pointer,
// derives the pointer key via crypto.DerivePointerEncKey, and calls
// crypto.DecryptPointerFile. On crypto.ErrTagMismatch, returns
// ErrPointerTagMismatch with NO plaintext returned under any circumstance
// (IC §5.9, IC §5.1).
func (o *Orchestrator) fetchAndDecryptPointerFile(ctx context.Context, masterSecret [32]byte, ownerID, fileID uuid.UUID) (pointerFilePlaintext, int64, error) {
	var resp pointerFileResponse
	httpResp, rawBody, err := o.api.doJSON(ctx, http.MethodGet, "/api/v1/file/"+fileID.String()+"/pointer", nil, &resp)
	if err != nil {
		return pointerFilePlaintext{}, 0, fmt.Errorf("retrieve: fetchAndDecryptPointerFile: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return pointerFilePlaintext{}, 0, fmt.Errorf("retrieve: fetchAndDecryptPointerFile: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return pointerFilePlaintext{}, 0, fmt.Errorf("retrieve: fetchAndDecryptPointerFile: unexpected status %d", httpResp.StatusCode)
	}
	if resp.SchemaVersion != pointerFileSchemaVersion {
		return pointerFilePlaintext{}, 0, fmt.Errorf("retrieve: fetchAndDecryptPointerFile: unsupported schema_version %d", resp.SchemaVersion)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(resp.PointerCiphertext)
	if err != nil {
		return pointerFilePlaintext{}, 0, fmt.Errorf("retrieve: fetchAndDecryptPointerFile: decode pointer_ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(resp.PointerNonce)
	if err != nil || len(nonce) != 12 {
		return pointerFilePlaintext{}, 0, fmt.Errorf("retrieve: fetchAndDecryptPointerFile: malformed pointer_nonce")
	}
	tag, err := base64.StdEncoding.DecodeString(resp.PointerTag)
	if err != nil || len(tag) != 16 {
		return pointerFilePlaintext{}, 0, fmt.Errorf("retrieve: fetchAndDecryptPointerFile: malformed pointer_tag")
	}
	var nonceArr [12]byte
	copy(nonceArr[:], nonce)

	key := crypto.DerivePointerEncKey(masterSecret[:], ownerID[:], fileID[:])
	full := append(append([]byte{}, ciphertext...), tag...)

	decrypted, err := crypto.DecryptPointerFile(key, nonceArr, pointerAAD(ownerID, fileID), full)
	if err != nil {
		if errors.Is(err, crypto.ErrTagMismatch) {
			return pointerFilePlaintext{}, 0, ErrPointerTagMismatch
		}
		return pointerFilePlaintext{}, 0, fmt.Errorf("retrieve: fetchAndDecryptPointerFile: %w", err)
	}

	plain, err := unmarshalPointerFilePlaintext(decrypted)
	if err != nil {
		return pointerFilePlaintext{}, 0, fmt.Errorf("retrieve: fetchAndDecryptPointerFile: %w", err)
	}
	return plain, resp.OriginalSizeBytes, nil
}
