// Package audit is declared in doc.go.
// This file implements provider audit-response validation per IC §5.5 and
// IC §4.2 Frame 2. ValidateResponse is pure (no shared mutable state) and
// goroutine-safe.
//
// SIGNATURE NOTE: IC §5.5 declares a 4-parameter ValidateResponse, but IC
// §4.2 Frame 2's signing input requires server_challenge_ts_ms and
// provider_id, neither of which the 4-parameter form can supply. This file
// implements the corrected 6-parameter signature the Phase 7.2 build.md
// preamble resolves the gap with, matching IC §4.2's wire fields exactly.
// interface-contracts.md itself still needs updating to match — flagged for
// a follow-up PR, not this session.
//
// [REF: IC §5.5, IC §4.2, IC §3.2, NFR-015]

package audit

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
)

// ── Layout sizes ───────────────────────────────────────────────────────────

const (
	// responseHashSize is the byte length of the response_hash field
	// (SHA-256 output) — IC §4.2 Frame 2.
	responseHashSize = sha256.Size

	// challengeNonceSize is the byte length of a challenge nonce: 1 version
	// byte + 32-byte HMAC-SHA256 output (DM §3 Invariant 5). Matches the
	// fixed [33]byte parameter type below.
	challengeNonceSize = 33

	// providerIDSize is the byte length of a provider_id: raw UUID bytes,
	// matching the IC §4.1 capability-token convention.
	providerIDSize = 16

	// ── Field offsets within the fixed-layout signing input ──────────────
	// IC §4.2 Frame 2 field order: response_hash || challenge_nonce ||
	// server_challenge_ts_ms || provider_id. The 8-byte timestamp width
	// reuses serverTsSize, already declared in challenge.go.
	nonceOffset      = responseHashSize
	tsOffset         = nonceOffset + challengeNonceSize
	idOffset         = tsOffset + serverTsSize
	signingInputSize = idOffset + providerIDSize
)

// ValidateResponse verifies the structural and cryptographic properties of a
// provider's audit response that the microservice CAN verify without
// holding chunk_data (IC §5.5, IC §4.2):
//
//  1. len(challengeNonce) == 33 — enforced by the compiler via the fixed
//     [33]byte parameter type (the same pattern as ChallengeNonce's chunkID
//     in challenge.go), so this can never fail at runtime. ErrNonceLength
//     stays exported as the sentinel this condition would return if
//     challengeNonce were ever widened to a []byte parameter; it is
//     unreachable given the signature actually declared here.
//  2. providerSig is a valid Ed25519 signature by providerPubKey over
//     SHA-256(responseHash || challengeNonce || serverChallengeTsMs ||
//     providerID) — IC §4.2 Frame 2, IC §3.2. Returns ErrInvalidSignature
//     on failure.
//
// NOTE — secret-version currency (IC §5.5 item 2, "challengeNonce[0]
// identifies a currently-valid secret version") is NOT checked here. This
// function has no reference to ClusterSecretCache. The caller MUST
// additionally call ClusterSecretCache.IsVersionValid(challengeNonce[0])
// (Phase 7.4) — a nil error from this function alone is not sufficient to
// accept the response.
//
// LIMITATION (IC §5.5, NFR-015): the microservice cannot verify that
// responseHash == SHA-256(chunkData || challengeNonce) because it never
// holds chunkData. Correctness depends on economic deterrence and JIT
// detection (ADR-014 Defence 3). This is a stated design property, not a
// gap to close.
//
// Signing input construction: the four fields are concatenated RAW, not
// pre-hashed, into a fixed 89-byte sequence, then passed directly to
// crypto.VerifyBytes — which applies SHA-256 internally per IC §3.2.
// Pre-hashing the sequence here first would double-hash the message and
// cause every genuine signature to fail.
//
// Pre-conditions:
//   - none beyond the fixed-size array types the compiler already enforces
//     on challengeNonce, responseHash, providerID, providerSig, and
//     providerPubKey.
//
// Error semantics:
//   - ErrInvalidSignature: providerSig does not verify against
//     providerPubKey for the reconstructed signing input.
//   - nil: signature verifies. Callers must still call
//     ClusterSecretCache.IsVersionValid before accepting the response — see
//     the NOTE above.
//
// Goroutine-safe: yes (pure function, no shared mutable state).
//
// [REF: IC §5.5, IC §4.2, IC §3.2, NFR-015]
func ValidateResponse(
	challengeNonce [33]byte,
	responseHash [32]byte,
	serverChallengeTsMs int64,
	providerID [16]byte,
	providerSig [64]byte,
	providerPubKey [32]byte,
) error {
	// signingInput = responseHash || challengeNonce ||
	// big-endian(serverChallengeTsMs) || providerID.
	var signingInput [signingInputSize]byte
	copy(signingInput[:nonceOffset], responseHash[:])
	copy(signingInput[nonceOffset:tsOffset], challengeNonce[:])
	binary.BigEndian.PutUint64(signingInput[tsOffset:idOffset], uint64(serverChallengeTsMs))
	copy(signingInput[idOffset:], providerID[:])

	if !crypto.VerifyBytes(providerPubKey, signingInput[:], providerSig) {
		return ErrInvalidSignature
	}
	return nil
}
