// Package audit is declared in doc.go.
// Unit tests for ValidateResponse.
//
// Tests:
//   - TestValidateResponseAccepts                    correct signature over the correct field order -> nil
//   - TestValidateResponseRejectsBadSignature         tampered signature -> ErrInvalidSignature
//   - TestValidateResponseRejectsWrongPubKey          signature from a different key pair -> ErrInvalidSignature
//   - TestValidateResponseSigningInputIsFixedLayout   reordering the four signed fields breaks verification
//
// TestValidateResponseRejectsBadNonceLength is not implemented as a runtime
// test: challengeNonce is declared [33]byte in both IC §5.5's original
// ValidateResponse signature and the Phase 7.2 corrected one in validate.go,
// so a wrong-length nonce is a compile error at the call site, never a
// condition ValidateResponse could observe at runtime — the same situation
// as ChallengeNonce's chunkID parameter (Session 7.1.1). ErrNonceLength
// remains exported as the sentinel this check would return if the parameter
// were ever widened to []byte; see validate.go's doc comment for the same
// note on the production-code side.
//
// [REF: IC §5.5, IC §4.2, IC §3.2, NFR-015, build.md Phase 7.2 Session 7.2.1]

package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
)

// vrNonce is a 33-byte test challenge nonce fixture.
var vrNonce = [33]byte{
	0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
	0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
	0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
	0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
	0xbf,
}

// vrResponseHash is a 32-byte test response_hash fixture.
var vrResponseHash = [32]byte{
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
}

// vrProviderID is a 16-byte test provider UUID fixture.
var vrProviderID = [16]byte{
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
}

const vrServerTsMs int64 = 1_752_100_000_000

// signValidResponse builds the canonical IC §4.2 Frame 2 signing input for
// the given fields (responseHash || nonce || big-endian ts || providerID)
// and signs it with priv via crypto.SignBytes — the exact construction a
// real provider daemon performs, and the same one ValidateResponse itself
// reconstructs to verify against.
func signValidResponse(t *testing.T, priv ed25519.PrivateKey, responseHash [32]byte, nonce [33]byte, serverTsMs int64, providerID [16]byte) [64]byte {
	t.Helper()
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(serverTsMs))

	input := make([]byte, 0, len(responseHash)+len(nonce)+len(tsBytes)+len(providerID))
	input = append(input, responseHash[:]...)
	input = append(input, nonce[:]...)
	input = append(input, tsBytes[:]...)
	input = append(input, providerID[:]...)

	return crypto.SignBytes(priv, input)
}

// TestValidateResponseAccepts verifies that a genuine signature — built the
// same way a real provider daemon would build one — is accepted.
//
// [REF: build.md Phase 7.2 Session 7.2.1]
func TestValidateResponseAccepts(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)

	sig := signValidResponse(t, priv, vrResponseHash, vrNonce, vrServerTsMs, vrProviderID)

	if err := ValidateResponse(vrNonce, vrResponseHash, vrServerTsMs, vrProviderID, sig, pubArr); err != nil {
		t.Errorf("ValidateResponse: got %v, want nil for a genuinely signed response", err)
	}
}

// TestValidateResponseRejectsBadSignature verifies that tampering with any
// byte of an otherwise-valid signature causes rejection.
//
// [REF: NFR-015, build.md Phase 7.2 Session 7.2.1]
func TestValidateResponseRejectsBadSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)

	sig := signValidResponse(t, priv, vrResponseHash, vrNonce, vrServerTsMs, vrProviderID)
	sig[0] ^= 0xFF // flip the first byte of an otherwise-valid signature

	err = ValidateResponse(vrNonce, vrResponseHash, vrServerTsMs, vrProviderID, sig, pubArr)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("tampered signature: got %v, want ErrInvalidSignature", err)
	}
}

// TestValidateResponseRejectsWrongPubKey verifies that a genuinely valid
// signature from one key pair is rejected when checked against a different
// provider's public key.
//
// [REF: IC §3.2 verification procedure, build.md Phase 7.2 Session 7.2.1]
func TestValidateResponseRejectsWrongPubKey(t *testing.T) {
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey A: %v", err)
	}
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey B: %v", err)
	}
	var pubArrB [32]byte
	copy(pubArrB[:], pubB)

	sig := signValidResponse(t, privA, vrResponseHash, vrNonce, vrServerTsMs, vrProviderID)

	err = ValidateResponse(vrNonce, vrResponseHash, vrServerTsMs, vrProviderID, sig, pubArrB)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("signature from a different key pair: got %v, want ErrInvalidSignature", err)
	}
}

// TestValidateResponseSigningInputIsFixedLayout verifies that the signing
// input is field-order-sensitive: a signature computed over the same four
// field values concatenated in a DIFFERENT order fails to verify, proving
// ValidateResponse reconstructs the exact IC §4.2 Frame 2 field order
// (responseHash || challengeNonce || serverChallengeTsMs || providerID)
// rather than some order-insensitive combination.
//
// [REF: IC §3.2, IC §4.2, build.md Phase 7.2 Session 7.2.1]
func TestValidateResponseSigningInputIsFixedLayout(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)

	// Baseline: the correct field order must verify.
	correctSig := signValidResponse(t, priv, vrResponseHash, vrNonce, vrServerTsMs, vrProviderID)
	if err := ValidateResponse(vrNonce, vrResponseHash, vrServerTsMs, vrProviderID, correctSig, pubArr); err != nil {
		t.Fatalf("baseline: signature over the correct field order was rejected: %v", err)
	}

	// Reordered: challengeNonce || responseHash || providerID || ts.
	// Same four values, different concatenation order.
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(vrServerTsMs))
	reordered := make([]byte, 0, len(vrNonce)+len(vrResponseHash)+len(vrProviderID)+len(tsBytes))
	reordered = append(reordered, vrNonce[:]...)
	reordered = append(reordered, vrResponseHash[:]...)
	reordered = append(reordered, vrProviderID[:]...)
	reordered = append(reordered, tsBytes[:]...)
	wrongOrderSig := crypto.SignBytes(priv, reordered)

	err = ValidateResponse(vrNonce, vrResponseHash, vrServerTsMs, vrProviderID, wrongOrderSig, pubArr)
	if err == nil {
		t.Error("signature computed over a reordered field sequence was accepted — signing input is not field-order-sensitive")
	}
}
