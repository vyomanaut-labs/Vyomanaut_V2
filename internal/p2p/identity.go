// Package p2p is declared in doc.go.
// This file implements Ed25519 key pair generation, encrypted persistence,
// and load-on-restart for the provider daemon's network identity.
//
// Per the substitution decision in doc.go, this uses crypto/ed25519 (stdlib)
// and this package's own PeerID (peerid.go) in place of
// github.com/libp2p/go-libp2p/core/crypto and core/peer — everything else in
// the original session design is unchanged: the keystore encryption key is
// still derived via crypto.DeriveKeystoreEncKey(masterSecret, ownerID), and
// the private key is still encrypted at rest with
// crypto.EncryptAEAD / DecryptAEAD (AEAD_CHACHA20_POLY1305) — not
// EncryptPointerFile/DecryptPointerFile, which are reserved for the pointer-
// file artifact specifically (M2 review §3).
//
// [REF: IC §3.2, IC §5.1, ARCH §13, build.md Phase 6.1 Session 6.1.3]

package p2p

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	localcrypto "github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
)

const identityFileName = "identity.key"

// ownerIDSize is the required byte length of ownerID: a raw UUID (IC §5.1
// convention shared with internal/crypto's HKDF functions).
const ownerIDSize = 16

// identityFileMode restricts the persisted identity file to owner-only
// read/write — it holds an encrypted Ed25519 private key.
const identityFileMode = 0600

// identityNonceSize is the ChaCha20-Poly1305 nonce length prepended to the
// on-disk ciphertext (RFC 8439 §2.3's 96-bit/12-byte nonce, matching
// internal/crypto.EncryptPointerFile's nonce parameter).
const identityNonceSize = 12

// identityAAD binds the encrypted identity file to its purpose, following the
// same "aad must include context" discipline as pointer-file encryption
// elsewhere in this project (IC §5.1).
var identityAAD = []byte("vyomanaut-identity-v1")

// LoadOrGenerateIdentity loads the provider's Ed25519 identity from
// dataDir/identity.key, or generates a new one if the file does not exist.
//
// The key file is encrypted with AEAD_CHACHA20_POLY1305 using a key derived
// from DeriveKeystoreEncKey(masterSecret, ownerID) (IC §3.2, IC §5.1).
//
// Returns the raw Ed25519 private key and the derived Peer ID
// (multihash(public_key), ARCH §13).
//
// Pre-conditions:
//   - len(ownerID) == 16 (UUID bytes)
//
// Error semantics:
//   - Returns a wrapped error on any I/O, decryption, or key-format failure.
//     All such failures are fatal at daemon startup — there is no partial or
//     degraded identity state to fall back to.
//
// [REF: IC §3.2, IC §5.1, build.md Phase 6.1 Session 6.1.3]
func LoadOrGenerateIdentity(
	dataDir string,
	masterSecret [32]byte,
	ownerID []byte, // 16-byte UUID bytes
) (ed25519.PrivateKey, PeerID, error) {
	if len(ownerID) != ownerIDSize {
		return nil, "", fmt.Errorf("p2p.LoadOrGenerateIdentity: ownerID must be %d bytes, got %d", ownerIDSize, len(ownerID))
	}

	encKey := localcrypto.DeriveKeystoreEncKey(masterSecret[:], ownerID)
	keyPath := filepath.Join(dataDir, identityFileName)

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return generateAndSaveIdentity(keyPath, encKey)
	}
	return loadIdentity(keyPath, encKey)
}

// generateAndSaveIdentity creates a new Ed25519 key pair, encrypts the
// private key, and persists it to keyPath with mode 0600 (owner-only).
func generateAndSaveIdentity(keyPath string, encKey [32]byte) (ed25519.PrivateKey, PeerID, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("p2p: generate Ed25519 key: %w", err)
	}

	var nonce [identityNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, "", fmt.Errorf("p2p: generate nonce: %w", err)
	}

	ciphertext, err := localcrypto.EncryptAEAD(encKey, nonce, identityAAD, priv)
	if err != nil {
		return nil, "", fmt.Errorf("p2p: encrypt identity: %w", err)
	}

	// File format: nonce(12) || ciphertext.
	blob := make([]byte, 0, len(nonce)+len(ciphertext))
	blob = append(blob, nonce[:]...)
	blob = append(blob, ciphertext...)
	if err := os.WriteFile(keyPath, blob, identityFileMode); err != nil {
		return nil, "", fmt.Errorf("p2p: write identity file: %w", err)
	}

	peerID, err := PeerIDFromEd25519PrivateKey(priv)
	if err != nil {
		return nil, "", fmt.Errorf("p2p: derive Peer ID: %w", err)
	}
	return priv, peerID, nil
}

// loadIdentity decrypts and loads an existing identity file.
func loadIdentity(keyPath string, encKey [32]byte) (ed25519.PrivateKey, PeerID, error) {
	blob, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("p2p: read identity file: %w", err)
	}
	if len(blob) < identityNonceSize {
		return nil, "", fmt.Errorf("p2p: identity file too short (%d bytes)", len(blob))
	}

	var nonce [identityNonceSize]byte
	copy(nonce[:], blob[:identityNonceSize])
	ciphertext := blob[identityNonceSize:]

	raw, err := localcrypto.DecryptAEAD(encKey, nonce, identityAAD, ciphertext)
	if err != nil {
		return nil, "", fmt.Errorf("p2p: decrypt identity: %w", err)
	}

	if len(raw) != ed25519.PrivateKeySize {
		return nil, "", fmt.Errorf("p2p: decrypted identity has length %d, want %d",
			len(raw), ed25519.PrivateKeySize)
	}

	priv := ed25519.PrivateKey(raw)
	peerID, err := PeerIDFromEd25519PrivateKey(priv)
	if err != nil {
		return nil, "", fmt.Errorf("p2p: derive Peer ID: %w", err)
	}
	return priv, peerID, nil
}
