// Package account is declared in doc.go.
// This file implements the encrypted local keystore (TASK step 4):
// crypto.DeriveKeystoreEncKey(masterSecret, ownerID) protects the Ed25519
// identity key and the pointer-file AEAD's monotone nonce counter (IC §5.1
// EncryptPointerFile: "12-byte (96-bit) monotone counter nonce ... MUST be
// unique per (key, nonce) pair. Counter incremented before each write.") so
// a crash-and-restart can never reuse a nonce under the same pointer-file
// key.
//
// [Flagged] The session's TASK step 4 cites "IC §2.5's monotone counter"
// for this field's exact representation; IC §2.5 is not present in this
// session's given reference material. This file takes EncryptPointerFile's
// own phrase — "12-byte (96-bit) monotone counter nonce" — at its most
// literal reading: the full 12 bytes ARE the counter (one big-endian 96-bit
// integer), not a 96-bit field containing a smaller counter plus a fixed or
// random prefix. Flagged for reconciliation against the actual IC §2.5 text
// once available, per this project's standing practice of flagging
// cross-document gaps rather than silently picking an interpretation and
// treating it as settled.
//
// [REF: IC §5.1 DeriveKeystoreEncKey/EncryptAEAD/DecryptAEAD,
// MVP §8.2 Phase 15.1 Session 15.1.1]
// Field-naming note: this session's task text refers to the counter as
// "pointerNonce"/the "nonceCounter"; exported below as NonceCounter per Go
// convention for exported struct fields — same value, Go-idiomatic name.

package account

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"

	"github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
)

// Keystore is the plaintext shape of the local keystore, held in memory
// only for as long as a session needs it — see master_secret.go for the
// same discipline applied to the master secret that protects it.
type Keystore struct {
	PrivateKey   ed25519.PrivateKey
	NonceCounter [12]byte // pointer-file AEAD monotone counter; see header note
}

// keystoreAAD is the fixed AAD for the keystore's own AEAD envelope. Uses
// EncryptAEAD directly, not EncryptPointerFile — the keystore is not the
// pointer-file artifact EncryptPointerFile's stricter precondition
// documents; its own doc comment steers any other artifact (this one
// included) to EncryptAEAD directly rather than repurposing
// EncryptPointerFile with an unrelated AAD string.
var keystoreAAD = []byte("vyomanaut-keystore-v1")

// EncryptKeystore serialises and encrypts ks under
// crypto.DeriveKeystoreEncKey(masterSecret, ownerID), returning a freshly
// generated random 12-byte nonce alongside the ciphertext. Unlike the
// pointer file (re-encrypted repeatedly under one fixed key across a
// session, hence its monotone-counter nonce requirement), the keystore is
// written once per change with a fresh random nonce each time — EncryptAEAD's
// baseline nonce contract, not the pointer file's stricter one.
//
// Goroutine-safe: yes.
func EncryptKeystore(ks Keystore, masterSecret [32]byte, ownerID []byte) (ciphertext []byte, nonce [12]byte, err error) {
	if _, err := cryptorand.Read(nonce[:]); err != nil {
		return nil, nonce, fmt.Errorf("account: EncryptKeystore: generate nonce: %w", err)
	}
	key := crypto.DeriveKeystoreEncKey(masterSecret[:], ownerID)
	plaintext := serializeKeystore(ks)
	ciphertext, err = crypto.EncryptAEAD(key, nonce, keystoreAAD, plaintext)
	if err != nil {
		return nil, nonce, fmt.Errorf("account: EncryptKeystore: %w", err)
	}
	return ciphertext, nonce, nil
}

// DecryptKeystore reverses EncryptKeystore.
//
// Error semantics:
//   - crypto.ErrTagMismatch: wrong master secret or a corrupted keystore
//     file; no plaintext is returned.
//
// Goroutine-safe: yes.
func DecryptKeystore(ciphertext []byte, nonce [12]byte, masterSecret [32]byte, ownerID []byte) (Keystore, error) {
	key := crypto.DeriveKeystoreEncKey(masterSecret[:], ownerID)
	plaintext, err := crypto.DecryptAEAD(key, nonce, keystoreAAD, ciphertext)
	if err != nil {
		return Keystore{}, fmt.Errorf("account: DecryptKeystore: %w", err)
	}
	return deserializeKeystore(plaintext)
}

// IncrementNonceCounter advances ks.NonceCounter by one, treating the full
// 12 bytes as a single big-endian 96-bit integer (see this file's header
// note). Must be called — and the keystore re-persisted via EncryptKeystore
// — BEFORE each EncryptPointerFile call (IC §5.1: "caller increments
// BEFORE this call").
func (ks *Keystore) IncrementNonceCounter() {
	for i := len(ks.NonceCounter) - 1; i >= 0; i-- {
		ks.NonceCounter[i]++
		if ks.NonceCounter[i] != 0 {
			return // no carry into the next byte
		}
	}
	// All 2^96 values exhausted — at 10^9 increments/sec this takes far
	// longer than the age of the universe; wraps to zero rather than
	// panicking, since a hard failure here would itself be a worse outcome
	// than the (practically unreachable) nonce reuse it would be guarding
	// against.
}

// serializeKeystore/deserializeKeystore use a fixed-layout byte encoding —
// never JSON. IC §11's forbidden-pattern rule states this for Ed25519
// signing inputs specifically, but ed25519.PrivateKey is exactly the kind
// of fixed-length byte sequence that rule exists for, so the same
// discipline applies here even though this is a local, unsigned encoding.
func serializeKeystore(ks Keystore) []byte {
	buf := make([]byte, 0, ed25519.PrivateKeySize+len(ks.NonceCounter))
	buf = append(buf, ks.PrivateKey...)
	buf = append(buf, ks.NonceCounter[:]...)
	return buf
}

func deserializeKeystore(plaintext []byte) (Keystore, error) {
	want := ed25519.PrivateKeySize + len([12]byte{})
	if len(plaintext) != want {
		return Keystore{}, fmt.Errorf("account: deserializeKeystore: got %d bytes, want %d", len(plaintext), want)
	}
	ks := Keystore{
		PrivateKey: ed25519.PrivateKey(append([]byte(nil), plaintext[:ed25519.PrivateKeySize]...)),
	}
	copy(ks.NonceCounter[:], plaintext[ed25519.PrivateKeySize:])
	return ks, nil
}
