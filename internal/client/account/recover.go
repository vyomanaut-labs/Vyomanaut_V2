// Package account is declared in doc.go.
// This file implements the two recovery paths (TASK step 5, FR-004):
// passphrase (re-running Register's own Argon2id derivation) and mnemonic
// (crypto.MnemonicToMasterSecret). On crypto.ErrInvalidMnemonic, surfaces
// the generic "Invalid recovery phrase" message without indicating which
// word failed, per IC §5.1's explicit timing-oracle warning on
// MnemonicToMasterSecret.
//
// [REF: IC §5.1 DeriveMasterSecret/MnemonicToMasterSecret,
// MVP §8.2 Phase 15.1 Session 15.1.1, FR-004]

package account

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	"github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
)

// ErrInvalidRecoveryPhrase is this package's user-facing sentinel for a
// failed mnemonic recovery — deliberately generic. Never names which word
// failed: RecoverFromMnemonic below doesn't even inspect which position(s)
// crypto.MnemonicToMasterSecret flagged internally, so there is nothing
// word-specific left to leak by the time this is returned (IC §5.1's own
// "do not expose which word failed (timing oracle)" instruction).
var ErrInvalidRecoveryPhrase = errors.New("account: invalid recovery phrase — please check your words and try again")

// RecoverFromPassphrase reproduces the master secret by re-running the same
// Argon2id derivation Register used (register.go step 1). Recovery via
// passphrase requires no stored secret at all — the deterministic
// derivation itself is the recovery, given the same ownerID, passphrase,
// and NetworkProfile Argon2 parameters originally used.
//
// The error return exists for API symmetry with RecoverFromMnemonic and
// future-proofing; DeriveMasterSecret itself never errors (pre-condition
// violations panic, per its own documented contract), so this is always
// nil today.
//
// Goroutine-safe: yes.
func RecoverFromPassphrase(ownerID uuid.UUID, passphrase []byte, profile config.NetworkProfile) ([32]byte, error) {
	return crypto.DeriveMasterSecret(passphrase, ownerID[:],
		profile.Argon2Time, profile.Argon2Memory, profile.Argon2Threads), nil
}

// RecoverFromMnemonic reproduces the master secret from a 24-word BIP-39
// backup phrase — the recovery path for an owner who has lost their
// passphrase but retained their mnemonic (FR-004).
//
// Error semantics:
//   - ErrInvalidRecoveryPhrase: wraps a crypto.ErrInvalidMnemonic failure
//     (wrong word count, unknown word, or BIP-39 checksum failure) behind
//     this package's generic message. See this var's own doc comment for
//     why no word-position detail is ever exposed.
//
// Goroutine-safe: yes.
func RecoverFromMnemonic(words []string) ([32]byte, error) {
	secret, err := crypto.MnemonicToMasterSecret(words)
	if err != nil {
		if errors.Is(err, crypto.ErrInvalidMnemonic) {
			return [32]byte{}, ErrInvalidRecoveryPhrase
		}
		return [32]byte{}, fmt.Errorf("account: RecoverFromMnemonic: %w", err)
	}
	return secret, nil
}