// Package account is declared in doc.go.
// This file implements Register(): local-crypto account creation only.
//
// [Design note] IC §5.9 gives an UploadOrchestrator interface for the
// upload/retrieve packages but no equivalent AccountManager interface for
// this package — this session's exported surface (Identity, Register,
// ConfirmMnemonic, Keystore, Recover*) is authored here, guided by IC §5.1's
// crypto primitives and this session's five numbered TASK steps, not copied
// from a pre-existing interface contract.
//
// Register does NOT call POST /api/v1/owner/register or run the phone/OTP
// flow — this session's own IMPORT_CONSTRAINTS restrict this package to
// config+crypto only (no net/http-worthy internal/ package, no p2p), and
// the TASK text's step 1 is exactly "generate an Ed25519 key pair; derive
// the master secret", nothing about a network round-trip. ownerID is
// therefore a pre-condition here — obtained by the caller from the OTP
// registration flow (not yet wired anywhere in this codebase; cmd/client's
// main.go is still a stub pending later wiring) before Register is called.
//
// [REF: IC §5.1 DeriveMasterSecret/MasterSecretToMnemonic, ADR-031,
// MVP §8.2 Phase 15.1 Session 15.1.1]

package account

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	"github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
)

// Identity is the local result of Register(): a fresh Ed25519 keypair, the
// Argon2id-derived master secret, and the mnemonic backup phrase. Held in
// memory only by the caller (master_secret.go) — never persisted as-is;
// keystore.go's Keystore is the on-disk encrypted form of the key material
// alone (the mnemonic itself is never persisted, encrypted or not — a data
// owner's only durable copy is what they wrote down when it was displayed).
type Identity struct {
	PublicKey    ed25519.PublicKey
	PrivateKey   ed25519.PrivateKey
	MasterSecret [32]byte
	Mnemonic     []string // 24 BIP-39 words; display once, never persist verbatim
}

// Register generates a new Ed25519 key pair and derives ownerID's master
// secret from passphrase, using the active NetworkProfile's Argon2id cost
// parameters — profile.Argon2Time/Argon2Memory/Argon2Threads are always
// read from the active NetworkProfile, never hardcoded (ADR-031; IC §5.1's
// own caller-responsibility note on DeriveMasterSecret).
//
// Pre-conditions:
//   - ownerID has already been obtained from the server (phone/OTP
//     registration flow) — Register makes no network call itself.
//   - len(passphrase) >= 8 (crypto.DeriveMasterSecret's own pre-condition;
//     violating it panics, per that function's documented contract)
//
// Post-conditions (on nil error):
//   - a fresh Ed25519 key pair is generated via crypto/rand
//   - Identity.MasterSecret is deterministic for (passphrase, ownerID,
//     profile's three Argon2 parameters) — recover.go's passphrase path
//     reproduces it exactly given the same profile
//   - Identity.Mnemonic encodes MasterSecret directly (round-trips via
//     crypto.MnemonicToMasterSecret); the caller must display it and run
//     ConfirmMnemonic (mnemonic.go) before treating registration as done
//
// Goroutine-safe: yes.
func Register(ownerID uuid.UUID, passphrase []byte, profile config.NetworkProfile) (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("account: Register: generate Ed25519 key: %w", err)
	}

	// Read explicitly off the active NetworkProfile — never hardcoded
	// (ADR-031) — one line per parameter so this reflects three
	// independent reads, not one call site that happens to touch all three.
	argon2Time := profile.Argon2Time
	argon2Memory := profile.Argon2Memory
	argon2Threads := profile.Argon2Threads
	masterSecret := crypto.DeriveMasterSecret(passphrase, ownerID[:],
		argon2Time, argon2Memory, argon2Threads)

	mnemonic, err := crypto.MasterSecretToMnemonic(masterSecret)
	if err != nil {
		return Identity{}, fmt.Errorf("account: Register: encode mnemonic: %w", err)
	}

	return Identity{
		PublicKey:    pub,
		PrivateKey:   priv,
		MasterSecret: masterSecret,
		Mnemonic:     mnemonic,
	}, nil
}