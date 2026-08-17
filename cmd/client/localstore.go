// Local on-disk persistence for the data owner's identity: the encrypted
// keystore (Ed25519 private key, AEAD-protected — see
// internal/client/account.EncryptKeystore/DecryptKeystore) plus session
// metadata (owner_id, current JWT). Deliberately a separate file from
// account_cmds.go: account_cmds.go's own VERIFY block forbids os.WriteFile
// and log./slog. calls in that specific file (MNEMONIC_NEVER_LOGGED_OR_
// SERIALISED, Session 17.1.1) — not because file I/O itself is
// forbidden, but so a mnemonic can never accidentally reach disk via a
// write call that file makes for an unrelated reason. This file writes
// only keystore ciphertext, nonces, owner_id, and JWTs — never a
// mnemonic word.
//
// [REF: MVP §8.3 --data-dir, internal/client/account/keystore.go,
// Design Council verdict "Owner Registration: Keypair/OwnerID Ordering"]
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

const (
	identityFileName           = "identity.json"
	pendingRegistrationFile    = "registration-pending.json"
	privateFilePermissions     = 0600
	privateDirectoryPermission = 0700
)

func ensureDataDir(dataDir string) error {
	if err := os.MkdirAll(dataDir, privateDirectoryPermission); err != nil {
		return fmt.Errorf("cmd/client: create data-dir %s: %w", dataDir, err)
	}
	return nil
}

// ── Final, completed identity (post successful register/recover) ──────────

type storedIdentity struct {
	OwnerID               string `json:"owner_id"`
	Token                 string `json:"token"`
	KeystoreNonceHex      string `json:"keystore_nonce_hex"`
	KeystoreCiphertextHex string `json:"keystore_ciphertext_hex"`
}

func identityFilePath(dataDir string) string {
	return filepath.Join(dataDir, identityFileName)
}

// writeIdentityFile persists ownerID/token/the already-encrypted keystore
// bytes. Never touches plaintext key material or the mnemonic — ciphertext
// and nonce are opaque bytes by the time they reach this function.
func writeIdentityFile(dataDir string, ownerID uuid.UUID, token string, ciphertext []byte, nonce [12]byte) error {
	if err := ensureDataDir(dataDir); err != nil {
		return err
	}
	rec := storedIdentity{
		OwnerID:               ownerID.String(),
		Token:                 token,
		KeystoreNonceHex:      hex.EncodeToString(nonce[:]),
		KeystoreCiphertextHex: hex.EncodeToString(ciphertext),
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("cmd/client: encode identity file: %w", err)
	}
	if err := os.WriteFile(identityFilePath(dataDir), data, privateFilePermissions); err != nil {
		return fmt.Errorf("cmd/client: write identity file: %w", err)
	}
	return nil
}

// readIdentityFile returns (nil, nil) if no identity file exists yet — an
// absent file is a normal, expected state (nothing registered on this
// data-dir yet), not an error.
func readIdentityFile(dataDir string) (*storedIdentity, error) {
	data, err := os.ReadFile(identityFilePath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cmd/client: read identity file: %w", err)
	}
	var rec storedIdentity
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("cmd/client: decode identity file: %w", err)
	}
	return &rec, nil
}

// decodeStoredKeystore turns a storedIdentity's hex fields back into the
// (ciphertext, nonce) pair account.DecryptKeystore expects.
func decodeStoredKeystore(rec storedIdentity) (ciphertext []byte, nonce [12]byte, err error) {
	ciphertext, err = hex.DecodeString(rec.KeystoreCiphertextHex)
	if err != nil {
		return nil, nonce, fmt.Errorf("cmd/client: decode keystore ciphertext: %w", err)
	}
	nonceBytes, err := hex.DecodeString(rec.KeystoreNonceHex)
	if err != nil || len(nonceBytes) != len(nonce) {
		return nil, nonce, fmt.Errorf("cmd/client: decode keystore nonce: %w", err)
	}
	copy(nonce[:], nonceBytes)
	return ciphertext, nonce, nil
}

// ── Orphan-detection marker (Design Council verdict item 3) ────────────────
//
// Written immediately after RegisterOwner succeeds server-side, before
// passphrase prompt / mnemonic confirmation / keystore encryption — any of
// which could still fail or be interrupted. If the process dies in that
// window, this file is the only local evidence the server already has an
// owner row for a keypair that was never locally persisted. Cleared once
// writeIdentityFile completes successfully.
//
// This briefly stores the raw, unencrypted Ed25519 private key on disk —
// a real, if narrow and short-lived, security trade-off, stated here
// rather than hidden. The window closes as soon as EncryptKeystore runs
// (register.go's runRegister does this immediately afterward).

type pendingRegistrationRecord struct {
	OwnerID       string `json:"owner_id"`
	Token         string `json:"token"`
	PublicKeyHex  string `json:"public_key_hex"`
	PrivateKeyHex string `json:"private_key_hex"`
}

func pendingRegistrationFilePath(dataDir string) string {
	return filepath.Join(dataDir, pendingRegistrationFile)
}

func writePendingRegistration(dataDir string, ownerID uuid.UUID, token string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	if err := ensureDataDir(dataDir); err != nil {
		return err
	}
	rec := pendingRegistrationRecord{
		OwnerID:       ownerID.String(),
		Token:         token,
		PublicKeyHex:  hex.EncodeToString(pub),
		PrivateKeyHex: hex.EncodeToString(priv),
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("cmd/client: encode pending-registration marker: %w", err)
	}
	if err := os.WriteFile(pendingRegistrationFilePath(dataDir), data, privateFilePermissions); err != nil {
		return fmt.Errorf("cmd/client: write pending-registration marker: %w", err)
	}
	return nil
}

// readPendingRegistration returns (nil, nil) if no marker exists — the
// normal, expected state.
func readPendingRegistration(dataDir string) (*pendingRegistrationRecord, error) {
	data, err := os.ReadFile(pendingRegistrationFilePath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cmd/client: read pending-registration marker: %w", err)
	}
	var rec pendingRegistrationRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("cmd/client: decode pending-registration marker: %w", err)
	}
	return &rec, nil
}

func clearPendingRegistration(dataDir string) error {
	err := os.Remove(pendingRegistrationFilePath(dataDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cmd/client: remove pending-registration marker: %w", err)
	}
	return nil
}
