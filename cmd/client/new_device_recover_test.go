package main

// Tests for the new-device recovery capability, reached via `recover`'s
// network path (phone+OTP+passphrase, no --owner-id) — not a separate
// `login` subcommand; see account_cmds.go's runRecover/runNetworkRecover
// and dispatch.go's knownSubcommands for why that was decided against
// after MVP §8.3's fixed eight-name table turned out to matter (a real
// test, TestDispatchRecognisesAllEightSubcommands, already enforced it).
//
// Covers: a stored identity can now exist with no local Ed25519 keystore
// at all (storedIdentity.HasKeystore == false), every subcommand that
// doesn't need signing (retrieve, ls, rm, balance, deposit) keeps working
// from one, upload refuses cleanly instead of failing deep inside
// p2p.NewHost, and dispatchRecover's own flag validation now only
// requires --passphrase/--mnemonic upfront for the local (--owner-id)
// path — the network path prompts instead.
//
// [REF: this session's own account_cmds.go/identity.go/localstore.go/
// transfer_cmds.go header notes — not build.md-sourced]

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/account"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// TestWriteIdentityFileTokenOnlyRoundTrips is the base case: a token-only
// identity round-trips through disk with HasKeystore explicitly false and
// no keystore bytes at all — not empty-but-present ones, which would let
// decodeStoredKeystore's nonce-length check mask this as some other kind
// of failure instead of the "nothing to decrypt" case it actually is.
func TestWriteIdentityFileTokenOnlyRoundTrips(t *testing.T) {
	dataDir := t.TempDir()
	ownerID := uuid.New()

	if err := writeIdentityFileTokenOnly(dataDir, ownerID, "jwt-abc"); err != nil {
		t.Fatalf("writeIdentityFileTokenOnly: %v", err)
	}

	stored, err := readIdentityFile(dataDir)
	if err != nil {
		t.Fatalf("readIdentityFile: %v", err)
	}
	if stored == nil {
		t.Fatal("readIdentityFile returned nil after a successful write")
	}
	if stored.HasKeystore {
		t.Error("HasKeystore = true, want false for a token-only identity")
	}
	if stored.OwnerID != ownerID.String() {
		t.Errorf("OwnerID = %q, want %q", stored.OwnerID, ownerID.String())
	}
	if stored.Token != "jwt-abc" {
		t.Errorf("Token = %q, want %q", stored.Token, "jwt-abc")
	}
	if stored.KeystoreCiphertextHex != "" || stored.KeystoreNonceHex != "" {
		t.Errorf("expected empty keystore fields, got ciphertext=%q nonce=%q", stored.KeystoreCiphertextHex, stored.KeystoreNonceHex)
	}
}

// TestLoadIdentityToleratesTokenOnlyIdentity is the actual new-device
// case this whole session exists for: loadIdentity must succeed off a
// token-only identity (no local keystore ever existed here), returning a
// nil SigningKey rather than erroring — the precondition retrieve/ls/rm/
// balance/deposit all now depend on.
func TestLoadIdentityToleratesTokenOnlyIdentity(t *testing.T) {
	dataDir := t.TempDir()
	ownerID := uuid.New()
	if err := writeIdentityFileTokenOnly(dataDir, ownerID, "jwt-xyz"); err != nil {
		t.Fatalf("writeIdentityFileTokenOnly: %v", err)
	}

	profile := config.SelectProfile("demo")
	in := bufio.NewReader(strings.NewReader(""))
	var out bytes.Buffer

	id, err := loadIdentity(dataDir, "correct horse battery staple", "", in, &out, profile)
	if err != nil {
		t.Fatalf("loadIdentity on a token-only identity returned an error: %v", err)
	}
	if id.SigningKey != nil {
		t.Errorf("SigningKey = %x, want nil for a token-only identity", []byte(id.SigningKey))
	}
	if id.OwnerID != ownerID {
		t.Errorf("OwnerID = %s, want %s", id.OwnerID, ownerID)
	}
	if id.Token != "jwt-xyz" {
		t.Errorf("Token = %q, want %q", id.Token, "jwt-xyz")
	}
	var zero [32]byte
	if id.MasterSecret == zero {
		t.Error("MasterSecret is all-zero — RecoverFromPassphrase should have derived a real value")
	}
}

// TestLoadIdentityStillDecryptsRealKeystore pins the pre-existing
// behavior for a real (HasKeystore == true) identity, so the branch added
// for the token-only case can never accidentally swallow this one instead.
func TestLoadIdentityStillDecryptsRealKeystore(t *testing.T) {
	dataDir := t.TempDir()
	ownerID := uuid.New()
	profile := config.SelectProfile("demo")
	passphrase := "correct horse battery staple"

	masterSecret, err := account.RecoverFromPassphrase(ownerID, []byte(passphrase), profile)
	if err != nil {
		t.Fatalf("RecoverFromPassphrase (test setup): %v", err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey (test setup): %v", err)
	}
	ciphertext, nonce, err := account.EncryptKeystore(account.Keystore{PrivateKey: priv}, masterSecret, ownerID[:])
	if err != nil {
		t.Fatalf("EncryptKeystore (test setup): %v", err)
	}
	if err := writeIdentityFile(dataDir, ownerID, "jwt-real", ciphertext, nonce); err != nil {
		t.Fatalf("writeIdentityFile (test setup): %v", err)
	}

	in := bufio.NewReader(strings.NewReader(""))
	var out bytes.Buffer
	id, err := loadIdentity(dataDir, passphrase, "", in, &out, profile)
	if err != nil {
		t.Fatalf("loadIdentity on a real keystore returned an error: %v", err)
	}
	if !bytes.Equal(id.SigningKey, priv) {
		t.Error("SigningKey does not match the originally encrypted key")
	}
}

// TestP2PIdentityForRetrieveGeneratesEphemeralKeyWhenNil covers both
// halves of p2pIdentityForRetrieve: a present signing key passes through
// unchanged (retrieve on a device that DOES have one shouldn't start
// using a different, throwaway identity for no reason), and nil produces
// a fresh, valid Ed25519 key rather than a zero-value/invalid one that
// would fail inside p2p.NewHost's own length check.
func TestP2PIdentityForRetrieveGeneratesEphemeralKeyWhenNil(t *testing.T) {
	_, real, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey (test setup): %v", err)
	}
	got, err := p2pIdentityForRetrieve(real)
	if err != nil {
		t.Fatalf("p2pIdentityForRetrieve(real): %v", err)
	}
	if !bytes.Equal(got, real) {
		t.Error("p2pIdentityForRetrieve replaced a present signing key instead of passing it through")
	}

	ephemeral, err := p2pIdentityForRetrieve(nil)
	if err != nil {
		t.Fatalf("p2pIdentityForRetrieve(nil): %v", err)
	}
	if len(ephemeral) != ed25519.PrivateKeySize {
		t.Fatalf("ephemeral key length = %d, want %d", len(ephemeral), ed25519.PrivateKeySize)
	}
	// A second call must not reuse the first ephemeral key — it's meant
	// to be throwaway per invocation, not a stable substitute identity.
	ephemeral2, err := p2pIdentityForRetrieve(nil)
	if err != nil {
		t.Fatalf("p2pIdentityForRetrieve(nil) second call: %v", err)
	}
	if bytes.Equal(ephemeral, ephemeral2) {
		t.Error("two ephemeral keys were identical — expected fresh randomness per call")
	}
}

// TestDispatchUploadRefusesCleanlyWithoutSigningKey is the integration
// point: on a token-only identity, upload must fail with
// errNoSigningKeyForUpload's clear message and exit 1, and it must do so
// before ever touching the network — this test gives no reachable
// --microservice-url, so a pass here that ever got past the signing-key
// check would hang or fail with a network/dial error instead of the
// clean, immediate message asserted below.
func TestDispatchUploadRefusesCleanlyWithoutSigningKey(t *testing.T) {
	dataDir := t.TempDir()
	ownerID := uuid.New()
	if err := writeIdentityFileTokenOnly(dataDir, ownerID, "jwt-upload-test"); err != nil {
		t.Fatalf("writeIdentityFileTokenOnly: %v", err)
	}
	uploadFile := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(uploadFile, []byte("hello"), 0600); err != nil {
		t.Fatalf("write test payload: %v", err)
	}

	args := []string{
		"--microservice-url", "http://127.0.0.1:1",
		"--data-dir", dataDir,
		"--mode", "demo",
		"--passphrase", "correct horse battery staple",
		uploadFile,
	}
	var out, errOut bytes.Buffer
	code := dispatchUpload(args, strings.NewReader(""), &out, &errOut)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (got stdout=%q stderr=%q)", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "no local signing key") {
		t.Errorf("stderr = %q, want it to contain the clear no-signing-key message", errOut.String())
	}
}

// TestRecoverLocalPathStillRequiresPassphraseOrMnemonic pins
// dispatchRecover's one remaining hard upfront requirement: --owner-id
// (local, same-machine recovery, decrypting a keystore already on disk
// right now) still needs --passphrase or --mnemonic given as a flag,
// since there's no later point in that path to prompt for one. Purely
// local — no network touched, so this must return fast and deterministically.
func TestRecoverLocalPathStillRequiresPassphraseOrMnemonic(t *testing.T) {
	args := []string{
		"--microservice-url", "http://127.0.0.1:1",
		"--data-dir", t.TempDir(),
		"--mode", "demo",
		"--owner-id", uuid.New().String(),
	}
	var out, errOut bytes.Buffer
	code := dispatchRecover(args, strings.NewReader(""), &out, &errOut)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d (usage error) — got stderr=%q", code, exitUsage, errOut.String())
	}
	if !strings.Contains(errOut.String(), "requires --passphrase or --mnemonic") {
		t.Errorf("stderr = %q, want it to explain --passphrase/--mnemonic is required", errOut.String())
	}
}

// TestRecoverNetworkPathAcceptsMissingPassphraseFlag is the Option-B
// behavior this session settled on instead of a separate `login`
// subcommand: on the network path (no --owner-id), leaving out both
// --passphrase and --mnemonic must NOT be a usage error the way it still
// is for --owner-id above — it should fall through to
// runNetworkRecover's own passphrase prompt. This test can't complete a
// real recovery (no mock coordinator here — SendOTP hits a real,
// deliberately-closed port), but that's the point: reaching a network
// error (exit 1) rather than a usage error (exit 2, with the
// "requires --passphrase or --mnemonic" message) is sufficient proof
// that validation let it through.
func TestRecoverNetworkPathAcceptsMissingPassphraseFlag(t *testing.T) {
	args := []string{
		"--microservice-url", "http://127.0.0.1:1",
		"--data-dir", t.TempDir(),
		"--mode", "demo",
		"--phone", "9876543210",
	}
	// Answers the passphrase prompt (runNetworkRecover, before SendOTP)
	// so the failure actually observed is SendOTP's connection-refused
	// error, not promptLine's own EOF error — both are exit 1, but only
	// the former proves the flag-validation relaxation is what let this
	// through, rather than an unrelated early failure that happens to
	// share the same exit code.
	stdin := strings.NewReader("a-fake-test-passphrase\n")
	var out, errOut bytes.Buffer
	code := dispatchRecover(args, stdin, &out, &errOut)

	if code == exitUsage {
		t.Fatalf("got a usage error — the network path should not require --passphrase/--mnemonic upfront (stderr=%q)", errOut.String())
	}
	if strings.Contains(errOut.String(), "requires --passphrase or --mnemonic") {
		t.Errorf("stderr = %q, should not contain the local-path-only requirement message", errOut.String())
	}
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (a network failure against the deliberately-unreachable port) — stderr=%q", code, errOut.String())
	}
}