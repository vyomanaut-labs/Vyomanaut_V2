// Package account is declared in doc.go.
// Unit tests for Register, ConfirmMnemonic, the keystore round-trip, and
// both recovery paths. No live database or network is needed — every
// exported function in this package is pure/local (IMPORT_CONSTRAINTS: only
// config+crypto).
//
// Tests:
//   - TestRegisterUsesProfileArgon2Params
//   - TestRegisterSkipsBlockingPromptInDemoOnly
//   - TestRegisterStillCallsSelectConfirmationWordsInDemo
//   - TestKeystoreRoundTripsEd25519KeyAndNonceCounter
//   - TestRecoverFromPassphraseReproducesMasterSecret
//   - TestRecoverFromMnemonicReproducesMasterSecret
//   - TestRecoverInvalidMnemonicDoesNotIdentifyFailingWord
//
// [REF: MVP §8.2 Phase 15.1 Session 15.1.1]

package account

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
)

func TestRegisterUsesProfileArgon2Params(t *testing.T) {
	ownerID := uuid.New()
	passphrase := []byte("correct horse battery staple")

	profileA := config.DemoProfile
	profileB := config.DemoProfile
	profileB.Argon2Time = profileA.Argon2Time + 1 // only the cost parameter differs

	idA, err := Register(ownerID, passphrase, profileA)
	if err != nil {
		t.Fatalf("Register (profileA): %v", err)
	}
	idB, err := Register(ownerID, passphrase, profileB)
	if err != nil {
		t.Fatalf("Register (profileB): %v", err)
	}
	if idA.MasterSecret == idB.MasterSecret {
		t.Fatal("MasterSecret identical across different profile.Argon2Time values — " +
			"Register is not threading the profile's Argon2 parameters through")
	}
}

func TestRegisterSkipsBlockingPromptInDemoOnly(t *testing.T) {
	ownerID := uuid.New()
	id, err := Register(ownerID, []byte("correct horse battery staple"), config.DemoProfile)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	profile := config.DemoProfile
	profile.SkipMnemonicConfirm = true

	// prompt is nil: if the blocking prompt were invoked despite
	// SkipMnemonicConfirm, this would panic on the nil call.
	if err := ConfirmMnemonic(id.Mnemonic, profile, nil); err != nil {
		t.Fatalf("ConfirmMnemonic in demo mode with nil prompt: %v", err)
	}
}

func TestRegisterStillCallsSelectConfirmationWordsInDemo(t *testing.T) {
	profile := config.DemoProfile
	profile.SkipMnemonicConfirm = true

	// A deliberately wrong-length mnemonic (23, not 24 words) violates
	// crypto.SelectConfirmationWords' own len(mnemonic)==24 pre-condition,
	// which panics per that function's documented contract. Only a genuine
	// call to SelectConfirmationWords can produce this panic — proving it
	// runs even though SkipMnemonicConfirm is true, per IC §5.1's own note
	// that the function "may still be called; the caller simply does not
	// block on user input."
	shortMnemonic := make([]string, 23)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected a panic from SelectConfirmationWords' own precondition check; " +
				"got none — SelectConfirmationWords was not actually called in demo mode")
		}
	}()
	_ = ConfirmMnemonic(shortMnemonic, profile, nil)
	t.Fatal("unreachable if SelectConfirmationWords was genuinely invoked")
}

func TestKeystoreRoundTripsEd25519KeyAndNonceCounter(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	var counter [12]byte
	if _, err := cryptorand.Read(counter[:]); err != nil {
		t.Fatalf("generate nonce counter: %v", err)
	}
	want := Keystore{PrivateKey: priv, NonceCounter: counter}

	var masterSecret [32]byte
	if _, err := cryptorand.Read(masterSecret[:]); err != nil {
		t.Fatalf("generate master secret: %v", err)
	}
	ownerID := uuid.New()

	ciphertext, nonce, err := EncryptKeystore(want, masterSecret, ownerID[:])
	if err != nil {
		t.Fatalf("EncryptKeystore: %v", err)
	}

	got, err := DecryptKeystore(ciphertext, nonce, masterSecret, ownerID[:])
	if err != nil {
		t.Fatalf("DecryptKeystore: %v", err)
	}

	if !bytes.Equal(got.PrivateKey, want.PrivateKey) {
		t.Errorf("PrivateKey did not round-trip")
	}
	if got.NonceCounter != want.NonceCounter {
		t.Errorf("NonceCounter did not round-trip: got %x, want %x", got.NonceCounter, want.NonceCounter)
	}

	// Wrong master secret must fail closed, not return plaintext.
	var wrongSecret [32]byte
	if _, err := cryptorand.Read(wrongSecret[:]); err != nil {
		t.Fatalf("generate wrong secret: %v", err)
	}
	if _, err := DecryptKeystore(ciphertext, nonce, wrongSecret, ownerID[:]); err == nil {
		t.Error("DecryptKeystore succeeded with the wrong master secret")
	}
}

func TestRecoverFromPassphraseReproducesMasterSecret(t *testing.T) {
	ownerID := uuid.New()
	passphrase := []byte("correct horse battery staple")

	id, err := Register(ownerID, passphrase, config.DemoProfile)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	recovered, err := RecoverFromPassphrase(ownerID, passphrase, config.DemoProfile)
	if err != nil {
		t.Fatalf("RecoverFromPassphrase: %v", err)
	}
	if recovered != id.MasterSecret {
		t.Error("RecoverFromPassphrase did not reproduce the original MasterSecret")
	}
}

func TestRecoverFromMnemonicReproducesMasterSecret(t *testing.T) {
	ownerID := uuid.New()
	id, err := Register(ownerID, []byte("correct horse battery staple"), config.DemoProfile)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	recovered, err := RecoverFromMnemonic(id.Mnemonic)
	if err != nil {
		t.Fatalf("RecoverFromMnemonic: %v", err)
	}
	if recovered != id.MasterSecret {
		t.Error("RecoverFromMnemonic did not reproduce the original MasterSecret")
	}
}

func TestRecoverInvalidMnemonicDoesNotIdentifyFailingWord(t *testing.T) {
	badMnemonic := make([]string, 24)
	for i := range badMnemonic {
		badMnemonic[i] = "abandon" // valid BIP-39 wordlist entries, wrong checksum
	}

	_, err := RecoverFromMnemonic(badMnemonic)
	if !errors.Is(err, ErrInvalidRecoveryPhrase) {
		t.Fatalf("RecoverFromMnemonic error = %v, want ErrInvalidRecoveryPhrase", err)
	}
	if err.Error() != ErrInvalidRecoveryPhrase.Error() {
		t.Errorf("error message = %q, want exactly the generic sentinel text (no word-position detail)", err.Error())
	}
}
