// Shared local-identity unlocking, used by every subcommand past register/
// recover: upload, retrieve (this session, 17.1.2) and ls/rm/balance/
// deposit (17.1.3) all need the same thing — decrypt the local keystore to
// get the owner's Ed25519 signing key, master secret, owner_id, and stored
// JWT before they can call into internal/client/{upload,retrieve,manage}.
// Factored out here rather than duplicated per subcommand file.
//
// [REF: internal/client/account/keystore.go DecryptKeystore,
// account/recover.go RecoverFromPassphrase/RecoverFromMnemonic]
package main

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/account"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// unlockedIdentity is everything a subcommand needs from the local
// identity once it's decrypted. MasterSecret is the caller's
// responsibility to zero (account.ZeroMasterSecret) once no longer
// needed — the same discipline internal/client/account itself applies.
type unlockedIdentity struct {
	OwnerID      uuid.UUID
	Token        string
	SigningKey   ed25519.PrivateKey
	MasterSecret [32]byte
}

// loadIdentity reads the local identity file, derives the master secret
// from passphrase or mnemonic (prompting for a passphrase if neither is
// given — this session's subcommands don't force a choice the way
// `recover` does, since a passphrase default is the common case for
// day-to-day use), and decrypts the local keystore to recover the Ed25519
// signing key.
func loadIdentity(dataDir, passphrase, mnemonic string, in *bufio.Reader, out io.Writer, profile config.NetworkProfile) (*unlockedIdentity, error) {
	stored, err := readIdentityFile(dataDir)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, fmt.Errorf("no local identity found at %s — run `register` first", identityFilePath(dataDir))
	}
	ownerID, err := uuid.Parse(stored.OwnerID)
	if err != nil {
		return nil, fmt.Errorf("cmd/client: stored identity has an invalid owner_id: %w", err)
	}

	if passphrase == "" && mnemonic == "" {
		passphrase, err = promptLine(out, in, "Passphrase to unlock local identity: ")
		if err != nil {
			return nil, err
		}
	}

	var masterSecret [32]byte
	if mnemonic != "" {
		masterSecret, err = account.RecoverFromMnemonic(strings.Fields(mnemonic))
	} else {
		masterSecret, err = account.RecoverFromPassphrase(ownerID, []byte(passphrase), profile)
	}
	if err != nil {
		return nil, err
	}

	ciphertext, nonce, err := decodeStoredKeystore(*stored)
	if err != nil {
		account.ZeroMasterSecret(&masterSecret)
		return nil, err
	}
	ks, err := account.DecryptKeystore(ciphertext, nonce, masterSecret, ownerID[:])
	if err != nil {
		account.ZeroMasterSecret(&masterSecret)
		return nil, fmt.Errorf("cmd/client: could not unlock the local keystore with the given passphrase/mnemonic: %w", err)
	}

	return &unlockedIdentity{
		OwnerID:      ownerID,
		Token:        stored.Token,
		SigningKey:   ks.PrivateKey,
		MasterSecret: masterSecret,
	}, nil
}
