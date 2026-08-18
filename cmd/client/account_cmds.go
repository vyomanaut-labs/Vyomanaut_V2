// register and recover, wired over internal/client/account per MVP §8.3.
//
// [Design Council extension, Session 17.1.1] The TASK text this session
// was given says simply "register -> account.Register" and "recover ->
// account.Recover, with --passphrase and --mnemonic paths" — neither
// mentions a network round-trip. Live-tracing the actual server protocol
// (internal/api/owner.go, internal/api/otp.go) surfaced a real ordering
// contradiction the Design Council resolved: see registerflow.go's own
// header note for the full account of why register.go's Register cannot
// itself be the live registration path, and why FinalizeIdentity exists
// instead.
//
// recover's use of phone+OTP (rather than a purely local --owner-id flag)
// is this session's own judgment call, not literally specified by the
// TASK text either: MVP §8.3 describes recover as "New-device recovery",
// and internal/api/otp.go's HandleVerify already returns a full JWT +
// entity_id for an existing phone number with no further network call
// needed (see registerflow.go) — a genuine login mechanism this project's
// own docs never named as such. A --owner-id + local-keystore-only path
// is also supported for the same-machine case (no network needed at all)
// since MVP §8.3 explicitly names --passphrase/--mnemonic as recover's
// two flag paths and a same-machine passphrase-typo scenario shouldn't
// require re-verifying a phone number.
//
// MNEMONIC_NEVER_LOGGED_OR_SERIALISED (this session's own VERIFY block):
// this file makes no structured-logging calls and never writes a file
// directly — all local persistence goes through localstore.go, which only
// ever touches keystore ciphertext, nonces, owner IDs, and JWTs, never
// mnemonic words. The mnemonic is printed to stdout exactly once
// (human-readable mode only, never under --json) and is never written to
// any file.
//
// [REF: MVP §8.3, IC §5.1 DeriveMasterSecret/MnemonicToMasterSecret,
// ADR-031, ADR-064, Design Council verdict "Owner Registration:
// Keypair/OwnerID Ordering"]
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/account"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

const cliHTTPClientTimeout = 30 * time.Second

// ── register ─────────────────────────────────────────────────────────────

type registerConfig struct {
	g          globalFlags
	profile    config.NetworkProfile
	httpClient *http.Client
	phone      string
	otpCode    string
	passphrase string
}

func dispatchRegister(args []string, stdin io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	phone := fs.String("phone", "", "Phone number in E.164 format (e.g. +91XXXXXXXXXX). Prompted if omitted.")
	otpCode := fs.String("otp-code", "", "6-digit OTP code. Prompted if omitted (useful for scripted/demo-harness runs that already know the code).")
	passphrase := fs.String("passphrase", "", "Passphrase for Argon2id derivation (profile.Argon2Time/Argon2Memory/Argon2Threads — never hardcoded). Prompted if omitted; a flag is convenient for automation but leaves the passphrase in shell history, so interactive use should prefer the prompt.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := validateGlobalFlags(g); err != nil {
		fprintln(errOut, err)
		return 2
	}

	profile := config.SelectProfile(g.mode)
	if err := config.ValidateStartupGuards(profile); err != nil {
		fprintln(errOut, err)
		return 1
	}

	cfg := registerConfig{
		g:          g,
		profile:    profile,
		httpClient: &http.Client{Timeout: cliHTTPClientTimeout},
		phone:      *phone,
		otpCode:    *otpCode,
		passphrase: *passphrase,
	}
	return runRegister(context.Background(), cfg, bufio.NewReader(stdin), out, errOut)
}

func runRegister(ctx context.Context, cfg registerConfig, in *bufio.Reader, out, errOut io.Writer) int {
	// Fail fast, not confusingly: --json never prints the mnemonic (by
	// design — MNEMONIC_NEVER_LOGGED_OR_SERIALISED), so a profile that
	// actually requires confirming it (SkipMnemonicConfirm == false —
	// i.e. anything but demo) has no channel to satisfy that
	// confirmation under --json. Left unchecked, this surfaces many
	// steps later as an opaque "word did not match" — this guard catches
	// it immediately, at the one place that actually knows both facts.
	if cfg.g.json && !cfg.profile.SkipMnemonicConfirm {
		fprintln(errOut, "register --json is not supported against a profile that requires mnemonic confirmation (this profile's SkipMnemonicConfirm is false): --json never prints the mnemonic, so there is no way to confirm it back. Register without --json, or use a profile where SkipMnemonicConfirm is true.")
		return 2
	}

	if existing, err := readIdentityFile(cfg.g.dataDir); err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	} else if existing != nil {
		fprintf(errOut, "An identity is already saved at %s (owner_id=%s). Use `recover` to restore a session, or point --data-dir somewhere new.\n", identityFilePath(cfg.g.dataDir), existing.OwnerID)
		return 1
	}
	if pending, err := readPendingRegistration(cfg.g.dataDir); err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	} else if pending != nil {
		fprintf(errOut, "A previous registration for owner_id=%s reached the server but never finished saving locally (found %s). This phone number cannot register again — the server already has an owner row for it. Complete recovery manually or contact support with this owner_id; remove that file yourself once you've confirmed it's abandoned.\n", pending.OwnerID, pendingRegistrationFilePath(cfg.g.dataDir))
		return 1
	}

	phone := cfg.phone
	if phone == "" {
		var err error
		phone, err = promptLine(out, in, "Phone number (E.164, e.g. +91XXXXXXXXXX): ")
		if err != nil {
			printCLIError(errOut, cfg.g.json, err, renderError)
			return 1
		}
	}

	if err := account.SendOTP(ctx, cfg.g.microserviceURL, cfg.httpClient, phone, account.OTPPurposeOwnerRegister); err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}
	fprintln(errOut, "OTP sent. In demo mode there is no real SMS integration — look up the 6-digit code from the otp_codes table.")

	code := cfg.otpCode
	if code == "" {
		var err error
		code, err = promptLine(out, in, "Enter the 6-digit code: ")
		if err != nil {
			printCLIError(errOut, cfg.g.json, err, renderError)
			return 1
		}
	}

	verifyResult, err := account.VerifyOTP(ctx, cfg.g.microserviceURL, cfg.httpClient, phone, code)
	if err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}
	if !verifyResult.IsNewEntity {
		fprintln(errOut, formatCopy(copyTable["PHONE_ALREADY_REGISTERED"]))
		fprintln(errOut, "Use `recover` instead.")
		return 1
	}

	registered, err := account.RegisterOwner(ctx, cfg.g.microserviceURL, cfg.httpClient, verifyResult.Token)
	if err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}

	// Orphan-detection marker (Design Council verdict item 3): the server
	// now has an owner row; everything from here on is local and could
	// still fail. Best-effort — a failure to write this marker doesn't
	// block registration, it just narrows the safety net.
	_ = writePendingRegistration(cfg.g.dataDir, registered.OwnerID, registered.Token, registered.PublicKey, registered.PrivateKey)

	passphrase := cfg.passphrase
	if passphrase == "" {
		var err error
		passphrase, err = promptLine(out, in, "Choose a passphrase (minimum 8 characters): ")
		if err != nil {
			printCLIError(errOut, cfg.g.json, err, renderError)
			return 1
		}
	}
	if len(passphrase) < 8 {
		fprintf(errOut, "Passphrase must be at least 8 characters. Your account IS registered (owner_id=%s); re-run register to finish with a longer passphrase.\n", registered.OwnerID)
		return 1
	}

	// Argon2id parameters are read from profile.Argon2Time/Argon2Memory/
	// Argon2Threads inside account.FinalizeIdentity — never hardcoded here
	// or anywhere in cmd/client (ADR-031).
	identity, err := account.FinalizeIdentity(registered.PublicKey, registered.PrivateKey, registered.OwnerID, []byte(passphrase), cfg.profile)
	passphrase = "" // best-effort local hygiene; Go can't guarantee this string's backing bytes are gone
	if err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}

	if !cfg.g.json {
		fprintln(out, "\nWrite down these 24 words in order. They are shown once, never saved to disk, never logged, and never included in --json output:")
		fprintln(out, strings.Join(identity.Mnemonic, " "))
		fprintln(out)
	}
	// --json + a non-demo profile (SkipMnemonicConfirm == false) would need
	// an interactive confirmation channel this mode doesn't have, since the
	// mnemonic is never printed under --json. Demo mode's profile always
	// has SkipMnemonicConfirm == true, so ConfirmMnemonic below never
	// blocks for this session's actual target (ADR-064). Flagged rather
	// than silently working around it: a --json registration against a
	// prod profile is not yet a supported combination.
	confirmPrompt := account.ConfirmPrompter(func(wordIndex int) string {
		typed, _ := promptLine(out, in, fmt.Sprintf("Confirm word #%d: ", wordIndex+1))
		return typed
	})
	if err := account.ConfirmMnemonic(identity.Mnemonic, cfg.profile, confirmPrompt); err != nil {
		fprintf(errOut, "Mnemonic confirmation failed: %v\n", err)
		fprintf(errOut, "Your account IS registered (owner_id=%s) but the local keystore was NOT saved. Re-run register to try confirmation again.\n", registered.OwnerID)
		return 1
	}

	ciphertext, nonce, err := account.EncryptKeystore(account.Keystore{PrivateKey: identity.PrivateKey}, identity.MasterSecret, registered.OwnerID[:])
	account.ZeroMasterSecret(&identity.MasterSecret)
	if err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}
	if err := writeIdentityFile(cfg.g.dataDir, registered.OwnerID, registered.Token, ciphertext, nonce); err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}
	_ = clearPendingRegistration(cfg.g.dataDir)

	if cfg.g.json {
		fprintln(out, renderRegisterJSON(registered.OwnerID))
	} else {
		fprintf(out, "Registered. owner_id=%s\n", registered.OwnerID)
	}
	return 0
}

// ── recover ──────────────────────────────────────────────────────────────

type recoverConfig struct {
	g          globalFlags
	profile    config.NetworkProfile
	httpClient *http.Client
	ownerID    string // local-only path
	phone      string
	otpCode    string
	passphrase string
	mnemonic   string
}

func dispatchRecover(args []string, stdin io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	ownerID := fs.String("owner-id", "", "Recover fully locally (no network) using the keystore already present at --data-dir. Requires that file to exist.")
	phone := fs.String("phone", "", "Phone number for network-based recovery (new-device case). Prompted if omitted and --owner-id is not given.")
	otpCode := fs.String("otp-code", "", "6-digit OTP code for network-based recovery. Prompted if omitted.")
	passphrase := fs.String("passphrase", "", "Passphrase recovery path (MVP §8.3). Mutually exclusive with --mnemonic.")
	mnemonic := fs.String("mnemonic", "", "24-word BIP-39 mnemonic recovery path (MVP §8.3), space-separated. Mutually exclusive with --passphrase.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := validateGlobalFlags(g); err != nil {
		fprintln(errOut, err)
		return 2
	}
	if *passphrase == "" && *mnemonic == "" {
		fprintln(errOut, "recover requires --passphrase or --mnemonic (MVP §8.3).")
		return 2
	}
	if *passphrase != "" && *mnemonic != "" {
		fprintln(errOut, "recover accepts only one of --passphrase or --mnemonic, not both.")
		return 2
	}

	profile := config.SelectProfile(g.mode)
	if err := config.ValidateStartupGuards(profile); err != nil {
		fprintln(errOut, err)
		return 1
	}

	cfg := recoverConfig{
		g:          g,
		profile:    profile,
		httpClient: &http.Client{Timeout: cliHTTPClientTimeout},
		ownerID:    *ownerID,
		phone:      *phone,
		otpCode:    *otpCode,
		passphrase: *passphrase,
		mnemonic:   *mnemonic,
	}
	return runRecover(context.Background(), cfg, bufio.NewReader(stdin), out, errOut)
}

func runRecover(ctx context.Context, cfg recoverConfig, in *bufio.Reader, out, errOut io.Writer) int {
	masterSecretFor := func(ownerID uuid.UUID) ([32]byte, error) {
		if cfg.mnemonic != "" {
			return account.RecoverFromMnemonic(strings.Fields(cfg.mnemonic))
		}
		return account.RecoverFromPassphrase(ownerID, []byte(cfg.passphrase), cfg.profile)
	}

	if cfg.ownerID != "" {
		return runLocalRecover(cfg, masterSecretFor, out, errOut)
	}
	return runNetworkRecover(ctx, cfg, masterSecretFor, in, out, errOut)
}

// runLocalRecover is the same-machine path: no network call at all,
// decrypting whatever keystore is already at --data-dir. Useful e.g.
// after a passphrase typo, or restoring --data-dir from a backup.
func runLocalRecover(cfg recoverConfig, masterSecretFor func(uuid.UUID) ([32]byte, error), out, errOut io.Writer) int {
	ownerID, err := uuid.Parse(cfg.ownerID)
	if err != nil {
		fprintf(errOut, "--owner-id is not a valid UUID: %v\n", err)
		return 2
	}
	stored, err := readIdentityFile(cfg.g.dataDir)
	if err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}
	if stored == nil {
		fprintf(errOut, "No local keystore found at %s. Use --phone instead so recover can re-authenticate over the network.\n", identityFilePath(cfg.g.dataDir))
		return 1
	}
	ciphertext, nonce, err := decodeStoredKeystore(*stored)
	if err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}

	masterSecret, err := masterSecretFor(ownerID)
	if err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}
	_, decErr := account.DecryptKeystore(ciphertext, nonce, masterSecret, ownerID[:])
	account.ZeroMasterSecret(&masterSecret)
	if decErr != nil {
		fprintln(errOut, "Could not decrypt the local keystore with the given passphrase/mnemonic for this --owner-id.")
		return 1
	}

	if cfg.g.json {
		fprintln(out, renderRecoverJSON(ownerID, true))
	} else {
		fprintf(out, "Recovered locally. owner_id=%s (signing identity restored from existing keystore; the session token on file may be stale — network calls will reject it once expired, at which point recover with --phone instead).\n", ownerID)
	}
	return 0
}

// runNetworkRecover is the new-device path: phone+OTP re-verification
// doubles as login for an existing phone number (registerflow.go's
// VerifyOTP doc comment) and gets back a fresh JWT and the ownerID. If a
// local keystore also happens to be present (e.g. copied over from the
// old machine), it's opportunistically decrypted too, restoring full
// signing capability; if not, the master secret is still recovered (file
// data can be decoded) but the Ed25519 identity key cannot be — there is
// no server-side re-keying endpoint in this codebase. Stated to the user
// plainly rather than silently degraded.
func runNetworkRecover(ctx context.Context, cfg recoverConfig, masterSecretFor func(uuid.UUID) ([32]byte, error), in *bufio.Reader, out, errOut io.Writer) int {
	phone := cfg.phone
	if phone == "" {
		var err error
		phone, err = promptLine(out, in, "Phone number (E.164, e.g. +91XXXXXXXXXX): ")
		if err != nil {
			printCLIError(errOut, cfg.g.json, err, renderError)
			return 1
		}
	}

	if err := account.SendOTP(ctx, cfg.g.microserviceURL, cfg.httpClient, phone, account.OTPPurposeLogin); err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}
	fprintln(errOut, "OTP sent. In demo mode there is no real SMS integration — look up the 6-digit code from the otp_codes table.")

	code := cfg.otpCode
	if code == "" {
		var err error
		code, err = promptLine(out, in, "Enter the 6-digit code: ")
		if err != nil {
			printCLIError(errOut, cfg.g.json, err, renderError)
			return 1
		}
	}

	verifyResult, err := account.VerifyOTP(ctx, cfg.g.microserviceURL, cfg.httpClient, phone, code)
	if err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}
	if verifyResult.IsNewEntity {
		fprintln(errOut, "No account exists yet for this phone number. Use `register` instead.")
		return 1
	}

	masterSecret, err := masterSecretFor(verifyResult.EntityID)
	if err != nil {
		printCLIError(errOut, cfg.g.json, err, renderError)
		return 1
	}

	signingKeyRestored := false
	if stored, readErr := readIdentityFile(cfg.g.dataDir); readErr == nil && stored != nil {
		if ciphertext, nonce, decodeErr := decodeStoredKeystore(*stored); decodeErr == nil {
			if _, decErr := account.DecryptKeystore(ciphertext, nonce, masterSecret, verifyResult.EntityID[:]); decErr == nil {
				signingKeyRestored = true
				_ = writeIdentityFile(cfg.g.dataDir, verifyResult.EntityID, verifyResult.Token, ciphertext, nonce)
			}
		}
	}
	account.ZeroMasterSecret(&masterSecret)

	if cfg.g.json {
		fprintln(out, renderRecoverJSON(verifyResult.EntityID, signingKeyRestored))
	} else {
		fprintf(out, "Recovered. owner_id=%s\n", verifyResult.EntityID)
		if !signingKeyRestored {
			fprintln(out, "Note: no local keystore was found or decryptable at this data-dir, so your Ed25519 signing identity could not be restored. File data can still be decoded with this master secret, but new uploads need the original keystore — there is currently no server-side way to register a replacement signing key for an existing owner_id.")
		}
	}
	return 0
}

// promptLine writes label to out, reads one line from in, and returns it
// trimmed. Plain stdin echo — this codebase has no golang.org/x/term
// dependency for no-echo input, a known, small demo-track gap (the
// mnemonic itself is never subject to this, since it is only ever
// printed, not typed back in full — ConfirmMnemonic only asks for two
// individual words).
// promptLine writes label to out, reads one line from in, and returns it
// trimmed.
//
// EOF handling is deliberate, not an oversight: a final line with no
// trailing newline (err == io.EOF, line != "") is valid input — common
// when a caller writes its last response without a trailing "\n" — and is
// returned normally. But EOF with zero bytes read at all (line == "") means
// the input source closed or ran out before this prompt got anything,
// which is never valid input; that case returns an explicit error instead
// of silently treating "nothing was typed" the same as "the input source
// is gone." Before this fix, the latter case silently returned ("", nil),
// so a stdin closed early (e.g. a test harness calling Close() before a
// prompt it didn't know to expect) surfaced many steps later as a
// confusing "word did not match" instead of a clear failure here, at the
// actual point of the problem.
func promptLine(out io.Writer, in *bufio.Reader, label string) (string, error) {
	if _, err := fmt.Fprint(out, label); err != nil {
		return "", err
	}
	line, err := in.ReadString('\n')
	if err != nil {
		if err == io.EOF && line != "" {
			return strings.TrimSpace(line), nil
		}
		return "", fmt.Errorf("cmd/client: read input for prompt %q: %w (input source closed or exhausted before a response was given)", label, err)
	}
	return strings.TrimSpace(line), nil
}
