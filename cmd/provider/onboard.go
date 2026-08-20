// Package main — `provider onboard` (M17-E Session 17.4.2, ADR-084 D-3,
// finding F-D-2).
//
// Before this session, no human could onboard a provider: registration
// required a bearer token only the integration harness could obtain (see
// providerFlags.registrationBearerToken's doc comment in main.go). This
// file closes that gap end to end — OTP send, a human reads the code off
// cmd/microservice's delivery log (internal/api's FileOtpSender, wired at
// cmd/microservice/main.go) via the network operator, OTP verify,
// registration — using nothing this daemon could not obtain itself over
// the wire, and no database access of any kind.
//
// This file deliberately does NOT import internal/api. Every request/
// response shape below is a local mirror of the server's own OAS-defined
// wire contract — the same convention main.go's
// registrationSigningField/canonicalRegisterSigningInput already establish
// for registration, and for the identical reason given there: this is a
// real, independent exercise of the actual wire protocol, not a shared-code
// shortcut that could silently drift out of sync with the server on only
// one side.
//
// [REF: ADR-084 §3.3, D-3; build_M17E.md Phase 17.4 Session 17.4.2;
// internal/api/otp.go Phase 11.4; internal/api/provider.go Session 11.5.x]
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// ── persisted registration (read by run, main.go; and depart, depart.go) ──

// registrationRecordFileName is the file onboard persists a successful
// registration to, under --data-dir. run and depart both read it —
// loadRegistrationRecord below.
const registrationRecordFileName = "registration.json"

// registrationRecord is what onboard persists after a successful
// POST /api/v1/provider/register: enough for a later `run` or `depart`
// invocation to act as this already-registered provider without repeating
// OTP — registration tokens are single-use, so repeating it would simply
// fail. Deliberately does NOT include the OTP code or phone number: this
// record outlives the OTP exchange and has no need to remember either.
type registrationRecord struct {
	ProviderID        string `json:"provider_id"`
	Token             string `json:"token"`
	DeclaredStorageGB int    `json:"declared_storage_gb"`
}

// saveRegistrationRecord persists rec under dataDir, mode 0600 — it holds a
// live 7-day bearer token (internal/api.ProviderTokenTTL), the same
// sensitivity class as owner-seed.bin (loadOrGenerateOwnerSeed, main.go).
func saveRegistrationRecord(dataDir string, rec registrationRecord) error {
	path := filepath.Join(dataDir, registrationRecordFileName)
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("cmd/provider: marshal registration record: %w", err)
	}
	if err := os.WriteFile(path, body, privateFilePermissions); err != nil {
		return fmt.Errorf("cmd/provider: persist registration record: %w", err)
	}
	return nil
}

// loadRegistrationRecord reads a previously-persisted registration.
// found == false with a nil error is the normal, expected case whenever
// `provider onboard` has never been run against dataDir — not an error
// condition; callers (main.go's runProviderInstance, depart.go) branch on
// it accordingly.
func loadRegistrationRecord(dataDir string) (rec registrationRecord, found bool, err error) {
	path := filepath.Join(dataDir, registrationRecordFileName)
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return registrationRecord{}, false, nil
		}
		return registrationRecord{}, false, fmt.Errorf("cmd/provider: read registration record: %w", readErr)
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return registrationRecord{}, false, fmt.Errorf("cmd/provider: parse registration record: %w", err)
	}
	return rec, true, nil
}

// ── onboard flags ───────────────────────────────────────────────────────

type onboardFlags struct {
	microserviceURL string
	phone           string
	storageGB       int
	dataDir         string
	listenPort      int
	advertiseAddr   string
	city            string
	region          string
}

func parseOnboardFlags(args []string) onboardFlags {
	fs := flag.NewFlagSet("provider onboard", flag.ExitOnError)

	var f onboardFlags
	fs.StringVar(&f.microserviceURL, "microservice-url", "", "Required. HTTPS base URL of the coordination microservice.")
	fs.StringVar(&f.phone, "phone", "", "Required. E.164 phone number, e.g. +919876500001.")
	fs.IntVar(&f.storageGB, "storage-gb", 0, "Storage to declare, in GB. Omit to be prompted (requirement 11's user-facing choice).")
	fs.StringVar(&f.dataDir, "data-dir", defaultProviderDataDir(), "Persistent data directory. `provider run`/`depart` must use the same one afterward.")
	fs.IntVar(&f.listenPort, "listen-port", defaultProviderListenPort, "Inbound libp2p listen port this registration advertises — must match the port `provider run` is later started with.")
	fs.StringVar(&f.advertiseAddr, "advertise-addr", "", "IPv4 host this daemon advertises to the network. Empty = autodetect (F-D-4) — see advertise.go.")
	fs.StringVar(&f.city, "city", demoProviderCity, "City, shown to the operator. No geolocation exists in this build — a disclosed gap, not a hidden default.")
	fs.StringVar(&f.region, "region", demoProviderRegion, "One of the declared metro regions the microservice validates against (internal/api/provider.go's validProviderRegions).")
	_ = fs.Parse(args)
	return f
}

// ── validation helpers ─────────────────────────────────────────────────

// onboardPhonePattern mirrors internal/api/otp.go's phoneNumberPattern
// (E.164) exactly — validating client-side before spending a network round
// trip on an input the server would reject anyway.
var onboardPhonePattern = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// onboardOtpCodePattern mirrors internal/api/otp.go's otpCodePattern.
var onboardOtpCodePattern = regexp.MustCompile(`^\d{6}$`)

// resolveStorageGB returns the declared storage allocation: flagValue if
// positive (--storage-gb was given), otherwise prompts on prompt and reads
// one line from in. Requirement 11's user-facing choice: the person
// answers a QUESTION, not a script default with no one behind it.
func resolveStorageGB(flagValue int, prompt io.Writer, in io.Reader) (int, error) {
	if flagValue > 0 {
		return flagValue, nil
	}
	fprint(prompt, "How much storage would you like to share, in GB? ")
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return 0, fmt.Errorf("--storage-gb is required (no input received)")
	}
	text := strings.TrimSpace(scanner.Text())
	gb, err := strconv.Atoi(text)
	if err != nil || gb <= 0 {
		return 0, fmt.Errorf("invalid storage amount %q: must be a positive whole number of GB", text)
	}
	return gb, nil
}

// promptOTPCode reads the six-digit OTP code from in, after printing a
// prompt to out. Read once, used once, never persisted — see this file's
// header: two separate parties (this volunteer, and the network operator
// reading cmd/microservice's delivery log) cooperate to admit a node, and
// this daemon holds no more of that code than the single verify call needs.
func promptOTPCode(out io.Writer, in io.Reader) (string, error) {
	fprint(out, "Enter the 6-digit code (ask the network operator): ")
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return "", fmt.Errorf("no OTP code entered")
	}
	code := strings.TrimSpace(scanner.Text())
	if !onboardOtpCodePattern.MatchString(code) {
		return "", fmt.Errorf("OTP code must be exactly 6 digits, got %q", code)
	}
	return code, nil
}

// ── wire calls: OTP send/verify ────────────────────────────────────────
// Local mirrors of internal/api/otp.go's unexported request/response
// shapes — see this file's header.

type onboardOtpSendRequestBody struct {
	PhoneNumber string `json:"phone_number"`
	Purpose     string `json:"purpose"`
}

type onboardOtpVerifyRequestBody struct {
	PhoneNumber string `json:"phone_number"`
	OtpCode     string `json:"otp_code"`
}

type onboardOtpVerifyResponseBody struct {
	Token       string  `json:"token"`
	Role        *string `json:"role"`
	EntityID    *string `json:"entity_id,omitempty"`
	IsNewEntity bool    `json:"is_new_entity"`
}

// sendOTP calls POST /api/v1/auth/otp/send. The code itself never appears
// in this function — it does not exist yet at this point in the flow.
func sendOTP(ctx context.Context, microserviceURL, phoneNumber, purpose string) error {
	body, err := json.Marshal(onboardOtpSendRequestBody{PhoneNumber: phoneNumber, Purpose: purpose})
	if err != nil {
		return fmt.Errorf("marshal otp send request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, microserviceURL+"/api/v1/auth/otp/send", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build otp send request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: providerHTTPClientTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("otp send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return fmt.Errorf("otp send returned HTTP %d: %s", resp.StatusCode, errBody)
	}
	return nil
}

// verifyOTP calls POST /api/v1/auth/otp/verify and returns the
// registration-token JWT. code is used here, once, to build the request
// body sent over TLS to the server — it is never written to disk, never
// logged, and never appears in any --json output this package produces
// (TestOnboardNeverWritesTheCodeToDisk asserts this behaviorally).
func verifyOTP(ctx context.Context, microserviceURL, phoneNumber, code string) (registrationToken string, err error) {
	body, err := json.Marshal(onboardOtpVerifyRequestBody{PhoneNumber: phoneNumber, OtpCode: code})
	if err != nil {
		return "", fmt.Errorf("marshal otp verify request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, microserviceURL+"/api/v1/auth/otp/verify", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build otp verify request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: providerHTTPClientTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("otp verify request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return "", fmt.Errorf("otp verify returned HTTP %d: %s", resp.StatusCode, errBody)
	}

	var respBody onboardOtpVerifyResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return "", fmt.Errorf("decode otp verify response: %w", err)
	}
	return respBody.Token, nil
}

// ── the flow itself ─────────────────────────────────────────────────────

// onboardPurpose is the OTP purpose this flow always sends — one of the
// three internal/api/otp.go's validOtpPurposes accepts.
const onboardPurpose = "PROVIDER_REGISTER"

// runOnboard executes the full onboarding flow against out/in — factored
// out of onboardCmd so tests can drive it deterministically (fixed stdin
// content, a fake microservice) without touching the real os.Stdin/Stdout.
func runOnboard(ctx context.Context, flags onboardFlags, out io.Writer, in io.Reader) (registrationRecord, error) {
	if flags.microserviceURL == "" {
		return registrationRecord{}, fmt.Errorf("--microservice-url is required")
	}
	if !onboardPhonePattern.MatchString(flags.phone) {
		return registrationRecord{}, fmt.Errorf("--phone must be E.164 format, e.g. +919876500001")
	}

	storageGB, err := resolveStorageGB(flags.storageGB, out, in)
	if err != nil {
		return registrationRecord{}, err
	}

	if err := os.MkdirAll(flags.dataDir, privateDirPermissions); err != nil {
		return registrationRecord{}, fmt.Errorf("create data dir: %w", err)
	}
	masterSecret, ownerID, err := loadOrGenerateOwnerSeed(flags.dataDir)
	if err != nil {
		return registrationRecord{}, err
	}
	signingKey, peerID, err := p2p.LoadOrGenerateIdentity(flags.dataDir, masterSecret, ownerID[:])
	if err != nil {
		return registrationRecord{}, fmt.Errorf("load/generate identity: %w", err)
	}
	fprintf(out, "Peer ID: %s\n", peerID)

	if err := sendOTP(ctx, flags.microserviceURL, flags.phone, onboardPurpose); err != nil {
		return registrationRecord{}, fmt.Errorf("send OTP: %w", err)
	}
	fprintln(out, "OTP sent — ask the network operator for your code.")

	code, err := promptOTPCode(out, in)
	if err != nil {
		return registrationRecord{}, err
	}

	registrationToken, err := verifyOTP(ctx, flags.microserviceURL, flags.phone, code)
	if err != nil {
		return registrationRecord{}, fmt.Errorf("verify OTP: %w", err)
	}

	// F-D-4: the SAME advertise/multiaddr machinery `run` uses (advertise.go,
	// main.go) — an onboarded provider's registered address is reachable
	// the same way a --sim-count instance's is, not hardcoded loopback.
	advertiseHost, warning := resolveAdvertiseHost(flags.advertiseAddr)
	if warning != "" {
		fprintf(out, "warning: %s\n", warning)
	}
	multiaddr := advertiseMultiaddr(advertiseHost, flags.listenPort, peerID)

	providerID, providerToken, err := registerProviderWithMicroservice(ctx, flags.microserviceURL, registrationToken, signingKey,
		storageGB, flags.city, flags.region, "", []string{multiaddr})
	if err != nil {
		return registrationRecord{}, fmt.Errorf("register: %w", err)
	}

	rec := registrationRecord{ProviderID: providerID, Token: providerToken, DeclaredStorageGB: storageGB}
	if err := saveRegistrationRecord(flags.dataDir, rec); err != nil {
		return registrationRecord{}, err
	}
	return rec, nil
}

// onboardCmd is the "onboard" subcommand's handler (dispatch.go).
func onboardCmd(args []string) int {
	flags := parseOnboardFlags(args)

	rec, err := runOnboard(context.Background(), flags, os.Stdout, os.Stdin)
	if err != nil {
		fprintf(os.Stderr, "vyomanaut provider onboard: %v\n", err)
		return 1
	}

	fprintf(os.Stdout, "Registered as provider %s (%d GB declared).\n", rec.ProviderID, rec.DeclaredStorageGB)
	fprintf(os.Stdout, "Run `provider run --microservice-url=%s --data-dir=%s` to start serving.\n", flags.microserviceURL, flags.dataDir)
	return 0
}
