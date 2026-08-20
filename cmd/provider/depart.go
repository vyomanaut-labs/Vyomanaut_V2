// Package main — `provider depart` (M17-E Session 17.4.2, ADR-084 §3.4) —
// the graceful half of requirement 7. Uses the identity and registration
// `provider onboard` (onboard.go) persisted under --data-dir: the request
// body's provider_sig is verified server-side
// (internal/api/provider.go's ProviderDepartHandler) against
// providers.ed25519_public_key, the exact keypair
// loadOrGenerateOwnerSeed/p2p.LoadOrGenerateIdentity deterministically
// reload from the same --data-dir — so a depart issued from the directory
// a provider registered from always verifies.
//
// Like onboard.go, this file deliberately does NOT import internal/api;
// providerDepartRequestBody/providerDepartResponseBody below are local
// mirrors of the server's own OAS-defined shapes — see main.go's
// registrationSigningField header note for why.
//
// [REF: ADR-084 §3.4; build_M17E.md Phase 17.4 Session 17.4.2;
// internal/api/provider.go Session 11.6.6]
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// providerDepartRequestBody / providerDepartResponseBody mirror
// internal/api/provider.go's identically-named unexported types exactly —
// the wire shape ProviderDepartHandler expects and returns.
type providerDepartRequestBody struct {
	DepartAt    *string `json:"depart_at"`
	ProviderSig string  `json:"provider_sig"`
}

type providerDepartResponseBody struct {
	Status             string `json:"status"`
	EscrowReleasePaise int64  `json:"escrow_release_paise"`
	RepairJobsQueued   int    `json:"repair_jobs_queued"`
}

// clientCanonicalDepartSigningInput mirrors internal/api/provider.go's
// canonicalDepartSigningInput exactly (same field, same jstr encoding) —
// built on main.go's registrationCanonicalSigningObject/registrationJstr,
// the same generic helpers registerProviderWithMicroservice's own signing
// input already uses.
func clientCanonicalDepartSigningInput(departAt *string) []byte {
	if departAt != nil {
		return registrationCanonicalSigningObject(registrationSigningField{"depart_at", registrationJstr(*departAt)})
	}
	return registrationCanonicalSigningObject()
}

type departFlags struct {
	microserviceURL string
	dataDir         string
	departAt        string
}

func parseDepartFlags(args []string) departFlags {
	fs := flag.NewFlagSet("provider depart", flag.ExitOnError)
	var f departFlags
	fs.StringVar(&f.microserviceURL, "microservice-url", "", "Required. HTTPS base URL of the coordination microservice.")
	fs.StringVar(&f.dataDir, "data-dir", defaultProviderDataDir(), "Persistent data directory — must match the --data-dir `provider onboard` (or `run`) used.")
	fs.StringVar(&f.departAt, "depart-at", "", "Optional ISO 8601 timestamp to include in the signed request. Empty = omitted.")
	_ = fs.Parse(args)
	return f
}

// signDepartRequest signs departAt the same way registerProviderWithMicroservice
// signs a registration: SHA-256(canonical bytes) then Ed25519.Sign on the
// digest — internal/crypto's hash-then-sign composition, NOT plain
// Ed25519.Sign on the raw bytes (see registerProviderWithMicroservice's own
// comment on why this distinction matters; getting it backwards there once
// made every real registration fail silently).
func signDepartRequest(signingKey ed25519.PrivateKey, departAt *string) []byte {
	digest := sha256.Sum256(clientCanonicalDepartSigningInput(departAt))
	return ed25519.Sign(signingKey, digest[:])
}

func postDepart(ctx context.Context, microserviceURL, bearerToken string, reqBody providerDepartRequestBody) (providerDepartResponseBody, error) {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return providerDepartResponseBody{}, fmt.Errorf("marshal depart request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, microserviceURL+"/api/v1/provider/depart", bytes.NewReader(body))
	if err != nil {
		return providerDepartResponseBody{}, fmt.Errorf("build depart request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+bearerToken)

	client := &http.Client{Timeout: providerHTTPClientTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return providerDepartResponseBody{}, fmt.Errorf("depart request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return providerDepartResponseBody{}, fmt.Errorf("depart returned HTTP %d: %s", resp.StatusCode, errBody)
	}

	var respBody providerDepartResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return providerDepartResponseBody{}, fmt.Errorf("decode depart response: %w", err)
	}
	return respBody, nil
}

// departCmd is the "depart" subcommand's handler (dispatch.go) — the
// graceful half of requirement 7 (ADR-084 §3.4).
func departCmd(args []string) int {
	flags := parseDepartFlags(args)
	if flags.microserviceURL == "" {
		fprintln(os.Stderr, "vyomanaut provider depart: --microservice-url is required")
		return 1
	}

	rec, found, err := loadRegistrationRecord(flags.dataDir)
	if err != nil {
		fprintf(os.Stderr, "vyomanaut provider depart: %v\n", err)
		return 1
	}
	if !found {
		fprintf(os.Stderr, "vyomanaut provider depart: no registration found under %s — run `provider onboard` first\n", flags.dataDir)
		return 1
	}

	masterSecret, ownerID, err := loadOrGenerateOwnerSeed(flags.dataDir)
	if err != nil {
		fprintf(os.Stderr, "vyomanaut provider depart: %v\n", err)
		return 1
	}
	signingKey, _, err := p2p.LoadOrGenerateIdentity(flags.dataDir, masterSecret, ownerID[:])
	if err != nil {
		fprintf(os.Stderr, "vyomanaut provider depart: load identity: %v\n", err)
		return 1
	}

	var departAt *string
	if flags.departAt != "" {
		departAt = &flags.departAt
	}
	sig := signDepartRequest(signingKey, departAt)

	resp, err := postDepart(context.Background(), flags.microserviceURL, rec.Token, providerDepartRequestBody{
		DepartAt:    departAt,
		ProviderSig: hex.EncodeToString(sig),
	})
	if err != nil {
		fprintf(os.Stderr, "vyomanaut provider depart: %v\n", err)
		return 1
	}

	fprintf(os.Stdout, "Departed. status=%s escrow_release=%s repair_jobs_queued=%d\n",
		resp.Status, formatPaise(resp.EscrowReleasePaise), resp.RepairJobsQueued)
	return 0
}
