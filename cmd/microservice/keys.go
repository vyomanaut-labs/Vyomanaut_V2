// cmd/microservice — see main.go's package doc comment.
//
// This file loads the microservice's own Ed25519 identity/signing key and
// its X-Admin-API-Key. Neither is named or specified by any document in
// scope (MVP, ARCH, IC, DM) — both are startup-wiring decisions this session
// must make to actually construct api.RouterConfig and the p2p.Host.
//
// [Decision — one shared keypair, not one per replica] ARCH §18 requires the
// cluster audit HMAC secret to be "identical across all three replicas... so
// that any replica can validate any challenge, including during a failover."
// The SAME requirement applies by direct analogy to the microservice's own
// Ed25519 identity: it backs repair_auth_sig (internal/repair/executor.go,
// verified by provider daemons against a microservice public key),
// capability_token signatures (same file, same verifiers), and this
// session's own JWT issuance (internal/api/jwt.go) whose JWKS a client may
// fetch from ANY of the 3 replicas behind the load balancer. A JWT (or
// capability token, or repair auth signature) issued by one replica must
// verify against a public key every OTHER replica — and every client that
// cached the JWKS response — already trusts, or ordinary load-balanced
// traffic breaks under failover exactly the way ARCH §18 warns the audit
// secret would. This must therefore be ONE cluster-wide keypair, sourced the
// same way as the cluster audit secret: an env-var seed in demo mode,
// deferred to a real shared-secret mechanism in prod (see the TODO below —
// this shares the exact same IC §9-vs-IC §8 tension secrets_client.go's
// header comment documents for the cluster audit secret itself, and is left
// for the same future session to resolve for real).
//
// [REF: ARCH §18, IC §4.1, IC §4.4.1, build.md Milestone 12 Phase 12.1
// Session 12.1.1]
package main

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/api"
)

// microserviceSigningSeedEnvVar holds the 32-byte Ed25519 seed (64 hex
// characters) shared across all three microservice replicas.
const microserviceSigningSeedEnvVar = "VYOMANAUT_MICROSERVICE_SIGNING_SEED"

// loadOrGenerateMicroserviceSigningKey returns the cluster-wide Ed25519
// keypair backing this replica's p2p identity, JWT issuance, service_sig,
// repair_auth_sig, and capability tokens (see this file's header note on why
// these all share one key).
//
// In prod (requireSecretsManager == true, mirroring profile.RequireQuorum's
// own "identical across all three replicas" requirement): the seed MUST come
// from seedHex and MUST be identical on every replica — there is no real
// cluster-wide key-distribution mechanism wired yet (see header TODO), so
// this fails closed rather than silently generating a replica-local key that
// would make cross-replica verification fail unpredictably.
//
// In demo mode: an ephemeral key is generated if seedHex is empty, logged
// prominently since demo mode runs a single replica anyway (no cross-replica
// consistency requirement applies).
func loadOrGenerateMicroserviceSigningKey(requireSecretsManager bool, seedHex string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if seedHex != "" {
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			return nil, nil, fmt.Errorf("cmd/microservice: %s is not valid hex: %w", microserviceSigningSeedEnvVar, err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, nil, fmt.Errorf("cmd/microservice: %s must decode to %d bytes, got %d",
				microserviceSigningSeedEnvVar, ed25519.SeedSize, len(seed))
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(pub, priv[ed25519.SeedSize:])

		return pub, priv, nil
	}

	if requireSecretsManager {
		return nil, nil, fmt.Errorf(
			"cmd/microservice: %s must be set identically on every replica in production "+
				"(ARCH §18's cross-replica identity requirement; no cluster-wide key-distribution "+
				"mechanism is wired yet — see keys.go's header note)", microserviceSigningSeedEnvVar)
	}

	log.Printf("[STARTUP] WARNING: %s not set; generating an ephemeral microservice signing key "+
		"(fine for a single demo-mode replica; every issued JWT/capability token becomes invalid on restart)",
		microserviceSigningSeedEnvVar)
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cmd/microservice: generate ephemeral signing key: %w", err)
	}
	return pub, priv, nil
}

// adminAPIKeyEnvVar holds the X-Admin-API-Key value (OAS AdminApiKey
// security scheme: >=32 random bytes, hex-encoded — api.AdminAPIKeyMinHexLen in
// internal/api/router.go).
const adminAPIKeyEnvVar = "VYOMANAUT_ADMIN_API_KEY"

// [Corrected — M12 audit corrections, Finding 9] Previously duplicated
// internal/api/router.go's constant here (it was unexported, so importing
// it wasn't possible) — now that it is exported as
// api.AdminAPIKeyMinHexLen, this file uses that single definition directly
// instead of maintaining a second, independently-kept-in-sync-by-convention
// literal. cmd/microservice already imports internal/api (main.go,
// background_loops.go) for other reasons.

const hexCharsPerByte = 2

// loadOrGenerateAdminAPIKey returns the admin API key. In prod, requires
// keyHex to already be set and valid (fails closed — an ephemeral admin key
// in production would be silently regenerated on every restart, locking out
// whatever operator tooling has the previous value configured). In demo
// mode, generates and logs an ephemeral key if unset, since demo runs are
// short-lived and the value must simply be discoverable somewhere.
func loadOrGenerateAdminAPIKey(requireSecretsManager bool, keyHex string) (string, error) {
	if keyHex != "" {
		if len(keyHex) < api.AdminAPIKeyMinHexLen {
			return "", fmt.Errorf("cmd/microservice: %s must be at least %d hex characters, got %d",
				adminAPIKeyEnvVar, api.AdminAPIKeyMinHexLen, len(keyHex))
		}
		if _, err := hex.DecodeString(keyHex); err != nil {
			return "", fmt.Errorf("cmd/microservice: %s is not valid hex: %w", adminAPIKeyEnvVar, err)
		}
		return keyHex, nil
	}

	if requireSecretsManager {
		return "", fmt.Errorf("cmd/microservice: %s must be set in production", adminAPIKeyEnvVar)
	}

	buf := make([]byte, api.AdminAPIKeyMinHexLen/hexCharsPerByte)
	if _, err := cryptorand.Read(buf); err != nil {
		return "", fmt.Errorf("cmd/microservice: generate ephemeral admin API key: %w", err)
	}
	key := hex.EncodeToString(buf)
	log.Printf("[STARTUP] WARNING: %s not set; generated ephemeral admin API key for this demo run: %s",
		adminAPIKeyEnvVar, key)
	return key, nil
}
