// cmd/microservice — see main.go's package doc comment.
//
// This file implements the two audit.SecretsManagerClient adapters Session
// 12.1.1's step 3 needs: an env-var-backed adapter for demo mode
// (profile.RequireSecretsManager == false), and a not-yet-implemented
// placeholder for prod mode, pending Milestone 17 Session 17.1.1's real
// Vault/AWS-SSM/GCP adapter.
//
// [Decision — placement] internal/audit/secrets_iface.go's own header
// comment says concrete adapters belong in internal/secrets (Milestone 17),
// satisfying audit.SecretsManagerClient structurally with no import needed.
// That works for the INTERFACE. It does not work for the ERROR SENTINELS
// audit.SecretsManagerClient's contract requires a conforming
// GetSecret to return: audit.ErrSecretNotFound and
// audit.ErrSecretManagerUnavailable are plain errors.New sentinels with no
// custom Is method, so errors.Is(err, audit.ErrSecretNotFound) can only ever
// be true if err IS that exact value (or wraps it) — which requires
// importing internal/audit to reference it by name. IC §9's own table
// forbids internal/secrets from importing ANY internal/ package, including
// internal/audit, so a conforming adapter literally cannot live in
// internal/secrets and also satisfy the error-sentinel contract
// audit.ClusterSecretCache.Load depends on (its "normal steady state: no
// newer version yet" branch specifically requires errors.Is(nextErr,
// ErrSecretNotFound) to be true for the speculative version+1 probe).
//
// This is a genuine, unresolved tension between IC §8 (the
// SecretsManagerClient error-semantics contract) and IC §9 (internal/secrets'
// import restriction) as documented — not something introduced here. Flagged
// rather than silently worked around. The resolution adopted for THIS
// session: both adapters below live in cmd/microservice instead, where there
// is no import restriction (cmd/ wiring code may import any internal/
// package) and audit.ErrSecretNotFound/ErrSecretManagerUnavailable can be
// referenced directly. NewClusterSecretCache's own doc comment supports this:
// it says only that "the caller decides which client to construct and passes
// the result in here," not that the client must live in internal/secrets.
// Milestone 17 Session 17.1.1, building the REAL Vault/AWS-SSM/GCP adapter,
// will need to resolve this tension for real — most likely by having
// internal/audit accept an error-classifying callback instead of fixed
// sentinels, or by loosening IC §9's internal/secrets restriction — rather
// than inheriting this same workaround.
//
// [REF: IC §8, IC §9, ADR-027, build.md Milestone 12 Phase 12.1 Session 12.1.1]
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/audit"
)

// clusterMasterSeedEnvVar is the IC §8 "Local development / simulation mode"
// substitute for the secrets manager: config.ValidateStartupGuards' Guard 1
// (PROD_MODE_ENV_SECRET) already forbids this variable being set when
// profile.RequireSecretsManager is true, so envSecretsClient below is never
// constructed in a context where that guard hasn't already run.
const clusterMasterSeedEnvVar = "VYOMANAUT_CLUSTER_MASTER_SEED"

// envSecretsClient substitutes for the whole secrets manager in demo mode
// (IC §8: "The VYOMANAUT_CLUSTER_MASTER_SEED environment variable may
// substitute for the secrets manager"). Rather than deriving per-version
// secrets via the ARCH §18 HKDF formula (server_secret_v{N} =
// HKDF-SHA256(cluster_master_seed, cluster_id, "vyomanaut-audit-secret-v"+N)
// — that formula describes how the value AT a real secrets-manager path was
// originally computed by the operator's rotate-secret tooling, not something
// a READER of the path re-derives), this adapter takes the simplest reading
// consistent with "substitute for the secrets manager": the env var IS
// version 1's secret, directly, decoded from base64 (IC §8: "Each path
// stores a 32-byte (256-bit) secret, base64-encoded"). No rotation ever
// happens in demo mode — there is exactly one version, forever — so every
// path other than v1 correctly reports audit.ErrSecretNotFound, which is
// exactly what ClusterSecretCache.Load's speculative version+1 probe expects
// to see in steady state (no rotation in progress).
type envSecretsClient struct {
	secret []byte
}

// newEnvSecretsClient reads and base64-decodes clusterMasterSeedEnvVar.
// Returns an error if the variable is unset or not valid base64 — a
// misconfigured demo deployment should fail loudly at startup, not silently
// serve a zero-value secret.
func newEnvSecretsClient() (*envSecretsClient, error) {
	raw := os.Getenv(clusterMasterSeedEnvVar)
	if raw == "" {
		return nil, fmt.Errorf("cmd/microservice: %s is not set (required in demo mode; IC §8)", clusterMasterSeedEnvVar)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("cmd/microservice: %s is not valid base64: %w", clusterMasterSeedEnvVar, err)
	}
	if len(decoded) != ed25519.SeedSize {
		return nil, fmt.Errorf("cmd/microservice: %s must decode to %d bytes, got %d", clusterMasterSeedEnvVar, ed25519.SeedSize, len(decoded))
	}
	return &envSecretsClient{secret: decoded}, nil
}

// GetSecret implements audit.SecretsManagerClient. path must be exactly
// "/vyomanaut/audit-secret/v1" — every other path (including v2+, since this
// stub never rotates) reports audit.ErrSecretNotFound, matching this file's
// header note on why that is the correct steady-state answer.
func (c *envSecretsClient) GetSecret(_ context.Context, path string) ([]byte, error) {
	if path != "/vyomanaut/audit-secret/v1" {
		return nil, audit.ErrSecretNotFound
	}
	return c.secret, nil
}

// notImplementedSecretsClient is the prod-mode placeholder for Milestone 17
// Session 17.1.1's real Vault/AWS-SSM/GCP adapter (this session's own task
// text names that session explicitly as where the real implementation
// belongs — it does not yet exist anywhere in this codebase). Every call
// fails closed with audit.ErrSecretManagerUnavailable, which is the CORRECT
// behaviour for "not implemented yet" under IC §8's fail-closed startup
// contract: a prod-mode replica that can't reach a real secrets manager must
// refuse to start, and that is exactly what happens today (there being no
// real backend to reach at all is a stricter version of "unreachable," not a
// different failure mode).
type notImplementedSecretsClient struct{}

// GetSecret implements audit.SecretsManagerClient.
func (notImplementedSecretsClient) GetSecret(context.Context, string) ([]byte, error) {
	return nil, fmt.Errorf(
		"cmd/microservice: no real secrets-manager adapter is wired yet (Milestone 17 Session 17.1.1): %w",
		audit.ErrSecretManagerUnavailable,
	)
}

// newSecretsClientForProfile selects the secretsClient per this session's
// step 3: the real adapter (prod, pending Milestone 17) when
// profile.RequireSecretsManager, otherwise the env-var adapter (demo). The
// PROD_MODE_ENV_SECRET guard (config.ValidateStartupGuards, M1 Session
// 1.3.2) is what prevents the env var from being used in production; this
// function does not re-check that itself (matching
// audit.NewClusterSecretCache's own documented division of responsibility).
func newSecretsClientForProfile(requireSecretsManager bool) (audit.SecretsManagerClient, error) {
	if requireSecretsManager {
		return notImplementedSecretsClient{}, nil
	}
	return newEnvSecretsClient()
}
