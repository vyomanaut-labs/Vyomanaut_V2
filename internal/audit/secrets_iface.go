// Package audit is declared in doc.go.
// This file declares SecretsManagerClient, a package-local interface
// matching IC §8's shape. internal/audit cannot import the not-yet-built
// internal/secrets (LTS track — Production Hardening milestone, relocated
// from the old Milestone 17 by M17 Session 17.3.1; see build_part4.md); the
// concrete Vault/AWS-SSM/GCP-Secret-Manager adapters built there satisfy
// this interface implicitly via Go's structural typing — no import is
// needed in either direction.
//
// [REF: IC §8, ADR-027]

package audit

import "context"

// SecretsManagerClient abstracts over Vault, AWS SSM, and GCP Secret Manager
// (IC §8). Concrete adapters are implemented in internal/secrets (LTS
// track — Production Hardening milestone) and satisfy this interface
// structurally.
type SecretsManagerClient interface {
	// GetSecret retrieves the decoded (not base64) secret at path, e.g.
	// "/vyomanaut/audit-secret/v3" (IC §8 path convention).
	//
	// Pre-conditions:
	//   - path is a valid secrets path
	//
	// Post-conditions (on nil error):
	//   - returned bytes are the decoded secret value, not base64
	//
	// Error semantics:
	//   - ErrSecretNotFound: the path does not exist
	//   - ErrSecretManagerUnavailable: the secrets manager is unreachable
	//
	// Goroutine-safe: yes.
	GetSecret(ctx context.Context, path string) ([]byte, error)
}
