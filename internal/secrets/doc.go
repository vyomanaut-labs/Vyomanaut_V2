// Package secrets is not built on the demo track. Its concrete Vault,
// AWS SSM, and GCP Secret Manager adapters (IC §8's SecretsManagerClient
// shape) belong to the LTS track's Production Hardening milestone —
// relocated there, with no new milestone number assigned, by M17 Session
// 17.3.1 (see docs/system-design/build_part4.md's "LTS — Production
// Hardening" section for the full TASK/FILES/VERIFY breakdown). Demo-track
// code that would otherwise need a concrete adapter (internal/audit) uses
// a package-local structural interface instead (internal/audit/
// secrets_iface.go) so it never imports this package.
//
// [REF: IC §8, ADR-027, build_part4.md "LTS — Production Hardening"]
package secrets
