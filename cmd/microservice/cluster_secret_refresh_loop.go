// cmd/microservice — see main.go's package doc comment.
//
// [Flagged and fixed — closes a gap found via live verification, the third
// of its kind this session alongside vetting_chunk_loop.go and the
// heartbeat-auth fix (internal/p2p/heartbeat.go): a correctly-implemented,
// well-documented component whose own design REQUIRES a periodic caller,
// where nothing in this file's startup sequence ever wired that caller in]
//
// internal/audit/secret.go's ClusterSecretCache has an intentional 5-minute
// TTL (IC §8, clusterSecretCacheTTL) — by design, not a bug: a real
// production deployment must periodically re-validate the cluster audit
// secret against its secrets manager to catch revocation/rotation, and
// CurrentSecret correctly fails closed (ErrSecretExpired) once that TTL
// lapses without a fresh Load. main.go calls cache.Load exactly once, at
// startup (loadClusterSecret) — nothing ever called it again. The result:
// every audit dispatch succeeded for the cache's first 5 minutes, then
// silently started failing with "cached secret TTL expired and manager
// unavailable" for the rest of any run, no matter how healthy the
// underlying secrets client (envSecretsClient, secrets_client.go) actually
// was — it was never asked again. This has no startup-time symptom:
// readiness.go's cluster_audit_secret_loaded condition only checks whether
// the cache was EVER loaded, not whether it is still fresh, so a demo run
// can look fully green at minute 1 and have every audit silently stop
// dispatching by minute 6.
//
// [REF: IC §8, ADR-027, build.md Milestone 12 Phase 12.1 Session 12.1.1,
// build.md Session 16.1.1]
package main

import (
	"context"
	"log"
	"time"

	"github.com/masamasaowl/Vyomanaut_V2/internal/audit"
)

// clusterSecretRefreshInterval is comfortably under ClusterSecretCache's
// own 5-minute TTL (internal/audit/secret.go's clusterSecretCacheTTL,
// unexported — duplicated as a value here rather than imported, same
// reasoning as cmd/provider's providerJWTAssumedTTL: keep in sync manually
// if either changes) so a single missed tick or transient secrets-manager
// hiccup never has a chance to let the cache actually expire.
const clusterSecretRefreshInterval = 2 * time.Minute

// runClusterSecretRefreshLoop blocks until ctx is cancelled, calling
// cache.Load on clusterSecretRefreshInterval to keep ClusterSecretCache's
// TTL from lapsing. A single failed refresh is logged, not fatal — the
// cache's own TTL grace period (IC §8) tolerates a missed cycle or two
// before ErrSecretExpired actually starts firing; the next tick retries.
func runClusterSecretRefreshLoop(ctx context.Context, cache *audit.ClusterSecretCache) {
	ticker := time.NewTicker(clusterSecretRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := cache.Load(ctx); err != nil {
				log.Printf("[cluster-secret] refresh: %v", err)
			}
		}
	}
}