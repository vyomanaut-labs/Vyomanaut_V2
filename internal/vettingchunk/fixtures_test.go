// Package vettingchunk is declared in doc.go.
// Shared DB fixture plumbing (openTestDB/openAndPing/testDSN/envOr/
// randPhone/randChunkID32/insertTestVettingProvider/
// insertVettingChunkAssignmentRow) reused by generator_test.go and
// gc_test.go — mirrors the repair package's own queue_test.go fixture-file
// pattern (a single accumulating home for DB test plumbing other _test.go
// files in the package reuse rather than redeclaring).
//
// [REF: build.md Milestone 14 Phase 14.1/14.2]

package vettingchunk

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // registers the "postgres" driver used by openTestDB
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return openAndPing(t, testDSN("PGUSER", "vyomanaut_app", "PGPASSWORD"))
}

func openAndPing(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("sql.Open failed, skipping live-DB test: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("live Postgres not reachable, skipping live-DB test: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func testDSN(userEnvKey, userFallback, passEnvKey string) string {
	host := envOr("PGHOST", "localhost")
	port := envOr("PGPORT", "5432")
	user := envOr(userEnvKey, userFallback)
	password := os.Getenv(passEnvKey)
	dbname := envOr("PGDATABASE", "vyomanaut_test")
	sslmode := envOr("PGSSLMODE", "disable")
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randPhone(t *testing.T) string {
	t.Helper()
	var suffix [5]byte
	if _, err := cryptorand.Read(suffix[:]); err != nil {
		t.Fatalf("randPhone: %v", err)
	}
	return fmt.Sprintf("+91%x", suffix[:])
}

func randChunkID32(t *testing.T) [32]byte {
	t.Helper()
	var id [32]byte
	if _, err := cryptorand.Read(id[:]); err != nil {
		t.Fatalf("randChunkID32: %v", err)
	}
	return id
}

// insertTestVettingProvider inserts a providers row with status = 'VETTING'
// and a real Ed25519 keypair + one parseable multiaddr, returning its
// provider_id.
func insertTestVettingProvider(t *testing.T, db *sql.DB, declaredStorageGB int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	pub, _, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("insertTestVettingProvider: generate key: %v", err)
	}
	multiaddrs, err := json.Marshal([]string{"/ip4/127.0.0.1/tcp/4001"})
	if err != nil {
		t.Fatalf("insertTestVettingProvider: marshal multiaddrs: %v", err)
	}
	_, err = db.Exec(`
		INSERT INTO providers (
			provider_id, phone_number, ed25519_public_key, status,
			declared_storage_gb, city, region, asn, last_known_multiaddrs
		) VALUES ($1,$2,$3,'VETTING',$4,'TestCity','TestRegion','SIM-AS1',$5)`,
		id, randPhone(t), []byte(pub), declaredStorageGB, multiaddrs)
	if err != nil {
		t.Fatalf("insertTestVettingProvider: %v", err)
	}
	return id
}

// insertVettingChunkAssignmentRow inserts a synthetic chunk_assignments row
// (is_vetting_chunk = TRUE, segment_id/shard_index NULL) at the given
// status.
func insertVettingChunkAssignmentRow(t *testing.T, db *sql.DB, chunkID [32]byte, providerID uuid.UUID, status string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO chunk_assignments (chunk_id, is_vetting_chunk, segment_id, shard_index, provider_id, status)
		VALUES ($1, TRUE, NULL, NULL, $2, $3)`,
		chunkID[:], providerID, status)
	if err != nil {
		t.Fatalf("insertVettingChunkAssignmentRow: %v", err)
	}
}