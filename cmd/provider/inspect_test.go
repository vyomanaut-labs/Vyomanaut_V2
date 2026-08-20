package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// TestInspectFlow is a thin wrapper so `go test -run TestInspectFlow`
// matches every test below — same pattern this package's other test files
// already use.
func TestInspectFlow(t *testing.T) {
	t.Run("TestInspectReportsDeclaredAllocationAndCeiling", TestInspectReportsDeclaredAllocationAndCeiling)
	t.Run("TestInspectFallsBackToDeclaredStorageGBFlagWithoutRegistration", TestInspectFallsBackToDeclaredStorageGBFlagWithoutRegistration)
	t.Run("TestInspectCompareComputesEntropyOfLocalFile", TestInspectCompareComputesEntropyOfLocalFile)
	t.Run("TestInspectChunkFlagNarrowsToOneChunk", TestInspectChunkFlagNarrowsToOneChunk)
	t.Run("TestInspectHexFlagAddsHexDump", TestInspectHexFlagAddsHexDump)
	t.Run("TestInspectRejectsMalformedChunkID", TestInspectRejectsMalformedChunkID)
}

// writeOneRandomChunk opens a fresh chunk store at dataDir, writes one
// 262144-byte chunk of genuinely random data (crypto/rand — standing in
// for AONT-RS output, which is indistinguishable from random by design),
// and closes the store again so a later runInspect call can open it
// without hitting the exclusive-lock constraint this file's own header
// documents.
func writeOneRandomChunk(t *testing.T, dataDir string) [32]byte {
	t.Helper()
	store, err := storage.NewChunkStore(dataDir)
	if err != nil {
		t.Fatalf("NewChunkStore: %v", err)
	}
	if err := store.RecoverFromCrash(); err != nil {
		t.Fatalf("RecoverFromCrash: %v", err)
	}
	data := make([]byte, storage.ChunkDataSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	id := sha256.Sum256(data)
	if _, err := store.AppendChunk(id, data); err != nil {
		t.Fatalf("AppendChunk: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return id
}

// TestInspectReportsDeclaredAllocationAndCeiling verifies the allocation
// shown comes from registration.json (requirement 11), the NFR-044
// ceiling is positive, and the one written chunk's entropy reads as
// expected for random data.
func TestInspectReportsDeclaredAllocationAndCeiling(t *testing.T) {
	dataDir := t.TempDir()
	writeOneRandomChunk(t, dataDir)

	if err := saveRegistrationRecord(dataDir, registrationRecord{
		ProviderID: "p1", Token: "t1", DeclaredStorageGB: 42,
	}); err != nil {
		t.Fatalf("saveRegistrationRecord: %v", err)
	}

	report, err := runInspect(inspectFlags{dataDir: dataDir})
	if err != nil {
		t.Fatalf("runInspect: %v", err)
	}
	if report.DeclaredStorageGB != 42 {
		t.Errorf("DeclaredStorageGB = %d, want 42 (from registration.json)", report.DeclaredStorageGB)
	}
	if report.ChunkCeiling <= 0 {
		t.Errorf("ChunkCeiling = %d, want > 0", report.ChunkCeiling)
	}
	if len(report.Chunks) != 1 {
		t.Fatalf("Chunks = %d, want 1", len(report.Chunks))
	}
	if report.Chunks[0].Entropy < 7.9 {
		t.Errorf("random chunk entropy = %v, want > 7.9", report.Chunks[0].Entropy)
	}
	if report.BytesUsed != storage.ChunkDataSize {
		t.Errorf("BytesUsed = %d, want %d", report.BytesUsed, storage.ChunkDataSize)
	}
}

// TestInspectFallsBackToDeclaredStorageGBFlagWithoutRegistration verifies
// the --declared-storage-gb fallback is used only when no registration.json
// exists (e.g. a --sim-count/--registration-bearer-token instance that
// never ran `provider onboard`).
func TestInspectFallsBackToDeclaredStorageGBFlagWithoutRegistration(t *testing.T) {
	dataDir := t.TempDir()
	store, err := storage.NewChunkStore(dataDir)
	if err != nil {
		t.Fatalf("NewChunkStore: %v", err)
	}
	if err := store.RecoverFromCrash(); err != nil {
		t.Fatalf("RecoverFromCrash: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	report, err := runInspect(inspectFlags{dataDir: dataDir, declaredStorageGB: 15})
	if err != nil {
		t.Fatalf("runInspect: %v", err)
	}
	if report.DeclaredStorageGB != 15 {
		t.Errorf("DeclaredStorageGB = %d, want 15 (from --declared-storage-gb fallback)", report.DeclaredStorageGB)
	}
	if len(report.Chunks) != 0 {
		t.Errorf("Chunks = %d, want 0 (empty store)", len(report.Chunks))
	}
}

// TestInspectCompareComputesEntropyOfLocalFile verifies --compare computes
// entropy over an arbitrary local file and that ordinary text measures
// well below random — the contrast requirement 5 needs.
func TestInspectCompareComputesEntropyOfLocalFile(t *testing.T) {
	dataDir := t.TempDir()
	writeOneRandomChunk(t, dataDir)

	comparePath := filepath.Join(t.TempDir(), "plaintext.txt")
	text := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200)
	if err := os.WriteFile(comparePath, []byte(text), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	report, err := runInspect(inspectFlags{dataDir: dataDir, comparePath: comparePath})
	if err != nil {
		t.Fatalf("runInspect: %v", err)
	}
	if report.Compare == nil {
		t.Fatal("Compare is nil, want a populated compare report")
	}
	if report.Compare.Path != comparePath {
		t.Errorf("Compare.Path = %q, want %q", report.Compare.Path, comparePath)
	}
	if report.Compare.SizeBytes != int64(len(text)) {
		t.Errorf("Compare.SizeBytes = %d, want %d", report.Compare.SizeBytes, len(text))
	}
	if report.Compare.Entropy >= 5.0 {
		t.Errorf("English-text compare entropy = %v, want < 5.0", report.Compare.Entropy)
	}
	// The point of --compare: the stored chunk's entropy and the
	// plaintext's entropy must be clearly, not marginally, different.
	if len(report.Chunks) != 1 {
		t.Fatalf("Chunks = %d, want 1", len(report.Chunks))
	}
	if report.Chunks[0].Entropy-report.Compare.Entropy < 2.0 {
		t.Errorf("chunk entropy (%v) is not clearly separated from compare entropy (%v)",
			report.Chunks[0].Entropy, report.Compare.Entropy)
	}
}

// TestInspectChunkFlagNarrowsToOneChunk verifies --chunk restricts the
// report to exactly the named chunk, not the whole store.
func TestInspectChunkFlagNarrowsToOneChunk(t *testing.T) {
	dataDir := t.TempDir()
	store, err := storage.NewChunkStore(dataDir)
	if err != nil {
		t.Fatalf("NewChunkStore: %v", err)
	}
	if err := store.RecoverFromCrash(); err != nil {
		t.Fatalf("RecoverFromCrash: %v", err)
	}
	var ids [][32]byte
	for i := 0; i < 3; i++ {
		data := make([]byte, storage.ChunkDataSize)
		data[0] = byte(i)
		id := sha256.Sum256(data)
		if _, err := store.AppendChunk(id, data); err != nil {
			t.Fatalf("AppendChunk %d: %v", i, err)
		}
		ids = append(ids, id)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	targetHex := hex.EncodeToString(ids[1][:])
	report, err := runInspect(inspectFlags{dataDir: dataDir, chunk: targetHex})
	if err != nil {
		t.Fatalf("runInspect: %v", err)
	}
	if len(report.Chunks) != 1 {
		t.Fatalf("Chunks = %d, want 1", len(report.Chunks))
	}
	if report.Chunks[0].ChunkID != targetHex {
		t.Errorf("Chunks[0].ChunkID = %q, want %q", report.Chunks[0].ChunkID, targetHex)
	}
}

// TestInspectHexFlagAddsHexDump verifies --hex populates HexDump and its
// absence leaves it empty.
func TestInspectHexFlagAddsHexDump(t *testing.T) {
	dataDir := t.TempDir()
	writeOneRandomChunk(t, dataDir)

	without, err := runInspect(inspectFlags{dataDir: dataDir})
	if err != nil {
		t.Fatalf("runInspect (without --hex): %v", err)
	}
	if without.Chunks[0].HexDump != "" {
		t.Errorf("HexDump = %q without --hex, want empty", without.Chunks[0].HexDump)
	}

	with, err := runInspect(inspectFlags{dataDir: dataDir, hexDump: true})
	if err != nil {
		t.Fatalf("runInspect (with --hex): %v", err)
	}
	if with.Chunks[0].HexDump == "" {
		t.Error("HexDump is empty with --hex, want a rendered dump")
	}
	if !strings.Contains(with.Chunks[0].HexDump, "|") {
		t.Errorf("HexDump does not look like a hexdump (no ASCII column): %q", with.Chunks[0].HexDump)
	}
}

// TestInspectRejectsMalformedChunkID verifies a non-hex or wrong-length
// --chunk value is rejected with a clear error rather than silently
// truncated or padded.
func TestInspectRejectsMalformedChunkID(t *testing.T) {
	dataDir := t.TempDir()
	store, err := storage.NewChunkStore(dataDir)
	if err != nil {
		t.Fatalf("NewChunkStore: %v", err)
	}
	if err := store.RecoverFromCrash(); err != nil {
		t.Fatalf("RecoverFromCrash: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := runInspect(inspectFlags{dataDir: dataDir, chunk: "not-hex-and-wrong-length"}); err == nil {
		t.Fatal("runInspect with a malformed --chunk: expected an error, got nil")
	}
}
