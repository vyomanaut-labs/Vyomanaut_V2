// Package main — `provider inspect` (M17-E Session 17.5.2, requirements 5
// and 11, ADR-084 D-2a).
//
// Opens the LOCAL chunk store directly (internal/storage — already a
// dependency of this package via main.go, ChunkStore's own consumer) and
// reports what is actually on disk: every chunk's ID, size, and computed
// Shannon entropy (entropy.go), optionally beside a plaintext file's own
// entropy (--compare) for the contrast requirement 5 needs, plus the
// declared allocation and NFR-044 chunk ceiling that make requirement 11
// land — the number a provider chose, shown governing a limit the system
// actually enforces, not merely echoed back decoratively.
//
// PROVIDER BLINDNESS (ADR-084 D-2a): a provider holds one shard against
// DataShards = 3 and must have no import path to a decoding primitive.
// This file only ever reads raw bytes via storage.ChunkStore.LookupChunk
// and computes a statistic over them — it never attempts to interpret
// their meaning, and imports nothing from internal/crypto/aont,
// internal/erasure, or internal/client/retrieve. Enforced structurally,
// not merely by convention:
//
//	go list -deps ./cmd/provider | grep -cE 'internal/(crypto/aont|erasure|client/retrieve)'
//	EXPECT: 0
//
// A KNOWN, DISCLOSED CONSTRAINT: both storage engines (wiskeyStore,
// engine_rocksdb.go; badgerStore, engine_badger.go) take an exclusive lock
// on their data directory. Running `inspect` while `provider run` is still
// live against the same --data-dir will fail to open the store — this
// requires the daemon to be stopped first. Solving concurrent read access
// would need either a read-only-open mode on both engines or an RPC into
// the running daemon; both are out of this session's scope and are not
// attempted here.
//
// [REF: ADR-084 D-2a; NFR-044; architecture.md §27.3; internal/api/upload.go
// activeChunkStorageCeilingGB; build_M17E.md Phase 17.5 Session 17.5.2]
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// nfr044StorageCeiling180DaysGB mirrors internal/api/upload.go's
// storageCeiling180DaysGB — the 180-day MTTF tier, the ceiling actually
// enforced today for every provider uniformly
// (activeChunkStorageCeilingGB, upload.go's own header note explains why).
// cmd/provider deliberately does not import internal/api (main.go's
// established convention — see registrationSigningField's own header
// note), so this is a mirrored constant, not a shared one: the server
// already echoes the live value back as storage_advisory_gb at
// registration time (providerRegisterResponseBody), but capturing that
// into registrationRecord would mean editing onboard.go and main.go again
// outside this session's FILES: list. Worth doing as a follow-up so this
// display tracks a live server value instead of a hand-mirrored constant
// that could silently drift if architecture.md §27.3 is ever revised.
const nfr044StorageCeiling180DaysGB = 70

// bytesPerGB matches upload.go's own convention (2^30, not a decimal
// billion) — the unit every declared-storage-gb figure in this package
// implicitly assumes.
const bytesPerGB = 1 << 30

// nfr044ChunkCeilingMaxChunks mirrors upload.go's chunkCeilingMaxChunks:
// the 180-day GB ceiling converted into a chunk count at this build's
// fixed shard size (storage.ChunkDataSize — a compile-time constant, not
// profile-variable, per migrations/README.md).
func nfr044ChunkCeilingMaxChunks() int64 {
	ceilingBytes := int64(nfr044StorageCeiling180DaysGB) * bytesPerGB
	return ceilingBytes / int64(storage.ChunkDataSize)
}

type inspectChunkReport struct {
	ChunkID   string  `json:"chunk_id"`
	SizeBytes int     `json:"size_bytes"`
	Entropy   float64 `json:"entropy_bits_per_byte"`
	HexDump   string  `json:"hex_dump,omitempty"`
}

type inspectCompareReport struct {
	Path      string  `json:"path"`
	SizeBytes int64   `json:"size_bytes"`
	Entropy   float64 `json:"entropy_bits_per_byte"`
}

type inspectReport struct {
	DataDir           string                `json:"data_dir"`
	DeclaredStorageGB int                   `json:"declared_storage_gb"`
	BytesUsed         int64                 `json:"bytes_used"`
	ChunkCeiling      int64                 `json:"chunk_ceiling"`
	Chunks            []inspectChunkReport  `json:"chunks"`
	Compare           *inspectCompareReport `json:"compare,omitempty"`
}

type inspectFlags struct {
	dataDir           string
	chunk             string
	hexDump           bool
	comparePath       string
	declaredStorageGB int
	jsonOutput        bool
}

func parseInspectFlags(args []string) inspectFlags {
	fs := flag.NewFlagSet("provider inspect", flag.ExitOnError)
	var f inspectFlags
	fs.StringVar(&f.dataDir, "data-dir", defaultProviderDataDir(), "Persistent data directory to inspect. `provider run` must be STOPPED first — both storage engines hold an exclusive lock on this directory.")
	fs.StringVar(&f.chunk, "chunk", "", "Narrow to one chunk, by its 64-character hex chunk_id. Empty = every chunk in the store.")
	fs.BoolVar(&f.hexDump, "hex", false, "Add a 128-byte hexdump for each chunk shown.")
	fs.StringVar(&f.comparePath, "compare", "", "Path to a local plaintext file — its entropy is computed and printed alongside every chunk's, for contrast (requirement 5).")
	fs.IntVar(&f.declaredStorageGB, "declared-storage-gb", 0, "Fallback declared allocation, used only when --data-dir has no registration.json (e.g. a --sim-count/--registration-bearer-token instance that never ran `provider onboard`).")
	fs.BoolVar(&f.jsonOutput, "json", false, "Emit the report as a single JSON object instead of human-readable text.")
	_ = fs.Parse(args)
	return f
}

// runInspect opens the local chunk store, lists (or looks up one named)
// chunk, computes each one's entropy, and assembles the full report.
// Returning the report rather than printing directly keeps this testable
// and lets inspectCmd decide human-readable vs. --json rendering.
func runInspect(flags inspectFlags) (inspectReport, error) {
	store, err := storage.NewChunkStore(flags.dataDir)
	if err != nil {
		return inspectReport{}, fmt.Errorf("open chunk store at %s (is `provider run` still running against it?): %w", flags.dataDir, err)
	}
	defer func() { _ = store.Close() }()

	var chunkIDs [][32]byte
	if flags.chunk != "" {
		raw, decErr := hex.DecodeString(flags.chunk)
		if decErr != nil || len(raw) != 32 {
			return inspectReport{}, fmt.Errorf("--chunk must be 64 lowercase hex characters, got %q", flags.chunk)
		}
		var id [32]byte
		copy(id[:], raw)
		chunkIDs = [][32]byte{id}
	} else {
		chunkIDs, err = store.ListChunks()
		if err != nil {
			return inspectReport{}, fmt.Errorf("list chunks: %w", err)
		}
	}

	report := inspectReport{
		DataDir:      flags.dataDir,
		ChunkCeiling: nfr044ChunkCeilingMaxChunks(),
		Chunks:       make([]inspectChunkReport, 0, len(chunkIDs)),
	}

	// requirement 11: the allocation shown is the number the provider
	// actually chose at onboarding (registration.json), not a
	// re-typed-on-the-spot value — the fallback flag exists only for
	// instances that were never onboarded through the human path at all.
	rec, found, recErr := loadRegistrationRecord(flags.dataDir)
	switch {
	case recErr != nil:
		return inspectReport{}, recErr
	case found:
		report.DeclaredStorageGB = rec.DeclaredStorageGB
	default:
		report.DeclaredStorageGB = flags.declaredStorageGB
	}

	var totalBytes int64
	for _, id := range chunkIDs {
		data, lookupErr := store.LookupChunk(id)
		if lookupErr != nil {
			return inspectReport{}, fmt.Errorf("lookup chunk %x: %w", id, lookupErr)
		}
		totalBytes += int64(len(data))

		chunkReport := inspectChunkReport{
			ChunkID:   hex.EncodeToString(id[:]),
			SizeBytes: len(data),
			Entropy:   shannonEntropy(data),
		}
		if flags.hexDump {
			n := 128
			if len(data) < n {
				n = len(data)
			}
			chunkReport.HexDump = hexDump(data[:n])
		}
		report.Chunks = append(report.Chunks, chunkReport)
	}
	report.BytesUsed = totalBytes

	if flags.comparePath != "" {
		data, readErr := os.ReadFile(flags.comparePath)
		if readErr != nil {
			return inspectReport{}, fmt.Errorf("read --compare file %s: %w", flags.comparePath, readErr)
		}
		report.Compare = &inspectCompareReport{
			Path:      flags.comparePath,
			SizeBytes: int64(len(data)),
			Entropy:   shannonEntropy(data),
		}
	}

	return report, nil
}

// hexDump renders data (at most 128 bytes, per this file's caller) in the
// classic offset/hex/ASCII format, 16 bytes per line — the visual contrast
// requirement 5 needs on a terminal: encrypted chunk data next to a
// plaintext original (--compare) should look nothing alike to a human
// reading it, not just to a statistic.
func hexDump(data []byte) string {
	var b strings.Builder
	for offset := 0; offset < len(data); offset += hexDumpWidth {
		end := offset + hexDumpWidth
		if end > len(data) {
			end = len(data)
		}
		line := data[offset:end]

		fprintf(&b, "  %04x  ", offset)
		for i := 0; i < hexDumpWidth; i++ {
			if i < len(line) {
				fprintf(&b, "%02x ", line[i])
			} else {
				b.WriteString("   ")
			}
			if i == hexDumpWidth/2-1 {
				b.WriteByte(' ')
			}
		}
		b.WriteString(" |")
		for _, c := range line {
			if c >= 0x20 && c < 0x7f {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func printInspectReport(out io.Writer, report inspectReport) {
	fprintf(out, "declared allocation: %d GB   used: %d B   NFR-044 chunk ceiling: %d chunks\n",
		report.DeclaredStorageGB, report.BytesUsed, report.ChunkCeiling)
	for _, c := range report.Chunks {
		fprintf(out, "chunk %s  %d B  entropy %.4f bits/byte\n", c.ChunkID, c.SizeBytes, c.Entropy)
		if c.HexDump != "" {
			fprintln(out, c.HexDump)
		}
	}
	if report.Compare != nil {
		fprintf(out, "compare %s  %d B  entropy %.4f bits/byte\n",
			report.Compare.Path, report.Compare.SizeBytes, report.Compare.Entropy)
	}
}

// inspectCmd is the "inspect" subcommand's handler (dispatch.go).
func inspectCmd(args []string) int {
	flags := parseInspectFlags(args)

	report, err := runInspect(flags)
	if err != nil {
		fprintf(os.Stderr, "vyomanaut provider inspect: %v\n", err)
		return 1
	}

	if flags.jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return 0
	}

	printInspectReport(os.Stdout, report)
	return 0
}
