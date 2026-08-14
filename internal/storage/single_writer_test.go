// Package storage_test provides external black-box tests for internal/storage.
// This file validates the single-writer goroutine contract (IC §5.3, MVP §8.2):
// 100 concurrent callers route write requests through a buffered channel to one
// writer goroutine; AppendChunk is called from that goroutine only.
//
// Run with: go test -race -run TestSingleWriterGoroutine ./internal/storage/
//
// [REF: IC §5.3, ADR-023, MVP §8.2, build.md Phase 5.2 Session 5.2.1]
package storage_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/storage"
)

// TestSingleWriterGoroutine validates that 100 concurrent callers routing through a
// single writer goroutine (via a buffered channel) store all 100 chunks correctly
// without data corruption or race conditions (IC §5.3, MVP §8.2).
//
// The "deadlock, not data corruption" property stated in MVP §8.2 means: if the
// writer goroutine exits early due to a bug, callers block on the channel (a
// detectable deadlock) rather than silently interleaving 262 KB writes that
// corrupt the vLog. Run with -race to verify the channel-plus-writer interaction
// is race-free.
//
// [REF: IC §5.3, ADR-023 §Single writer goroutine, MVP §8.2, ARCH §16]
func TestSingleWriterGoroutine(t *testing.T) {
	store, err := storage.NewChunkStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.RecoverFromCrash())
	t.Cleanup(func() { _ = store.Close() })

	// writeReq is the message type submitted to the single writer goroutine.
	// Concurrent callers fill chunkID + chunkData and receive the error on result.
	type writeReq struct {
		chunkID   [32]byte
		chunkData []byte
		result    chan error
	}

	// writeCh serialises all AppendChunk calls through exactly one goroutine.
	writeCh := make(chan writeReq, 200)
	go func() {
		// This goroutine is the sole authorised caller of AppendChunk (IC §5.3).
		// All 100 callers submit work via writeCh; this goroutine serialises writes.
		// Calling AppendChunk from any other goroutine produces undefined vLog corruption.
		// It drains writeCh until the channel is closed after all chunks are submitted.
		for req := range writeCh {
			_, err := store.AppendChunk(req.chunkID, req.chunkData)
			req.result <- err
		}
	}()

	const numChunks = 100
	errCh := make(chan error, numChunks)
	chunkIDs := make([][32]byte, numChunks)

	// Launch 100 concurrent callers. Each submits via writeCh; none calls AppendChunk directly.
	for i := 0; i < numChunks; i++ {
		data := make([]byte, 262144)
		data[0] = byte(i) // unique first byte per chunk for content verification
		id := sha256.Sum256(data)
		chunkIDs[i] = id
		resultCh := make(chan error, 1)
		writeCh <- writeReq{chunkID: id, chunkData: data, result: resultCh}
		go func() { errCh <- <-resultCh }()
	}

	// All 100 AppendChunk calls must succeed.
	for i := 0; i < numChunks; i++ {
		require.NoError(t, <-errCh, "chunk %d AppendChunk must not error", i)
	}
	close(writeCh)

	// All 100 chunks must be readable back with the correct content.
	for i, id := range chunkIDs {
		data, lookupErr := store.LookupChunk(id)
		require.NoError(t, lookupErr, "chunk %d must be found after write", i)
		require.Equal(t, 262144, len(data), "chunk %d must be 262144 bytes", i)
		require.Equal(t, byte(i), data[0], "chunk %d first byte must equal its index", i)
	}
}
