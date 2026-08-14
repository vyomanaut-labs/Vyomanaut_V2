// Package vettingchunk is declared in doc.go.
// Unit and live-database tests for GCDelivery. There is no real libp2p
// network in this test environment — fakeGCHost/fakeGCStream simulate a
// provider's vetting-gc responder in-memory, encoding real IC §4.5
// (ADR-036 addendum) wire frames so the actual framing code in gc.go is
// genuinely exercised, not bypassed.
//
// Tests:
//   - TestDeliverGCMarksDeletedOn0x00
//   - TestDeliverGCPartialFailureRetriesFailedOnly
//   - TestDeliverGCOfflineSetsPendingDeletionReturnsErrProviderOffline
//   - TestDeliverGCBackoffFromProfile
//
// [REF: IC §4.5, ADR-036, build.md Milestone 14 Phase 14.2 Session 14.2.1]

package vettingchunk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// ── Mock p2p.Stream / p2p.Host for the vetting-gc protocol ────────────────

// fakeGCStream captures every byte written to it (the VettingGCRequest
// frame this package's own gc.go builds) and serves a canned, well-formed
// VettingGCResponse Frame 2 on Read.
type fakeGCStream struct {
	written bytes.Buffer
	resp    *bytes.Reader
}

func (s *fakeGCStream) Read(p []byte) (int, error)       { return s.resp.Read(p) }
func (s *fakeGCStream) Write(p []byte) (int, error)      { return s.written.Write(p) }
func (s *fakeGCStream) Close() error                     { return nil }
func (s *fakeGCStream) Protocol() p2p.ProtocolID         { return vettingGCProtocolID }
func (s *fakeGCStream) RemotePeer() p2p.PeerID           { return "fake-provider-peer" }
func (s *fakeGCStream) Reset() error                     { return nil }
func (s *fakeGCStream) SetDeadline(time.Time) error      { return nil }
func (s *fakeGCStream) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeGCStream) SetWriteDeadline(time.Time) error { return nil }

// gcOKResponse builds a well-formed IC §4.5 VettingGCResponse Frame 2:
// status = 0x00, no failure_bitmap.
func gcOKResponse() *bytes.Reader {
	body := []byte{gcStatusOK}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	return bytes.NewReader(append(lenBuf[:], body...))
}

// gcPartialFailureResponse builds a status = 0x01 VettingGCResponse with
// failedIndexes set in the failure_bitmap (IC §4.5: "Bit N is set if
// deletion of chunk_ids[N] failed").
func gcPartialFailureResponse(chunkCount int, failedIndexes ...int) *bytes.Reader {
	bitmapLen := (chunkCount + gcBitsPerByte - 1) / gcBitsPerByte
	bitmap := make([]byte, bitmapLen)
	for _, idx := range failedIndexes {
		bitmap[idx/gcBitsPerByte] |= 1 << uint(idx%gcBitsPerByte)
	}
	body := append([]byte{gcStatusPartialFailure}, bitmap...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	return bytes.NewReader(append(lenBuf[:], body...))
}

// fakeGCHost implements p2p.Host. connectErr/streamErr simulate an
// unreachable provider (IC §4.5's "provider offline" case) when set.
type fakeGCHost struct {
	stream     *fakeGCStream
	connectErr error
	streamErr  error
}

func (h *fakeGCHost) PeerID() p2p.PeerID { return "fake-microservice-peer" }
func (h *fakeGCHost) Connect(context.Context, p2p.PeerID, []p2p.Multiaddr) error {
	return h.connectErr
}
func (h *fakeGCHost) NewStream(context.Context, p2p.PeerID, p2p.ProtocolID) (p2p.Stream, error) {
	if h.streamErr != nil {
		return nil, h.streamErr
	}
	return h.stream, nil
}
func (h *fakeGCHost) PromoteConn(context.Context, net.Conn, p2p.PeerID, p2p.ProtocolID) (p2p.Stream, error) {
	return nil, fmt.Errorf("fakeGCHost: PromoteConn not implemented")
}
func (h *fakeGCHost) SetStreamHandler(p2p.ProtocolID, p2p.StreamHandler) {}
func (h *fakeGCHost) NATType() p2p.NATStatus                             { return 0 }
func (h *fakeGCHost) Close() error                                       { return nil }

// ── DeliverGCInstruction ────────────────────────────────────────────────

func TestDeliverGCMarksDeletedOn0x00(t *testing.T) {
	db := openTestDB(t)
	_, msSigningKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate microservice signing key: %v", err)
	}
	providerID := insertTestVettingProvider(t, db, 50)
	chunkA := randChunkID32(t)
	chunkB := randChunkID32(t)
	insertVettingChunkAssignmentRow(t, db, chunkA, providerID, "ACTIVE")
	insertVettingChunkAssignmentRow(t, db, chunkB, providerID, "ACTIVE")

	host := &fakeGCHost{stream: &fakeGCStream{resp: gcOKResponse()}}
	gc := NewGCDelivery(db, host, msSigningKey)

	if err := gc.DeliverGCInstruction(context.Background(), providerID); err != nil {
		t.Fatalf("DeliverGCInstruction: %v", err)
	}

	for _, id := range [][32]byte{chunkA, chunkB} {
		var status string
		if err := db.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1 AND provider_id = $2`,
			id[:], providerID).Scan(&status); err != nil {
			t.Fatalf("query status: %v", err)
		}
		if status != "DELETED" {
			t.Errorf("chunk %x status = %q, want DELETED", id, status)
		}
	}
}

func TestDeliverGCPartialFailureRetriesFailedOnly(t *testing.T) {
	db := openTestDB(t)
	_, msSigningKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate microservice signing key: %v", err)
	}
	providerID := insertTestVettingProvider(t, db, 50)
	chunkA := randChunkID32(t)
	chunkB := randChunkID32(t)
	insertVettingChunkAssignmentRow(t, db, chunkA, providerID, "ACTIVE")
	insertVettingChunkAssignmentRow(t, db, chunkB, providerID, "ACTIVE")

	// loadActiveSyntheticChunkIDs orders by chunk_id ASC (gc.go); determine
	// which of the two sorts first so the failure_bitmap targets a known ID.
	first, second := chunkA, chunkB
	if bytes.Compare(chunkB[:], chunkA[:]) < 0 {
		first, second = chunkB, chunkA
	}

	host := &fakeGCHost{stream: &fakeGCStream{resp: gcPartialFailureResponse(2, 0)}} // index 0 (first) fails
	gc := NewGCDelivery(db, host, msSigningKey)

	if err := gc.DeliverGCInstruction(context.Background(), providerID); err != nil {
		t.Fatalf("DeliverGCInstruction: %v", err)
	}

	var firstStatus, secondStatus string
	if err := db.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1`, first[:]).Scan(&firstStatus); err != nil {
		t.Fatalf("query first status: %v", err)
	}
	if err := db.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1`, second[:]).Scan(&secondStatus); err != nil {
		t.Fatalf("query second status: %v", err)
	}
	if firstStatus != "PENDING_DELETION" {
		t.Errorf("failed chunk status = %q, want PENDING_DELETION (retry next connection)", firstStatus)
	}
	if secondStatus != "DELETED" {
		t.Errorf("succeeded chunk status = %q, want DELETED", secondStatus)
	}
}

func TestDeliverGCOfflineSetsPendingDeletionReturnsErrProviderOffline(t *testing.T) {
	db := openTestDB(t)
	_, msSigningKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate microservice signing key: %v", err)
	}
	providerID := insertTestVettingProvider(t, db, 50)
	chunkA := randChunkID32(t)
	insertVettingChunkAssignmentRow(t, db, chunkA, providerID, "ACTIVE")

	host := &fakeGCHost{connectErr: fmt.Errorf("simulated: provider unreachable")}
	gc := NewGCDelivery(db, host, msSigningKey)

	err = gc.DeliverGCInstruction(context.Background(), providerID)
	if !errors.Is(err, ErrProviderOffline) {
		t.Fatalf("DeliverGCInstruction error = %v, want ErrProviderOffline", err)
	}

	var status string
	if err := db.QueryRow(`SELECT status FROM chunk_assignments WHERE chunk_id = $1`, chunkA[:]).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "PENDING_DELETION" {
		t.Errorf("status = %q, want PENDING_DELETION", status)
	}
}

// ── GCRetryBackoffDelay ─────────────────────────────────────────────────

func TestDeliverGCBackoffFromProfile(t *testing.T) {
	for _, profile := range []config.NetworkProfile{config.DemoProfile, config.ProductionProfile} {
		for attempt, want := range profile.GCRetryBackoff {
			if got := GCRetryBackoffDelay(profile, attempt); got != want {
				t.Errorf("GCRetryBackoffDelay(profile, %d) = %v, want %v", attempt, got, want)
			}
		}
		last := profile.GCRetryBackoff[len(profile.GCRetryBackoff)-1]
		if got := GCRetryBackoffDelay(profile, 99); got != last {
			t.Errorf("GCRetryBackoffDelay(profile, 99) = %v, want %v (clamped to last step)", got, last)
		}
		if got := GCRetryBackoffDelay(profile, -1); got != profile.GCRetryBackoff[0] {
			t.Errorf("GCRetryBackoffDelay(profile, -1) = %v, want %v (clamped to first step)", got, profile.GCRetryBackoff[0])
		}
	}
}
