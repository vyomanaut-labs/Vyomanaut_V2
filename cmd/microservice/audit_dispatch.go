// cmd/microservice — see main.go's package doc comment.
//
// This file implements Session 12.1.2: the audit challenge dispatch loop.
// For each active chunk assignment, it builds and dispatches a
// ChallengeRequest (IC §4.2), waits for the provider's ChallengeResponse (or
// times out at the per-provider RTO), and records the three-phase receipt
// write, updating scoring state accordingly.
//
// [Flagged and fixed — closes a gap the session text itself left open] The
// given step 7 sketch ("On response: call audit.ValidateResponse(), then
// audit.WriteReceiptPhase2()") omits WriteReceiptRecordResponse entirely.
// internal/audit/receipt.go's own Milestone 7 corrections-session doc
// comment is explicit that WriteReceiptPhase2 "has no parameter for
// [response_hash/provider_sig] and never will — WriteReceiptRecordResponse
// must be called first to populate them while the row is still PENDING":
// calling Phase2 with result = AuditPass/AuditFail without that prior call
// fails DM §4.7's audit_receipts_response_consistency CHECK constraint.
// dispatchOneChallenge below calls WriteReceiptRecordResponse for every
// non-timeout status before Phase2, exactly as that doc comment requires —
// this is the same category of gap this session's own IsVersionValid note
// already flags for step 7a, just in a different function of the same
// three-phase write.
//
// [Corrected — M12 audit corrections, Finding 4 — FAIL-status (0x01/0x02)
// signature verification] IC §4.2's Frame 2 table documents a SECOND
// provider_sig signing-input shape for status 0x01/0x02
// (SHA-256(status_byte || nonce || ts || provider_id), vs.
// audit.ValidateResponse's SHA-256(response_hash || nonce || ts ||
// provider_id) for status 0x00). This was previously unimplemented —
// flagged rather than guessed at, consistent with this session's own
// precedent for unspecified wire-format details (see payment_provider.go,
// secrets_client.go) — but IC §4.2 fully specifies this second shape, so it
// is now implemented as audit.ValidateFailResponse and called below for
// status 0x01/0x02. Status 0x03/0x04 (INVALID_NONCE / INTERNAL_ERROR) carry
// no provider_sig at all per IC §4.2's own field table ("absent for 0x03,
// 0x04" — see readChallengeResponse) and so still map directly to AuditFail
// with no signature check: there is nothing to check, not a gap.
//
// This restores IC §4.2's stated purpose for the FAIL signature — proving
// the provider deliberately reported FAIL rather than a transport drop —
// but does NOT change the scoring outcome: an unverifiable FAIL claim (bad
// signature) still scores as AuditFail, the same as a verified one, for the
// same reason an unverifiable PASS claim below scores as AuditFail rather
// than AuditPass — see that comment. What changes is that a bad FAIL
// signature is now a distinguishable, loggable event instead of silently
// indistinguishable from a genuine one.
//
// [Corrected — M12 audit corrections, Finding 1 — challenge dispatch timing
// randomisation] FR-037, ADR-002, and ADR-014 all independently require
// audit challenge timing to be randomised within the polling window so a
// provider cannot anticipate when it will be challenged — see
// randomJitterDelay's own doc comment. dispatchAuditCycle previously fired
// every active chunk assignment's challenge at tick time with no jitter
// (bounded only by auditChallengeConcurrencyLimit, a throughput control,
// not a time-spreading one); it now assigns each assignment an independent
// random delay within [0, profile.PollingInterval) before dispatch. One
// consequence worth stating plainly: since dispatchAuditCycle still
// wg.Wait()s for every (now-delayed) dispatch before returning — preserving
// the existing "cycles never overlap" property rather than letting cycle
// N+1 start while cycle N's jittered dispatches are still in flight — a
// cycle's total wall-clock duration can now approach profile.PollingInterval
// itself in the worst case (an assignment drawing a delay near the top of
// the window, plus its own RTO), not just the time to fan out every
// dispatch immediately. This is the direct, unavoidable cost of genuinely
// spreading dispatch across the full window rather than clustering it at
// the front; it does not reintroduce the overlapping-cycles behaviour the
// audit's own Recheck pass confirmed was clean, and Go's ticker (buffer of
// 1, extra ticks dropped, never queued) means no goroutine pile-up results
// either.
//
// [REF: IC §4.2, DM §4.7, ADR-002, ADR-014, ADR-015, ADR-027, FR-037,
// FR-038, FR-040, build.md Milestone 7 corrections session, Milestone 12
// Phase 12.1 Session 12.1.2, Milestone 12 audit corrections Finding 1]
package main

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/audit"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/scoring"
)

// auditChallengeProtocolID is IC §4.2's protocol ID.
const auditChallengeProtocolID = p2p.ProtocolID("/vyomanaut/audit-challenge/1.0.0")

// Wire-format field sizes (IC §4.2 Frame 1/Frame 2) — named rather than
// inlined so no raw byte-count literal appears in the framing arithmetic
// below (this codebase's "no magic numbers" standard).
const (
	lengthPrefixSize        = 4  // uint32 big-endian frame length prefix
	chunkIDFieldSize        = 32 // SHA-256 content address
	challengeNonceFieldSize = 33 // 1-byte version prefix || 32-byte HMAC-SHA256
	serverTsFieldSize       = 8  // int64 big-endian
	responseHashFieldSize   = 32
	providerSigFieldSize    = 64

	// challengeRequestFrameSize is IC §4.2's Frame 1 payload length: 32 + 33
	// + 8 = 73 bytes.
	challengeRequestFrameSize = chunkIDFieldSize + challengeNonceFieldSize + serverTsFieldSize // 73

	challengeResponseOKSize   = 1 + responseHashFieldSize + providerSigFieldSize // 97
	challengeResponseFailSize = 1 + providerSigFieldSize                         // 65
)

// ChallengeResponse status codes (IC §4.2 Frame 2).
const (
	challengeStatusOK             = 0x00
	challengeStatusFailNotFound   = 0x01
	challengeStatusFailCorruption = 0x02
	challengeStatusInvalidNonce   = 0x03
	challengeStatusInternalError  = 0x04
)

// auditChallengeConcurrencyLimit bounds concurrent in-flight challenge
// streams across the whole dispatch cycle. IC §4.2: "the provider daemon
// must handle at least 32 concurrent challenge streams without queuing
// delay" — this is a network-wide bound on the microservice's own
// dispatcher, not a per-provider one; a value at that same floor keeps the
// microservice from ever being the bottleneck relative to what every
// provider is already required to support.
const auditChallengeConcurrencyLimit = 32

// throughputBytesPerKB and msPerSecondFloat are unit-conversion constants
// for computeThroughputKbps below — not "magic numbers" in the sense this
// codebase's standard prohibits (see internal/audit/jit.go's own msPerSecond
// constant for the same pattern), just named unit conversions.
const (
	throughputBytesPerKB = 1024
	msPerSecondFloat     = 1000.0
)

// runAuditDispatchLoop implements Session 12.1.2: on profile.PollingInterval,
// dispatch one audit challenge per active chunk assignment, bounded by
// auditChallengeConcurrencyLimit concurrent streams (IC §4.2's concurrency
// allowance). Blocks until ctx is cancelled.
func runAuditDispatchLoop(
	ctx context.Context,
	db *sql.DB,
	profile config.NetworkProfile,
	cache *audit.ClusterSecretCache,
	host p2p.Host,
	dht p2p.DHT,
	signingKey ed25519.PrivateKey,
) {
	ticker := time.NewTicker(profile.PollingInterval)
	defer ticker.Stop()
	sem := make(chan struct{}, auditChallengeConcurrencyLimit)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dispatchAuditCycle(ctx, db, profile, cache, host, dht, signingKey, sem)
		}
	}
}

// chunkAssignmentRow is one row from active_chunk_assignments, joined with
// providers and segments for the fields dispatchOneChallenge needs.
type chunkAssignmentRow struct {
	ChunkID        [32]byte
	FileID         *uuid.UUID
	ProviderID     uuid.UUID
	MultiaddrStale bool
}

// loadActiveChunkAssignments queries active_chunk_assignments (IC §2, DM
// §4.2) for every currently active assignment, joined against segments for
// file_id (NULL for vetting chunks — ReceiptFields.FileID's own documented
// nil-for-vetting semantics, DM §8.20) and providers for
// multiaddr_stale (DM §4.7's AddressWasStale source).
func loadActiveChunkAssignments(ctx context.Context, db *sql.DB) ([]chunkAssignmentRow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT ca.chunk_id, s.file_id, ca.provider_id, p.multiaddr_stale
		FROM active_chunk_assignments ca
		LEFT JOIN segments s ON s.segment_id = ca.segment_id
		JOIN providers p ON p.provider_id = ca.provider_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("loadActiveChunkAssignments: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []chunkAssignmentRow
	for rows.Next() {
		var (
			chunkIDBytes []byte
			fileID       *uuid.UUID
			a            chunkAssignmentRow
		)
		if err := rows.Scan(&chunkIDBytes, &fileID, &a.ProviderID, &a.MultiaddrStale); err != nil {
			return nil, fmt.Errorf("loadActiveChunkAssignments: scan: %w", err)
		}
		copy(a.ChunkID[:], chunkIDBytes)
		a.FileID = fileID
		out = append(out, a)
	}
	return out, rows.Err()
}

// dispatchAuditCycle runs one full pass over every active chunk assignment,
// dispatching challenges concurrently (bounded by sem).
func dispatchAuditCycle(
	ctx context.Context,
	db *sql.DB,
	profile config.NetworkProfile,
	cache *audit.ClusterSecretCache,
	host p2p.Host,
	dht p2p.DHT,
	signingKey ed25519.PrivateKey,
	sem chan struct{},
) {
	assignments, err := loadActiveChunkAssignments(ctx, db)
	if err != nil {
		log.Printf("[AUDIT] loadActiveChunkAssignments: %v", err)
		return
	}

	var wg sync.WaitGroup
	for _, assignment := range assignments {
		assignment := assignment

		// FR-037 / ADR-002 / ADR-014: this chunk's dispatch is delayed by an
		// independent random offset within the polling window, computed
		// once per assignment here at cycle start — see this file's header
		// note. A jitter-generation failure skips this one chunk for this
		// cycle rather than silently falling back to zero delay (which
		// would defeat the anti-prediction purpose for exactly that chunk
		// without anyone noticing); it is picked up again next cycle.
		delay, err := randomJitterDelay(profile.PollingInterval)
		if err != nil {
			log.Printf("[AUDIT] randomJitterDelay for chunk assigned to provider %s: %v", assignment.ProviderID, err)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return
			}

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if err := dispatchOneChallenge(ctx, db, profile, cache, host, dht, signingKey, assignment); err != nil {
				log.Printf("[AUDIT] dispatch to provider %s: %v", assignment.ProviderID, err)
			}
		}()
	}
	wg.Wait()
}

// randomJitterDelay returns a cryptographically random duration in
// [0, window) — FR-037 / ADR-002 / ADR-014 require per-chunk challenge
// dispatch timing a provider cannot anticipate. crypto/rand (not math/rand)
// is used for the same reason every other timing- or identity-relevant
// random value in this codebase does (see cmd/microservice/keys.go,
// internal/p2p/identity.go): this is specifically an anti-prediction
// security control, exactly the kind of value that must not depend on a
// PRNG a sufficiently motivated adversary could ever have a chance of
// modelling — a provider gaming this exact mechanism is the attack ADR-002
// and ADR-014 name.
//
// window <= 0 returns a zero delay rather than an error (defensive only;
// profile.PollingInterval is always positive in both NetworkProfile
// configurations — see config.DemoProfile / config.ProductionProfile).
func randomJitterDelay(window time.Duration) (time.Duration, error) {
	if window <= 0 {
		return 0, nil
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(window)))
	if err != nil {
		return 0, fmt.Errorf("randomJitterDelay: %w", err)
	}
	return time.Duration(n.Int64()), nil
}

// dispatchOneChallenge runs the full per-chunk audit challenge protocol
// (IC §4.2) for one active chunk assignment.
func dispatchOneChallenge(
	ctx context.Context,
	db *sql.DB,
	profile config.NetworkProfile,
	cache *audit.ClusterSecretCache,
	host p2p.Host,
	dht p2p.DHT,
	signingKey ed25519.PrivateKey,
	assignment chunkAssignmentRow,
) error {
	// Step 2 (Session 12.1.2 task text): build the challenge nonce.
	secret, versionByte, err := cache.CurrentSecret()
	if err != nil {
		return fmt.Errorf("current secret: %w", err)
	}
	serverTsMs := time.Now().UnixMilli()
	nonce := audit.ChallengeNonce(secret, versionByte, assignment.ChunkID, serverTsMs)

	// Step 3: Phase 1 write BEFORE dispatch.
	fields := audit.ReceiptFields{
		ChunkID:           assignment.ChunkID,
		FileID:            assignment.FileID,
		ProviderID:        assignment.ProviderID,
		ChallengeNonce:    nonce,
		ServerChallengeTs: time.UnixMilli(serverTsMs),
		AddressWasStale:   assignment.MultiaddrStale,
	}
	receiptID, err := audit.WriteReceiptPhase1(ctx, db, fields)
	if err != nil {
		return fmt.Errorf("WriteReceiptPhase1: %w", err)
	}

	// Step 4-5: resolve the provider's real p2p identity, connect, and open
	// the /vyomanaut/audit-challenge/1.0.0 stream (repairTransport-equivalent
	// for audit — the same p2p.Host session 12.1.1 constructs).
	stream, dispatchStart, err := openChallengeStream(ctx, db, host, dht, assignment.ProviderID)
	if err != nil {
		// Cannot even reach the provider: treat as a genuine TIMEOUT (no
		// response is possible without a stream) rather than leaving the
		// receipt PENDING forever.
		return finalizeTimeout(ctx, db, signingKey, receiptID, assignment)
	}
	defer func() { _ = stream.Close() }()

	// Step 6: apply the per-provider RTO timeout.
	rto, err := computeRTO(ctx, db, assignment.ProviderID)
	if err != nil {
		return fmt.Errorf("computeRTO: %w", err)
	}
	if err := stream.SetDeadline(dispatchStart.Add(rto)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	if err := writeChallengeRequest(stream, assignment.ChunkID, nonce, serverTsMs); err != nil {
		return finalizeTimeout(ctx, db, signingKey, receiptID, assignment)
	}

	status, responseHash, providerSig, err := readChallengeResponse(stream)
	if err != nil {
		// Deadline exceeded or transport error: genuine TIMEOUT (IC §4.2:
		// "If the timeout elapses, the microservice records
		// audit_result = TIMEOUT and resets the stream").
		return finalizeTimeout(ctx, db, signingKey, receiptID, assignment)
	}
	responseLatencyMs := int(time.Since(dispatchStart).Milliseconds())

	// Step 7a (Milestone 7 Phase 7.2's item 2, deferred to here): a response
	// under a since-retired secret version is not adjudicated at all.
	if !cache.IsVersionValid(nonce[0]) {
		log.Printf("[AUDIT] provider %s: response under retired secret version %d; leaving receipt %s PENDING",
			assignment.ProviderID, nonce[0], receiptID)
		return nil
	}

	result, err := adjudicateResponse(ctx, db, nonce, serverTsMs, assignment.ProviderID, status, responseHash, providerSig)
	if err != nil {
		return fmt.Errorf("adjudicate response: %w", err)
	}

	// WriteReceiptRecordResponse MUST run before Phase2 for PASS/FAIL — see
	// this file's header note.
	p95ThroughputKbps, err := currentP95ThroughputKbps(ctx, db, assignment.ProviderID)
	if err != nil {
		return fmt.Errorf("currentP95ThroughputKbps: %w", err)
	}
	if err := audit.WriteReceiptRecordResponse(ctx, db, receiptID, responseHash, providerSig, responseLatencyMs, p95ThroughputKbps); err != nil {
		return fmt.Errorf("WriteReceiptRecordResponse: %w", err)
	}

	serviceSig, serviceTS := signServiceReceipt(signingKey, receiptID, result)
	if err := audit.WriteReceiptPhase2(ctx, db, receiptID, result, serviceSig, serviceTS); err != nil {
		return fmt.Errorf("WriteReceiptPhase2: %w", err)
	}

	// Step 8.
	if result == audit.AuditPass {
		if err := scoring.IncrementConsecutivePasses(ctx, db, assignment.ProviderID, profile); err != nil && !errors.Is(err, scoring.ErrProviderNotVetting) {
			log.Printf("[AUDIT] IncrementConsecutivePasses: %v", err)
		}
	} else if result != audit.AuditTimeout || !assignment.MultiaddrStale {
		if err := scoring.ResetConsecutivePasses(ctx, db, assignment.ProviderID); err != nil {
			log.Printf("[AUDIT] ResetConsecutivePasses: %v", err)
		}
	}

	// Step 9: never called for TIMEOUT (no response_latency_ms to sample).
	// Guard: result != AuditTimeout.
	if result != audit.AuditTimeout {
		throughputKbps := computeThroughputKbps(profile, responseLatencyMs)
		if err := scoring.UpdateRTO(ctx, db, assignment.ProviderID, responseLatencyMs, throughputKbps); err != nil {
			log.Printf("[AUDIT] UpdateRTO: %v", err)
		}
	}
	return nil
}

// openChallengeStream resolves assignment's provider to a real p2p peer,
// connects, and opens the audit-challenge stream. Returns the dispatch
// timestamp captured immediately before the stream open, for
// responseLatencyMs measurement.
func openChallengeStream(ctx context.Context, db *sql.DB, host p2p.Host, dht p2p.DHT, providerID uuid.UUID) (p2p.Stream, time.Time, error) {
	peerID, addrs, err := resolveProviderPeer(ctx, db, dht, providerID)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := host.Connect(ctx, peerID, addrs); err != nil {
		return nil, time.Time{}, err
	}
	dispatchStart := time.Now()
	stream, err := host.NewStream(ctx, peerID, auditChallengeProtocolID)
	if err != nil {
		return nil, time.Time{}, err
	}
	return stream, dispatchStart, nil
}

// writeChallengeRequest writes IC §4.2's Frame 1: length(4) || chunk_id(32)
// || challenge_nonce(33) || server_challenge_ts_ms(8) = 73-byte payload.
func writeChallengeRequest(w io.Writer, chunkID [32]byte, nonce [33]byte, serverTsMs int64) error {
	var frame [lengthPrefixSize + challengeRequestFrameSize]byte
	binary.BigEndian.PutUint32(frame[0:lengthPrefixSize], challengeRequestFrameSize)
	offset := lengthPrefixSize
	copy(frame[offset:offset+chunkIDFieldSize], chunkID[:])
	offset += chunkIDFieldSize
	copy(frame[offset:offset+challengeNonceFieldSize], nonce[:])
	offset += challengeNonceFieldSize
	binary.BigEndian.PutUint64(frame[offset:offset+serverTsFieldSize], uint64(serverTsMs))
	_, err := w.Write(frame[:])
	return err
}

// readChallengeResponse reads IC §4.2's Frame 2 and returns the raw status
// byte plus response_hash/provider_sig (zero-valued fields when the status
// doesn't carry them — see IC §4.2's Frame 2 field table).
func readChallengeResponse(r io.Reader) (status byte, responseHash [32]byte, providerSig [64]byte, err error) {
	var lengthBuf [lengthPrefixSize]byte
	if _, err = io.ReadFull(r, lengthBuf[:]); err != nil {
		return 0, responseHash, providerSig, err
	}
	length := binary.BigEndian.Uint32(lengthBuf[:])
	body := make([]byte, length)
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, responseHash, providerSig, err
	}
	if len(body) < 1 {
		return 0, responseHash, providerSig, fmt.Errorf("readChallengeResponse: empty body")
	}
	status = body[0]
	switch status {
	case challengeStatusOK:
		if len(body) != challengeResponseOKSize {
			return 0, responseHash, providerSig, fmt.Errorf("readChallengeResponse: status OK but body length %d, want %d", len(body), challengeResponseOKSize)
		}
		copy(responseHash[:], body[1:1+responseHashFieldSize])
		copy(providerSig[:], body[1+responseHashFieldSize:])
	case challengeStatusFailNotFound, challengeStatusFailCorruption:
		if len(body) != challengeResponseFailSize {
			return 0, responseHash, providerSig, fmt.Errorf("readChallengeResponse: status 0x%02x but body length %d, want %d", status, len(body), challengeResponseFailSize)
		}
		copy(providerSig[:], body[1:])
	case challengeStatusInvalidNonce, challengeStatusInternalError:
		// No response_hash, no provider_sig (IC §4.2: "absent for 0x03, 0x04").
	default:
		return 0, responseHash, providerSig, fmt.Errorf("readChallengeResponse: unrecognised status 0x%02x", status)
	}
	return status, responseHash, providerSig, nil
}

// adjudicateResponse maps a ChallengeResponse's status/signature into an
// audit.AuditResult. Status 0x00 goes through audit.ValidateResponse
// (nonce, responseHash, serverChallengeTsMs, providerID, providerSig,
// providerPubKey); status 0x01/0x02 go through audit.ValidateFailResponse,
// IC §4.2's second, distinct signing-input shape (see this file's header
// note — Finding 4). Status 0x03/0x04 carry no provider_sig at all (IC
// §4.2: "absent for 0x03, 0x04") and map directly to AuditFail with no
// signature check — there is nothing to verify, not a gap.
func adjudicateResponse(
	ctx context.Context,
	db *sql.DB,
	nonce [33]byte,
	serverChallengeTsMs int64,
	providerUUID uuid.UUID,
	status byte,
	responseHash [32]byte,
	providerSig [64]byte,
) (audit.AuditResult, error) {
	switch status {
	case challengeStatusInvalidNonce, challengeStatusInternalError:
		return audit.AuditFail, nil
	}

	providerPubKey, err := lookupProviderPubKey(ctx, db, providerUUID)
	if err != nil {
		return audit.AuditFail, fmt.Errorf("lookupProviderPubKey: %w", err)
	}
	providerID := [16]byte(providerUUID)

	if status == challengeStatusOK {
		if err := audit.ValidateResponse(nonce, responseHash, serverChallengeTsMs, providerID, providerSig, providerPubKey); err != nil {
			// An unverifiable PASS claim is functionally equivalent to a
			// failed audit from the network's perspective — no valid
			// cryptographic proof of possession was given (see this
			// file's header note; no document in scope specifies this
			// mapping explicitly).
			return audit.AuditFail, nil
		}
		return audit.AuditPass, nil
	}

	// status is challengeStatusFailNotFound or challengeStatusFailCorruption
	// (readChallengeResponse rejects any other value outright, so no other
	// case can reach here).
	if err := audit.ValidateFailResponse(status, nonce, serverChallengeTsMs, providerID, providerSig, providerPubKey); err != nil {
		// A FAIL claim with an invalid signature is still scored as
		// AuditFail (the chunk audit did not pass either way) — but log it
		// distinctly, since an unverifiable FAIL is a materially different
		// event than a genuine one: it means the provider_sig on this FAIL
		// frame does not actually prove the provider sent it, which is
		// exactly the case IC §4.2 requires this signature to distinguish
		// (see this file's header note).
		log.Printf("[AUDIT] provider %s: FAIL response (status 0x%02x) has an invalid provider_sig — scoring as FAIL but this is not a proven deliberate report", providerUUID, status)
	}
	return audit.AuditFail, nil
}

// finalizeTimeout writes the TIMEOUT terminal state for a receipt that
// never got a usable response — no WriteReceiptRecordResponse call (a
// genuine TIMEOUT never has a response_latency_ms to record, DM §4.7 §8.10)
// — then applies step 8's scoring gate.
func finalizeTimeout(ctx context.Context, db *sql.DB, signingKey ed25519.PrivateKey, receiptID uuid.UUID, assignment chunkAssignmentRow) error {
	serviceSig, serviceTS := signServiceReceipt(signingKey, receiptID, audit.AuditTimeout)
	if err := audit.WriteReceiptPhase2(ctx, db, receiptID, audit.AuditTimeout, serviceSig, serviceTS); err != nil {
		return fmt.Errorf("WriteReceiptPhase2 (timeout): %w", err)
	}
	// A stale-address TIMEOUT does nothing, per DM §4.7 (Milestone 8 Phase
	// 8.2). As of the M12 audit corrections (Finding 2), a real DHT
	// fallback now runs inside resolveProviderPeer before this point is
	// ever reached for a TIMEOUT — so this guard's practical meaning has
	// narrowed: it now means the DHT fallback was tried and still came up
	// empty (or dht was nil), not "no fallback exists at all." Either way,
	// the scoring rationale is unchanged: a stale-address TIMEOUT is still
	// not attributable to the provider's own behaviour, so it must not
	// reset consecutive passes.
	if !assignment.MultiaddrStale {
		if err := scoring.ResetConsecutivePasses(ctx, db, assignment.ProviderID); err != nil {
			log.Printf("[AUDIT] ResetConsecutivePasses (timeout): %v", err)
		}
	}
	// UpdateRTO is never called for TIMEOUT.
	return nil
}

// lookupProviderPubKey reads providers.ed25519_public_key for providerID.
func lookupProviderPubKey(ctx context.Context, db *sql.DB, providerID uuid.UUID) ([32]byte, error) {
	var pubKey []byte
	var out [32]byte
	if err := db.QueryRowContext(ctx, `SELECT ed25519_public_key FROM providers WHERE provider_id = $1`, providerID).Scan(&pubKey); err != nil {
		return out, err
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return out, fmt.Errorf("lookupProviderPubKey: provider %s: ed25519_public_key is %d bytes, want %d", providerID, len(pubKey), ed25519.PublicKeySize)
	}
	copy(out[:], pubKey)
	return out, nil
}

// bootstrapFallbackRTO is used only when scoring.PoolMedianRTO itself has
// nothing to compute from yet (scoring.ErrNoPoolMedianAvailable — "no
// provider has an established measurement," expected only very early in the
// network's life, per that sentinel's own doc comment).
//
// [Bumped — F-17E-07, live verification, M17-E Phase 17.7 departure-matrix
// debugging] No document in scope specifies a value for this bootstrap-only
// edge case. 5 seconds (this constant's original value) is exactly the
// window during which every provider in the live-verification harness is
// simultaneously cold-starting on one machine — 7 real provider daemons,
// the microservice, and Postgres all competing for CPU, each doing real
// TLS handshakes, RocksDB opens, and (for account setup) Argon2 hashing —
// so it is also the least representative moment to assume a steady-state
// RTT. A single provider drawing a genuinely slow (but not hung — see
// internal/p2p/host.go's F-17E-06 fix for the unbounded-hang case this
// does NOT cover) first response against that tight a bound reaches
// finalizeTimeout, which unconditionally calls scoring.ResetConsecutivePasses
// unless the address was already known-stale — wiping consecutive_audit_passes
// back to 0. Bumped to 15s: still generous enough to tighten automatically
// the moment any provider reaches rto_sample_count >= 5 and a real pool
// median becomes available (same self-correcting behaviour as before), just
// wide enough to stop the coldest-start window from being the likeliest
// place for a spurious reset. This does not touch the RESET behaviour
// itself — see that mechanism's own flagged, unresolved question (this
// session's handoff) about whether a single failing chunk among a
// provider's several concurrent vetting-chunk assignments should be able to
// wipe out passes already earned by its siblings in the same cycle.
const bootstrapFallbackRTO = 15 * time.Second

const rtoVarianceMultiplier = 4

// computeRTO returns the per-provider RTO timeout (IC §4.2): the pool-median
// RTO for a provider with fewer than 5 samples, otherwise
// avg_rtt_ms + 4*var_rtt_ms from that provider's own row (ADR-006, FR-040,
// Milestone 8).
func computeRTO(ctx context.Context, db *sql.DB, providerID uuid.UUID) (time.Duration, error) {
	const rtoSampleThreshold = 5

	var (
		sampleCount int
		avgRTT      sql.NullFloat64
		varRTT      sql.NullFloat64
	)
	err := db.QueryRowContext(ctx,
		`SELECT rto_sample_count, avg_rtt_ms, var_rtt_ms FROM providers WHERE provider_id = $1`,
		providerID,
	).Scan(&sampleCount, &avgRTT, &varRTT)
	if err != nil {
		return 0, err
	}

	if sampleCount < rtoSampleThreshold || !avgRTT.Valid {
		medianMs, err := scoring.PoolMedianRTO(ctx, db)
		if err != nil {
			if errors.Is(err, scoring.ErrNoPoolMedianAvailable) {
				return bootstrapFallbackRTO, nil
			}
			return 0, err
		}
		return time.Duration(medianMs * float64(time.Millisecond)), nil
	}

	rtoMs := avgRTT.Float64 + rtoVarianceMultiplier*varRTT.Float64
	return time.Duration(rtoMs * float64(time.Millisecond)), nil
}

// currentP95ThroughputKbps reads providers.p95_throughput_kbps BEFORE
// scoring.UpdateRTO updates it — WriteReceiptRecordResponse's own doc
// comment requires this exact read/pass-through pattern (see
// internal/audit/receipt.go): "the caller's responsibility to supply, from
// the same providers row read the IC §6 EWMA update already requires."
func currentP95ThroughputKbps(ctx context.Context, db *sql.DB, providerID uuid.UUID) (*float64, error) {
	var p95 sql.NullFloat64
	if err := db.QueryRowContext(ctx, `SELECT p95_throughput_kbps FROM providers WHERE provider_id = $1`, providerID).Scan(&p95); err != nil {
		return nil, err
	}
	if !p95.Valid {
		return nil, nil
	}
	v := p95.Float64
	return &v, nil
}

// computeThroughputKbps derives this response's measured throughput from
// the fixed 256 KB shard size (profile.ShardSize, DM §3 Invariant 7) and the
// observed responseLatencyMs, for scoring.UpdateRTO's own EWMA update.
func computeThroughputKbps(profile config.NetworkProfile, responseLatencyMs int) float64 {
	if responseLatencyMs <= 0 {
		return 0
	}
	chunkSizeKB := float64(profile.ShardSize) / throughputBytesPerKB
	seconds := float64(responseLatencyMs) / msPerSecondFloat
	return chunkSizeKB / seconds
}

const (
	auditResultByteLen = 1
	unixMillisByteLen  = 8
)

// signServiceReceipt computes service_sig — the microservice's own
// countersignature over the terminal audit result (analogous to
// internal/api/provider.go's microservice_sig; no document in scope
// specifies this exact signing input, so one is defined here following that
// same file's established "hand-constructed, fixed-field-order byte
// sequence, never JSON" convention: receipt_id(16) || audit_result(1) ||
// service_countersign_ts_ms(8)).
func signServiceReceipt(signingKey ed25519.PrivateKey, receiptID uuid.UUID, result audit.AuditResult) ([64]byte, time.Time) {
	now := time.Now()
	input := make(
		[]byte,
		0,
		len(receiptID)+
			auditResultByteLen+
			unixMillisByteLen)
	input = append(input, receiptID[:]...)
	input = append(input, byte(result))
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(now.UnixMilli()))
	input = append(input, tsBuf[:]...)

	sig := ed25519.Sign(signingKey, input)
	var out [64]byte
	copy(out[:], sig)
	return out, now
}
