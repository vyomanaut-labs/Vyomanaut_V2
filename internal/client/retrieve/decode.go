// Package retrieve is declared in doc.go.
// This file implements segment decode (TASK step 3): RS-decode via
// erasure.Engine.DecodeSegment, then crypto.AONTDecodePackage. On
// crypto.ErrCanaryMismatch, zeroes whatever buffer was returned and returns
// ErrCanaryMismatch — no plaintext under any circumstance (IC §5.1, IC §5.9,
// FR-018).
//
// [Verified against the actual implementation, not assumed] Checked
// internal/crypto/aont.go's AONTDecodePackage before writing this file:
// on a canary mismatch it already zeroes its internal decryption buffer and
// returns nil (not the zeroed buffer) alongside ErrCanaryMismatch. The
// zeroing loop below is therefore a defense-in-depth no-op against the
// current implementation (ranging over a nil slice is zero iterations) —
// kept anyway so this file does not silently depend on AONTDecodePackage
// never changing to return a non-nil buffer on error in the future.
//
// [REF: IC §5.1 AONTDecodePackage, IC §5.9 ErrCanaryMismatch, FR-018,
// MVP §8.2 Phase 15.3 Session 15.3.1]

package retrieve

import (
	"errors"
	"fmt"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
)

// decodeSegment reconstructs a segment's plaintext from its downloaded
// shards.
func (o *Orchestrator) decodeSegment(shards [][]byte) ([]byte, error) {
	aontPkg, err := o.engine.DecodeSegment(shards)
	if err != nil {
		return nil, fmt.Errorf("decodeSegment: RS decode: %w", err)
	}

	plaintext, err := crypto.AONTDecodePackage(aontPkg, o.aesNI)
	if err != nil {
		if errors.Is(err, crypto.ErrCanaryMismatch) {
			for i := range plaintext {
				plaintext[i] = 0
			} // zero before return (IC §5.1) — see header note
			return nil, ErrCanaryMismatch
		}
		return nil, fmt.Errorf("decodeSegment: AONT decode: %w", err)
	}
	return plaintext, nil
}
