// Package account is declared in doc.go.
// This file is the UI gate for the master secret (TASK step 3): it holds no
// state of its own — Identity.MasterSecret (register.go) or the [32]byte
// returned by recover.go IS the master secret, passed by value from here on.
// Every other client package (upload, retrieve, manage) receives the master
// secret as a [32]byte parameter to its own entry points; none of them
// reads this file's internals directly because there is nothing here to
// read — that is the point of the gate: the master secret's only home is
// the caller's local variable, for exactly as long as the current
// CLI/GUI session needs it, and this file exists to name that discipline
// and provide the one hygiene helper (ZeroMasterSecret) every session
// end-point should call.
//
// [REF: MVP §8.2 Phase 15.1 Session 15.1.1]

package account

// ZeroMasterSecret overwrites secret's bytes in place. Callers should call
// this when a session ends (logout, process exit handler, or after the
// last operation that needs it in a single-shot CLI invocation) so the
// master secret does not linger in memory longer than necessary. This
// cannot guarantee removal from every copy the Go runtime may have made
// (e.g. a stack-to-heap escape before this call) — it is the best available
// hygiene step, not a formal guarantee, mirroring the same
// zero-before-return discipline internal/client/retrieve/decode.go applies
// on an AONT canary mismatch (IC §5.1 AONTDecodePackage's own "caller MUST
// NOT return any plaintext ... zero the buffer" contract).
//
// Goroutine-safe: yes (operates only on the caller-owned array pointed to
// by secret; callers must not call this concurrently with a read of the
// same secret).
func ZeroMasterSecret(secret *[32]byte) {
	for i := range secret {
		secret[i] = 0
	}
}