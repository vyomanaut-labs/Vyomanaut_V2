// Package vettingchunk is declared in doc.go.
// This file defines all sentinel errors exported by the vettingchunk
// package (IC §5.10). Callers must compare using errors.Is; never construct
// these values inline. This is the single accumulating home for every
// sentinel error this package exports — mirrors the repair and scoring
// packages' own errors.go accumulating pattern — later
// sessions append further sentinels here.
//
// [REF: IC §5.10]

package vettingchunk

import "errors"

var (
	// ErrProviderOffline is returned by DeliverGCInstruction when the
	// provider cannot be reached. All synthetic chunk_assignments rows for
	// that provider have already been set to PENDING_DELETION before this
	// error is returned (IC §4.5); the caller must retry on the provider's
	// next successful heartbeat connection.
	ErrProviderOffline = errors.New("vettingchunk: provider not reachable for GC delivery")

	// ErrCapExceeded is returned when a provider's synthetic chunk count has
	// reached or exceeded floor(declared_storage_gb × 400) (IC §5.10 Cap).
	ErrCapExceeded = errors.New("vettingchunk: synthetic chunk cap exceeded for provider")

	// ErrNotVettingProvider is returned when the target provider's
	// providers.status is not 'VETTING' (IC §5.10 GenerateChunk
	// pre-condition).
	ErrNotVettingProvider = errors.New("vettingchunk: provider is not in VETTING status")
)