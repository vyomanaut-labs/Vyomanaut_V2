// Package account is declared in doc.go.
// This file implements the two-word mnemonic confirmation gate (TASK step
// 2, FR-003). crypto.SelectConfirmationWords always runs — even in demo
// mode — per its own doc comment: "this function may still be called; the
// caller simply does not block on user input." Only the blocking prompt is
// skipped when profile.SkipMnemonicConfirm == true.
//
// [REF: IC §5.1 SelectConfirmationWords, MVP §8.2 Phase 15.1 Session 15.1.1,
// FR-003]

package account

import (
	"fmt"

	"github.com/masamasaowl/Vyomanaut_V2/internal/config"
	"github.com/masamasaowl/Vyomanaut_V2/internal/crypto"
)

// ConfirmPrompter is the minimal UI hook this package needs from its
// caller: given the 0-based word index to confirm, return what the user
// typed for that position. A CLI implementation reads a line from stdin; a
// GUI implementation reads a text field. A function type rather than an
// interface, so a caller can pass a closure without a wrapper struct.
type ConfirmPrompter func(wordIndex int) (typed string)

// ConfirmMnemonic runs the two-word confirmation gate (FR-003) over
// mnemonic. crypto.SelectConfirmationWords is called unconditionally, in
// both demo and normal mode, so the same index-selection code path is
// exercised either way; only the blocking prompt is conditional on
// profile.SkipMnemonicConfirm.
//
// Pre-conditions:
//   - len(mnemonic) == 24 (crypto.SelectConfirmationWords' own
//     pre-condition; violating it panics, per that function's contract —
//     this is not re-validated here, since re-checking would just duplicate
//     that function's own guarantee)
//   - prompt is non-nil unless profile.SkipMnemonicConfirm == true
//
// Post-conditions (on nil error):
//   - in normal mode: the words the user typed at the two
//     SelectConfirmationWords-selected indices matched mnemonic exactly
//   - in demo mode (profile.SkipMnemonicConfirm == true): always succeeds
//     without blocking, regardless of prompt
//
// Error semantics: returns a plain error (not a package sentinel — this is
// a UI-level mismatch, not a cryptographic failure) if either typed word
// doesn't match. The message identifies the mismatch only as "word 1" /
// "word 2" by prompt order, never by the mnemonic's 0–23 position, so a
// failed confirmation attempt doesn't itself disclose which of the 24
// positions was selected beyond what the prompt already showed the user.
//
// Goroutine-safe: yes (no shared state).
func ConfirmMnemonic(mnemonic []string, profile config.NetworkProfile, prompt ConfirmPrompter) error {
	indexA, indexB := crypto.SelectConfirmationWords(mnemonic)

	if profile.SkipMnemonicConfirm {
		return nil
	}
	if prompt == nil {
		return fmt.Errorf("account: ConfirmMnemonic: prompt is required unless profile.SkipMnemonicConfirm is true")
	}

	if typed := prompt(indexA); typed != mnemonic[indexA] {
		return fmt.Errorf("account: ConfirmMnemonic: word 1 did not match")
	}
	if typed := prompt(indexB); typed != mnemonic[indexB] {
		return fmt.Errorf("account: ConfirmMnemonic: word 2 did not match")
	}
	return nil
}
