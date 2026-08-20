// Package main — money formatting (M17-E Session 17.5.2, NFR-038).
//
// The single paise formatter every money-displaying path in cmd/provider
// uses. depart.go (Session 17.4.2) carried its own local
// formatPaiseAsRupees until this file existed, with a doc comment that
// named this exact consolidation as expected future work — done here:
// depart.go now calls formatPaise below, and its own copy is deleted.
//
// [REF: NFR-038; build_M17E.md Phase 17.5 Session 17.5.2]
package main

import "fmt"

// formatPaise renders paise as a rupee-and-paise string with no floating
// point anywhere in the computation — NFR-038's integer-arithmetic
// discipline for money, held to the same standard in this CLI package as
// internal/payment itself is held to server-side.
func formatPaise(paise int64) string {
	sign := ""
	if paise < 0 {
		sign = "-"
		paise = -paise
	}
	return fmt.Sprintf("%s\u20b9%d.%02d", sign, paise/paisePerRupee, paise%paisePerRupee)
}
