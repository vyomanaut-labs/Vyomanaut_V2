// Package main — money formatting (M17-E Session 17.6.2, NFR-038).
//
// The single paise formatter the escrow panel uses. Mirrors
// cmd/provider/money.go's formatPaise exactly — same NFR-038 discipline,
// same shape — but this is a separate copy: cmd/operator and cmd/provider
// are different Go packages (different directories), so nothing can be
// shared between them without introducing a new internal/ package neither
// this session's nor 17.6.1's FILES list authorises.
//
// [REF: NFR-038; build_M17E.md Phase 17.6 Session 17.6.2]
package main

import "fmt"

const paisePerRupee = 100

// formatPaise renders paise as a rupee-and-paise string with no floating
// point anywhere in the computation — the escrow panel's own NFR-038
// requirement, and the only place in this package that formats money.
func formatPaise(paise int64) string {
	sign := ""
	if paise < 0 {
		sign = "-"
		paise = -paise
	}
	return fmt.Sprintf("%s\u20b9%d.%02d", sign, paise/paisePerRupee, paise%paisePerRupee)
}
