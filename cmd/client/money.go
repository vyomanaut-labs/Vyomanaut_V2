// The single paise-to-rupee formatter for cmd/client (TASK step 5, IC §11,
// NFR-038). int64 paise in, a plain string out — no floating point
// anywhere on this path, ever.
package main

import "strconv"

// paisePerRupee is India's fixed paise-to-rupee subdivision (100 paise = 1
// rupee), same constant NFR-038's money path relies on elsewhere.
const paisePerRupee = 100

// formatPaise renders paise as a rupee string with exactly two decimal
// places, entirely in integer arithmetic — no floating-point type or
// conversion of any kind, satisfying NFR-038's CI-enforced rule even though that
// rule technically scopes to internal/payment/ only (this is the same
// invariant applied consistently on cmd/client's own money-rendering
// path).
func formatPaise(paise int64) string {
	negative := paise < 0
	if negative {
		paise = -paise
	}
	rupees := paise / paisePerRupee
	cents := paise % paisePerRupee
	sign := ""
	if negative {
		sign = "-"
	}
	return sign + "₹" + strconv.FormatInt(rupees, 10) + "." + twoDigits(cents)
}

// decimalBase is the digit radix twoDigits splits n's tens/ones place by —
// distinct in meaning from paisePerRupee above even though both currently
// equal 100/10-adjacent values; named separately so a future reader never
// has to wonder whether they're the same constant in disguise.
const decimalBase = 10

// twoDigits zero-pads a 0-99 value to exactly two digits without fmt.Sprintf's
// %d-based formatting verbs (which read as suspiciously close to a
// float-formatting verb at a glance) — plain integer division/modulo,
// consistent with formatPaise's own no-float discipline.
func twoDigits(n int64) string {
	if n < 0 || n > 99 {
		n = 0 // defensive; paise%100 is always in [0,99] for the non-negative input formatPaise passes in
	}
	tens := n / decimalBase
	ones := n % decimalBase
	return strconv.FormatInt(tens, 10) + strconv.FormatInt(ones, 10)
}
