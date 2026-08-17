/*
// Package payment implements the PaymentProvider interface and the escrow ledger. ALL monetary amounts are int64 paise (₹1 = 100 paise). Passing float64 is a calling contract violation — it panics in debug builds.

Components:
  - PaymentProvider interface
  - Razorpay implementation
  - Escrow ledger

Ref: ADR-011, ADR-016, NFR-038
*/
package payment
