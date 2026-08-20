package main

import "testing"

// TestFormatPaiseRendersRupeesWithNoFloat verifies formatPaise across
// zero, whole rupees, mixed paise, and negative amounts — the single
// formatter every money-displaying path in this package now uses
// (consolidated from depart.go's own former formatPaiseAsRupees, Session
// 17.4.2, per that file's own forecast of this consolidation).
func TestFormatPaiseRendersRupeesWithNoFloat(t *testing.T) {
	cases := []struct {
		paise int64
		want  string
	}{
		{0, "\u20b90.00"},
		{100, "\u20b91.00"},
		{12345, "\u20b9123.45"},
		{-500, "-\u20b95.00"},
	}
	for _, c := range cases {
		if got := formatPaise(c.paise); got != c.want {
			t.Errorf("formatPaise(%d) = %q, want %q", c.paise, got, c.want)
		}
	}
}
