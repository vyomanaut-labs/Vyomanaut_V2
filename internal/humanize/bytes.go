package humanize

import "fmt"

// BytesPerMB is the single definition of "one megabyte" this system's
// human-facing output uses: 2^20 (binary), matching every other
// storage-unit constant already in this codebase (cmd/provider/inspect.go's
// bytesPerGB is 1<<30 for exactly this reason; cmd/client/transfer_cmds.go's
// own bytesPerMB, used only for the retrieve throughput line, is folded
// into this one constant rather than kept as a second private definition
// that could silently drift from it) — never the decimal-million SI
// convention some tools use instead.
const BytesPerMB = 1 << 20

// FormatMB renders n bytes as a fixed two-decimal-place megabyte figure,
// e.g. FormatMB(262144) == "0.25 MB", FormatMB(117544938) == "112.10 MB".
//
// Always MB, never bytes, KB, or GB, and never adaptively switched between
// units by magnitude — see this package's doc comment for why a single
// fixed unit matters more here than the extra decimal places a very small
// or very large value costs. A negative n (which should never occur for a
// real byte count, but this function does not assume its caller validated
// that) renders as a negative MB figure rather than panicking — display
// code's job is to show what it was given, not to silently mask an upstream
// bug by clamping it away.
func FormatMB(n int64) string {
	mb := float64(n) / float64(BytesPerMB)
	return fmt.Sprintf("%.2f MB", mb)
}
