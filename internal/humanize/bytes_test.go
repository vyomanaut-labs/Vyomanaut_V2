package humanize

import "testing"

// TestFormatMBKnownValues pins FormatMB against real figures this system
// has actually produced, not synthetic round numbers only — 262144 is one
// shard (storage.ChunkDataSize at the demo/prod profile's shared
// ShardSize), 117544938 is the live demo video from a real upload
// (cmd/client/manage_cmds_test.go's own TestDeriveShardLayoutMatchesTheUploadersOwnSplit
// pins the same byte count), and 19922944 is a real "used" figure captured
// from a live `provider inspect` run (M18 Stage 1 verification).
func TestFormatMBKnownValues(t *testing.T) {
	cases := []struct {
		name  string
		bytes int64
		want  string
	}{
		{"zero", 0, "0.00 MB"},
		{"one byte rounds down to zero", 1, "0.00 MB"},
		{"one shard (ShardSize)", 262144, "0.25 MB"},
		{"exactly one MB", 1048576, "1.00 MB"},
		{"the 3328987-byte demo photo", 3328987, "3.17 MB"},
		{"the 117544938-byte demo video", 117544938, "112.10 MB"},
		{"one GB expressed in MB, never switched to GB", 1 << 30, "1024.00 MB"},
		{"a real captured provider-inspect used-bytes figure", 19922944, "19.00 MB"},
		{"negative input renders rather than panics", -1048576, "-1.00 MB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FormatMB(c.bytes); got != c.want {
				t.Errorf("FormatMB(%d) = %q, want %q", c.bytes, got, c.want)
			}
		})
	}
}

// TestFormatMBNeverAdaptsUnit guards the specific design decision this
// package's doc comment argues for: the same function must never switch to
// "KB", "GB", or bare "B" no matter how small or large the input is. A
// naive adaptive-unit humanizer (bytes for tiny values, GB for huge ones)
// would pass TestFormatMBKnownValues by coincidence at some inputs and fail
// at others — this test specifically targets the two ends of that range.
func TestFormatMBNeverAdaptsUnit(t *testing.T) {
	tiny := FormatMB(1)               // would be "1 B" or "1 byte" under an adaptive humanizer
	huge := FormatMB(500 * (1 << 30)) // 500 GB; would be "500.00 GB" under an adaptive humanizer

	for _, got := range []string{tiny, huge} {
		if !hasSuffix(got, " MB") {
			t.Errorf("FormatMB(%q) does not end in the fixed unit %q — unit must never adapt to magnitude", got, "MB")
		}
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
