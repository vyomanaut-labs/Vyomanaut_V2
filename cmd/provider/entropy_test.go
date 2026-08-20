package main

import (
	"crypto/rand"
	"strings"
	"testing"
)

// TestEntropyTests is a thin wrapper so `go test -run TestEntropyTests`
// matches every test below — same pattern the rest of this package's test
// files already use.
func TestEntropyTests(t *testing.T) {
	t.Run("TestEntropyOfUniformRandomExceeds7Point9", TestEntropyOfUniformRandomExceeds7Point9)
	t.Run("TestEntropyOfRepeatedByteIsZero", TestEntropyOfRepeatedByteIsZero)
	t.Run("TestEntropyOfEnglishTextIsBelow5", TestEntropyOfEnglishTextIsBelow5)
	t.Run("TestEntropyOfEmptyDataIsZero", TestEntropyOfEmptyDataIsZero)
}

// TestEntropyOfUniformRandomExceeds7Point9 verifies genuinely random data
// (crypto/rand, standing in for AONT-RS output — indistinguishable from
// random by design) measures close to the theoretical maximum.
func TestEntropyOfUniformRandomExceeds7Point9(t *testing.T) {
	data := make([]byte, 65536)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	got := shannonEntropy(data)
	if got <= 7.9 {
		t.Errorf("shannonEntropy(uniform random, 65536 bytes) = %v, want > 7.9", got)
	}
}

// TestEntropyOfRepeatedByteIsZero verifies the degenerate single-symbol
// case: exactly one distinct byte value carries zero information.
func TestEntropyOfRepeatedByteIsZero(t *testing.T) {
	data := make([]byte, 65536)
	for i := range data {
		data[i] = 0xAB
	}
	got := shannonEntropy(data)
	if got != 0 {
		t.Errorf("shannonEntropy(single repeated byte) = %v, want exactly 0", got)
	}
}

// TestEntropyOfEnglishTextIsBelow5 verifies ordinary structured text
// measures well below random — the contrast --compare (inspect.go) is
// built to show.
func TestEntropyOfEnglishTextIsBelow5(t *testing.T) {
	text := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200)
	got := shannonEntropy([]byte(text))
	if got >= 5.0 {
		t.Errorf("shannonEntropy(English text) = %v, want < 5.0", got)
	}
}

// TestEntropyOfEmptyDataIsZero verifies the empty-input edge case returns
// 0 rather than NaN (log2(0) is undefined; the len(data)==0 guard exists
// specifically for this).
func TestEntropyOfEmptyDataIsZero(t *testing.T) {
	if got := shannonEntropy(nil); got != 0 {
		t.Errorf("shannonEntropy(nil) = %v, want 0", got)
	}
}
