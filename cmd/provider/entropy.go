// Package main — Shannon entropy (M17-E Session 17.5.2, requirement 5).
//
// AONT-RS output is indistinguishable from random by design (ADR-019) — a
// stored chunk should measure at very close to the theoretical maximum of
// 8.0 bits/byte, while plaintext (English text, images with structure,
// most real files) measures noticeably lower. This file computes that
// number; it never asserts one. inspect.go's --compare flag is what makes
// the contrast land on an audience — see that file.
//
// [REF: ADR-019; build_M17E.md Phase 17.5 Session 17.5.2]
package main

import "math"

// shannonEntropy computes the Shannon entropy of data in bits per byte:
//
//	H = -Σ p_i · log2(p_i)
//
// over the 256 possible byte values, where p_i is the observed frequency
// of byte value i in data. Uniform random data lands at the theoretical
// maximum, 8.0 — though any finite real sample measures a little under
// that due to ordinary sampling variance, not a defect in the chunk or in
// this function.
//
// Computed here, not asserted: no caller may hardcode an expected value
// for what this function should return on real data. Requirement 5's
// proof depends on a genuine measurement, not a canned number — an
// audience needs to see the computation happen, not be told the answer in
// advance.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	total := float64(len(data))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
