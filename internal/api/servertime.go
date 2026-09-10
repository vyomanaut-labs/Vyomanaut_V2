// Package api is declared in doc.go.
// This file implements GET /api/v1/time.
//
// [Added — not build.md-sourced] join.sh and join.ps1's clock-skew
// preflight (both scripts, added for the same reason: a real college-lab
// desktop run over ZeroTier where the join itself, the OTP exchange, and
// onboarding all succeeded cleanly, yet every heartbeat afterward came
// back "400: timestamp skew exceeds 5 minutes" until the provider was
// marked DEPARTED having never actually left) originally read the
// coordinator's clock off the HTTP Date response header of
// /.well-known/jwks.json (HandleJWKS, jwt.go) — an endpoint that happened
// to be unauthenticated for unrelated reasons, never designed as a time
// source. That worked, but cost both scripts a GNU-date/BSD-date (or, on
// Windows, DateTime.Parse) fallback branch just to turn an HTTP-date
// string back into an epoch. This endpoint returns UnixEpoch directly so
// neither script needs any date-parsing branch at all — see both
// scripts' own preflight blocks for the callers.
//
// Deliberately unauthenticated and DB-free, same trust tier as HandleJWKS
// and the pricing-estimate handlers: every timestamp check that actually
// gates anything (heartbeat, repair-download, vetting-gc) is
// authenticated on its own endpoint and depends only on this endpoint's
// accuracy, not its integrity — the coordinator's system clock is the
// coordinator's system clock regardless of who asks for it, and there is
// nothing here for an unauthenticated caller to forge that would matter.
//
// Not yet reflected in openapi.yaml (kept in the research repo, not this
// one) — needs a matching OAS entry and, per this project's own ADR
// governance, a short ADR or build.md session note before this is
// considered a permanently settled part of the wire contract rather than
// an ad hoc addition.
//
// [REF: none yet — new addition, not build.md-sourced]

package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// ServerTimeResponse is the body GET /api/v1/time returns.
type ServerTimeResponse struct {
	// UnixEpoch is the field callers should use for skew arithmetic — a
	// plain integer second count sidesteps every cross-platform
	// date-string-parsing difference (GNU `date -d` vs BSD `date -j`,
	// .NET DateTime.Parse locale/format quirks) the previous
	// JWKS-Date-header approach required both join scripts to handle.
	UnixEpoch int64 `json:"unix_epoch"`
	// UTC is included only for human-readable log lines and operator
	// messaging (e.g. "set the clock manually close to: ...") — no
	// caller should parse this field back into a time for skew math.
	UTC string `json:"utc"`
}

// HandleServerTime serves GET /api/v1/time.
func HandleServerTime(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	resp := ServerTimeResponse{
		UnixEpoch: now.Unix(),
		UTC:       now.Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
