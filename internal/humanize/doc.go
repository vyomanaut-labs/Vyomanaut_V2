/*
Package humanize formats byte counts for human-facing display only.

It exists because three separate command-line tools (cmd/client, cmd/operator,
cmd/provider) each print raw byte counts — a file's size, a shard's size, a
provider's used storage — to a non-technical audience (investors, faculty, a
college director) who has no reason to know that 262144 means anything, let
alone that it means a quarter of a megabyte. Before this package, each of
those three call sites either printed the bare integer with a literal
"bytes" suffix, or (transfer_cmds.go's retrieveThroughput) rolled its own
private MB constant. This package is the single place that conversion lives,
so a demo audience sees one unit, spelled one way, everywhere.

DISPLAY ONLY — READ THIS BEFORE ADDING A CALL SITE: every byte-denominated
calculation elsewhere in this system (segment/shard derivation in
cmd/client's deriveShardLayout, monthly cost in internal/payment's
fileMonthlyCostPaise, the NFR-044 chunk ceiling in cmd/provider's
nfr044ChunkCeilingMaxChunks, Shannon entropy in cmd/provider's
shannonEntropy) MUST keep computing in raw bytes, exactly as before this
package existed. FormatMB is a pure presentation function: it takes a byte
count that has already been computed, and returns a string. It is never
itself a step in a computation — nothing in this codebase may parse a
FormatMB result back into a number, and no caller may pass a FormatMB
result to a function that expects bytes. Each call site that uses this
package keeps its own test proving the underlying byte-denominated value
(the struct field, the derived segment count, the entropy figure) is
unchanged by this package's existence — see cmd/provider/inspect_test.go,
cmd/client/manage_cmds_test.go, cmd/client/transfer_cmds_test.go, and
cmd/operator/shards_test.go.

JSON output (every cmd/*'s --json flag) is deliberately NOT covered by this
package. A JSON response is a machine-readable contract for whatever
consumes it next (a script, another tool, a future UI) — it keeps the exact
byte-denominated fields it always had. Only the human-readable text tables
and printouts route through FormatMB.

MB, not KB or GB, and never adaptively switched between them: a demo
audience comparing a single 262144-byte shard (0.25 MB) against a
117544938-byte file (112.10 MB) needs both numbers on the same visible
scale to compare them at a glance. Switching units by magnitude (the more
common humanize-library behavior — bytes for small values, then KB, then
MB, then GB) would mean the exact same shard reads as "256 KB" in one
line of a table and "0.25 MB" in another, which is worse for a
non-technical audience than a single, always-MB convention, even at the
cost of a few extra decimal places on very small or very large values.

This package has nothing to do with "declared allocation: N GB"
(cmd/provider/inspect.go) or the GB column in `operator watch`'s Provider
Fleet panel — those are the operator's own chosen integer from
registration, never a byte-derived figure, so they were never bytes to
begin with and are untouched by this package.

[Added, M18 Session 18.2 — demo unit-legibility pass, Karma's own
observation that a general audience would misread a raw byte count as
something other than a size]
*/
package humanize
