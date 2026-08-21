// Package main — `operator shards <file_id>` (M17-E Session 17.6.1,
// ADR-084 §D-2a, requirement 4's parenthetical made visible).
//
// This command prints the operator's complete view of one file: per-chunk
// placement (chunk_id, segment_id, shard_index, provider_id, asn,
// size_bytes) plus the file's original_size_bytes and its
// display_name_ciphertext — rendered ONLY as hex, explicitly labelled as
// ciphertext this command cannot read. That label is the point: shown next
// to the owner's real filename (which this command never has and never
// requests), it is requirement 4's confidentiality claim made visible
// rather than merely asserted (I-DEMO-1, this package's own doc comment in
// main.go).
//
// [REF: ADR-084 D-2a, ADR-020; internal/api/admin.go Session 17.6.1;
// build_M17E.md Phase 17.6 Session 17.6.1]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"text/tabwriter"
)

func dispatchShards(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("operator shards", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	g.adminAPIKey = resolveAdminAPIKey(g.adminAPIKey)
	if err := validateGlobalFlags(g); err != nil {
		fprintln(errOut, err)
		return exitUsage
	}

	rest := fs.Args()
	if len(rest) != 1 {
		fprintln(errOut, "usage: operator shards <file_id> [flags]")
		return exitUsage
	}
	fileID := rest[0]

	client := newAdminClient(g.microserviceURL, g.adminAPIKey)
	resp, err := client.fetchFileShards(context.Background(), fileID)
	if err != nil {
		fprintf(errOut, "vyomanaut operator shards: %v\n", err)
		return 1
	}

	renderShards(out, resp, g.json)
	return 0
}

const (
	tableTabWidth = 2
	tablePadding  = 2
)

// renderShards writes resp to out. jsonOutput selects the same
// machine-readable-vs-human-readable split every other cmd/*'s --json flag
// already establishes (cmd/client, cmd/provider earnings.go).
func renderShards(out io.Writer, resp shardsAdminResponseBody, jsonOutput bool) {
	if jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return
	}

	fprintf(out, "File %s\n", resp.FileID)
	fprintf(out, "  original size:  %d bytes\n", resp.OriginalSizeBytes)
	if resp.DisplayNameCiphertext != nil {
		fprintf(out, "  display name:   %s  (display_name_ciphertext — AEAD ciphertext; the operator cannot read this, ADR-020)\n", *resp.DisplayNameCiphertext)
	} else {
		fprintln(out, "  display name:   (none set)")
	}
	fprintf(out, "  shards:         %d\n\n", len(resp.Shards))

	tw := tabwriter.NewWriter(out, 0, tableTabWidth, tablePadding, ' ', 0)
	fprintln(tw, "SEGMENT_ID\tSHARD\tCHUNK_ID\tPROVIDER_ID\tASN\tSIZE_BYTES")
	for _, s := range resp.Shards {
		fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%d\n", s.SegmentID, s.ShardIndex, s.ChunkID, s.ProviderID, s.ASN, s.SizeBytes)
	}
	_ = tw.Flush()
}
