// ls, rm, balance, and deposit, wired over internal/client/manage per
// MVP §8.3. Calls manage.ListFiles, manage.DeleteFile, manage.Balance,
// manage.Deposit — never reimplements any of their HTTP/decryption logic.
//
// [REF: MVP §8.3, IC §14.2 (availability labels), ADR-035 (intent_url is
// server-owned), IC §11 / NFR-038 (no float on the money path)]
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/account"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/manage"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

func buildManager(g globalFlags, id *unlockedIdentity) *manage.Manager {
	return manage.NewManager(g.microserviceURL, id.Token, &http.Client{Timeout: cliHTTPClientTimeout})
}

// tabWriterTabWidth/tabWriterPadding are dispatchLs's text/tabwriter column
// tab width and inter-column padding — display-only constants, no IC/DM
// significance.
const (
	tabWriterTabWidth = 4
	tabWriterPadding  = 2
)

// unlockForReadOnly is the shared prologue every subcommand in this file
// needs: select the profile, load and decrypt the local identity. Named
// distinctly from transfer_cmds.go's own inline sequence only because
// these four subcommands don't also need a p2p.Host/erasure.Engine —
// factoring that difference out would cost more than the few duplicated
// lines it would save.
func unlockForReadOnly(g globalFlags, passphrase, mnemonic string, in *bufio.Reader, out, errOut io.Writer) (*unlockedIdentity, config.NetworkProfile, bool) {
	profile := config.SelectProfile(g.mode)
	if err := config.ValidateStartupGuards(profile); err != nil {
		fprintln(errOut, err)
		return nil, profile, false
	}
	id, err := loadIdentity(g.dataDir, passphrase, mnemonic, in, out, profile)
	if err != nil {
		printCLIError(errOut, g.json, err, renderError)
		return nil, profile, false
	}
	return id, profile, true
}

// ── ls ───────────────────────────────────────────────────────────────────

func dispatchLs(args []string, stdin io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	passphrase := fs.String("passphrase", "", "Passphrase to unlock the local identity. Prompted if omitted.")
	mnemonic := fs.String("mnemonic", "", "Mnemonic to unlock the local identity, as an alternative to --passphrase.")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if err := validateGlobalFlags(g); err != nil {
		fprintln(errOut, err)
		return exitUsage
	}

	in := bufio.NewReader(stdin)
	id, profile, ok := unlockForReadOnly(g, *passphrase, *mnemonic, in, out, errOut)
	if !ok {
		return 1
	}
	defer account.ZeroMasterSecret(&id.MasterSecret)

	m := buildManager(g, id)
	entries, err := m.ListFiles(context.Background(), id.MasterSecret, id.OwnerID)
	if err != nil {
		printCLIError(errOut, g.json, err, renderError)
		return 1
	}

	if g.json {
		type jsonEntry struct {
			FileID            string `json:"file_id"`
			DisplayName       string `json:"display_name"`
			SizeBytes         int64  `json:"size_bytes"`
			MonthlyCostPaise  int64  `json:"monthly_cost_paise"`
			AvailabilityLabel string `json:"availability_label"`
		}
		rows := make([]jsonEntry, len(entries))
		for i, e := range entries {
			rows[i] = jsonEntry{
				FileID: e.FileID.String(), DisplayName: e.DisplayName, SizeBytes: e.SizeBytes,
				MonthlyCostPaise: e.MonthlyCostPaise, AvailabilityLabel: e.AvailabilityLabel,
			}
		}
		data := marshalJSONNoEscape(rows)
		fprintln(out, data)
		return 0
	}

	if len(entries) == 0 {
		fprintln(out, "No files.")
		return 0
	}
	// AvailabilityLabel is already IC §14.2-mapped by manage.ListFiles —
	// this table prints it verbatim and never re-derives or invents a
	// label from the raw Availability enum itself.
	// [Extended, Session 18.1.7] SEGMENTS/SHARDS/NEED are shown so an owner
	// can see the redundancy their file actually has, which until now was
	// only visible to the operator via `operator shards`.
	//
	// All three are DERIVED from the profile and the file size, not
	// fetched: the owner's files endpoint returns no shard breakdown, and
	// inventing an endpoint for arithmetic the client can already do
	// exactly would be the wrong trade. deriveShardLayout documents the
	// derivation and its one assumption.
	tw := tabwriter.NewWriter(out, 0, tabWriterTabWidth, tabWriterPadding, ' ', 0)
	fprintln(tw, "FILE_ID\tNAME\tSIZE\tSEGMENTS\tSHARDS\tNEED\tSHARD_SIZE\tMONTHLY_COST\tAVAILABILITY")
	for _, e := range entries {
		segments, shards := deriveShardLayout(e.SizeBytes, profile)
		fprintf(tw, "%s\t%s\t%d bytes\t%d\t%d\t%d of %d\t%d bytes\t%s\t%s\n",
			e.FileID, e.DisplayName, e.SizeBytes,
			segments, shards, profile.DataShards, profile.TotalShards,
			profile.ShardSize,
			formatPaise(e.MonthlyCostPaise), e.AvailabilityLabel)
	}
	if err := tw.Flush(); err != nil {
		fprintf(errOut, "error writing table: %v\n", err)
		return 1
	}
	return 0
}

// ── rm ───────────────────────────────────────────────────────────────────

func dispatchRm(args []string, stdin io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	yes := fs.Bool("yes", false, "Skip the confirmation prompt.")
	passphrase := fs.String("passphrase", "", "Passphrase to unlock the local identity. Prompted if omitted.")
	mnemonic := fs.String("mnemonic", "", "Mnemonic to unlock the local identity, as an alternative to --passphrase.")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if err := validateGlobalFlags(g); err != nil {
		fprintln(errOut, err)
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fprintln(errOut, "usage: cmd/client rm <file_id> [--yes] [flags]")
		return exitUsage
	}
	fileID, err := uuid.Parse(rest[0])
	if err != nil {
		fprintf(errOut, "<file_id> must be a valid UUID: %v\n", err)
		return exitUsage
	}

	in := bufio.NewReader(stdin)
	if !*yes {
		answer, err := promptLine(out, in, fmt.Sprintf("Delete file %s? This cannot be undone. [y/N]: ", fileID))
		if err != nil {
			printCLIError(errOut, g.json, err, renderError)
			return 1
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fprintln(out, "Cancelled.")
			return 0
		}
	}

	id, _, ok := unlockForReadOnly(g, *passphrase, *mnemonic, in, out, errOut)
	if !ok {
		return 1
	}
	defer account.ZeroMasterSecret(&id.MasterSecret)

	m := buildManager(g, id)
	result, err := m.DeleteFile(context.Background(), fileID)
	if err != nil {
		printCLIError(errOut, g.json, err, renderError)
		return 1
	}

	if g.json {
		data := marshalJSONNoEscape(struct {
			FileID            string `json:"file_id"`
			AlreadyDeleted    bool   `json:"already_deleted"`
			AssignmentsMarked int    `json:"assignments_marked"`
			ProvidersNotified int    `json:"providers_notified"`
			ProvidersPending  int    `json:"providers_pending"`
		}{
			FileID: fileID.String(), AlreadyDeleted: result.AlreadyDeleted,
			AssignmentsMarked: result.AssignmentsMarked, ProvidersNotified: result.ProvidersNotified, ProvidersPending: result.ProvidersPending,
		})
		fprintln(out, data)
		return 0
	}
	if result.AlreadyDeleted {
		fprintln(out, "Already deleted.")
	} else {
		fprintf(out, "Deleted. %d provider(s) notified, %d pending.\n", result.ProvidersNotified, result.ProvidersPending)
	}
	return 0
}

// ── balance ──────────────────────────────────────────────────────────────

func dispatchBalance(args []string, stdin io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("balance", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	passphrase := fs.String("passphrase", "", "Passphrase to unlock the local identity. Prompted if omitted.")
	mnemonic := fs.String("mnemonic", "", "Mnemonic to unlock the local identity, as an alternative to --passphrase.")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if err := validateGlobalFlags(g); err != nil {
		fprintln(errOut, err)
		return exitUsage
	}

	in := bufio.NewReader(stdin)
	id, _, ok := unlockForReadOnly(g, *passphrase, *mnemonic, in, out, errOut)
	if !ok {
		return 1
	}
	defer account.ZeroMasterSecret(&id.MasterSecret)

	m := buildManager(g, id)
	balancePaise, reservedPaise, availablePaise, err := m.Balance(context.Background(), id.OwnerID)
	if err != nil {
		printCLIError(errOut, g.json, err, renderError)
		return 1
	}

	// The single paise formatter (money.go) is the only place any of these
	// three figures is rendered to text — no float anywhere on this path
	// (IC §11, NFR-038).
	if g.json {
		data := marshalJSONNoEscape(struct {
			BalancePaise         int64 `json:"balance_paise"`
			ReservedNext30dPaise int64 `json:"reserved_next_30d_paise"`
			AvailablePaise       int64 `json:"available_paise"`
		}{BalancePaise: balancePaise, ReservedNext30dPaise: reservedPaise, AvailablePaise: availablePaise})
		fprintln(out, data)
		return 0
	}
	fprintf(out, "Balance:            %s\n", formatPaise(balancePaise))
	fprintf(out, "Reserved (30 days): %s\n", formatPaise(reservedPaise))
	fprintf(out, "Available:          %s\n", formatPaise(availablePaise))
	return 0
}

// ── deposit ──────────────────────────────────────────────────────────────

func dispatchDeposit(args []string, stdin io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("deposit", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	amountPaise := fs.Int64("amount-paise", 0, "Amount to deposit, in whole paise (int64 — never a rupee/float amount).")
	passphrase := fs.String("passphrase", "", "Passphrase to unlock the local identity. Prompted if omitted.")
	mnemonic := fs.String("mnemonic", "", "Mnemonic to unlock the local identity, as an alternative to --passphrase.")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if err := validateGlobalFlags(g); err != nil {
		fprintln(errOut, err)
		return exitUsage
	}
	if *amountPaise <= 0 {
		fprintln(errOut, "--amount-paise must be a positive integer.")
		return exitUsage
	}

	in := bufio.NewReader(stdin)
	id, _, ok := unlockForReadOnly(g, *passphrase, *mnemonic, in, out, errOut)
	if !ok {
		return 1
	}
	defer account.ZeroMasterSecret(&id.MasterSecret)

	m := buildManager(g, id)
	// depositRequestID is fresh per CLI invocation — this session doesn't
	// give deposit a --resume-style flag the way upload has one, so there
	// is no persisted state across separate `deposit` runs to reuse a
	// prior attempt's ID from. Retry-safety within THIS invocation (if
	// manage.Deposit's own HTTP call were ever retried internally) is
	// still correct, since the same ID would be reused for that.
	depositRequestID := uuid.New()
	info, err := m.Deposit(context.Background(), id.OwnerID, depositRequestID, *amountPaise)
	if err != nil {
		printCLIError(errOut, g.json, err, renderError)
		return 1
	}

	// ADR-035: intent_url is server-owned. info.PrimaryOutput is exactly
	// what manage.Deposit decoded from the server's intent_url field when
	// present (manage/escrow.go's own DepositInfo doc comment) — rendered
	// verbatim by renderDepositOutput below. This file never builds a UPI
	// deep-link string of its own in either output mode.
	fprintln(out, renderDepositOutput(*amountPaise, info, g.json))
	return 0
}

// renderDepositOutput is dispatchDeposit's entire output-formatting logic,
// factored out as a pure function of (amountPaise, info, jsonMode) so it's
// directly testable without a live server standing in for manage.Deposit's
// HTTP call.
func renderDepositOutput(amountPaise int64, info manage.DepositInfo, jsonMode bool) string {
	if jsonMode {
		data := marshalJSONNoEscape(struct {
			AmountPaise   int64  `json:"amount_paise"`
			PrimaryOutput string `json:"primary_output"`
			UsesIntentURL bool   `json:"uses_intent_url"`
			QRCodeURL     string `json:"qr_code_url"`
		}{AmountPaise: amountPaise, PrimaryOutput: info.PrimaryOutput, UsesIntentURL: info.UsesIntentURL, QRCodeURL: info.QRCodeURL})
		return string(data)
	}
	var b strings.Builder
	fprintf(&b, "Deposit of %s initiated.\n", formatPaise(amountPaise))
	if info.UsesIntentURL {
		fprintf(&b, "Pay via: %s\n", info.PrimaryOutput) // the server's intent_url, rendered exactly as returned
	} else {
		fprintf(&b, "Pay to VPA: %s\n", info.PrimaryOutput)
	}
	fprintf(&b, "QR code: %s", info.QRCodeURL)
	return b.String()
}

// deriveShardLayout computes how a file of sizeBytes was split, from the
// profile alone.
//
// [Added, Session 18.1.7] A segment holds exactly DataShards x ShardSize
// bytes of plaintext (internal/client/upload/orchestrator.go's
// plaintextSegmentSize), and each segment becomes TotalShards shards. So:
//
//	segments = ceil(sizeBytes / (DataShards x ShardSize))
//	shards   = segments x TotalShards
//
// The one assumption is that the file was uploaded under THIS profile. That
// holds on the demo track, where only one profile ever runs and the demo
// repository is frozen at a single parameter set; it would not hold across
// a profile change, which is why this is derived at display time and never
// persisted as if it were a recorded fact.
//
// A zero-byte file yields zero segments rather than one — there is nothing
// to store, and rounding it up to a full segment would overstate both the
// redundancy and the cost.
func deriveShardLayout(sizeBytes int64, profile config.NetworkProfile) (segments, shards int64) {
	segmentBytes := int64(profile.DataShards) * int64(profile.ShardSize)
	if sizeBytes <= 0 || segmentBytes <= 0 {
		return 0, 0
	}
	segments = (sizeBytes + segmentBytes - 1) / segmentBytes
	return segments, segments * int64(profile.TotalShards)
}
