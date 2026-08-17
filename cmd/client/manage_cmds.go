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

// unlockForReadOnly is the shared prologue every subcommand in this file
// needs: select the profile, load and decrypt the local identity. Named
// distinctly from transfer_cmds.go's own inline sequence only because
// these four subcommands don't also need a p2p.Host/erasure.Engine —
// factoring that difference out would cost more than the few duplicated
// lines it would save.
func unlockForReadOnly(g globalFlags, passphrase, mnemonic string, in *bufio.Reader, out, errOut io.Writer) (*unlockedIdentity, config.NetworkProfile, bool) {
	profile := config.SelectProfile(g.mode)
	if err := config.ValidateStartupGuards(profile); err != nil {
		fmt.Fprintln(errOut, err)
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
		return 2
	}
	if err := validateGlobalFlags(g); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}

	in := bufio.NewReader(stdin)
	id, _, ok := unlockForReadOnly(g, *passphrase, *mnemonic, in, out, errOut)
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
		fmt.Fprintln(out, data)
		return 0
	}

	if len(entries) == 0 {
		fmt.Fprintln(out, "No files.")
		return 0
	}
	// AvailabilityLabel is already IC §14.2-mapped by manage.ListFiles —
	// this table prints it verbatim and never re-derives or invents a
	// label from the raw Availability enum itself.
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "FILE_ID\tNAME\tSIZE\tMONTHLY_COST\tAVAILABILITY")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%d bytes\t%s\t%s\n", e.FileID, e.DisplayName, e.SizeBytes, formatPaise(e.MonthlyCostPaise), e.AvailabilityLabel)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(errOut, "error writing table: %v\n", err)
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
		return 2
	}
	if err := validateGlobalFlags(g); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintln(errOut, "usage: cmd/client rm <file_id> [--yes] [flags]")
		return 2
	}
	fileID, err := uuid.Parse(rest[0])
	if err != nil {
		fmt.Fprintf(errOut, "<file_id> must be a valid UUID: %v\n", err)
		return 2
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
			fmt.Fprintln(out, "Cancelled.")
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
		fmt.Fprintln(out, data)
		return 0
	}
	if result.AlreadyDeleted {
		fmt.Fprintln(out, "Already deleted.")
	} else {
		fmt.Fprintf(out, "Deleted. %d provider(s) notified, %d pending.\n", result.ProvidersNotified, result.ProvidersPending)
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
		return 2
	}
	if err := validateGlobalFlags(g); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
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
		fmt.Fprintln(out, data)
		return 0
	}
	fmt.Fprintf(out, "Balance:            %s\n", formatPaise(balancePaise))
	fmt.Fprintf(out, "Reserved (30 days): %s\n", formatPaise(reservedPaise))
	fmt.Fprintf(out, "Available:          %s\n", formatPaise(availablePaise))
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
		return 2
	}
	if err := validateGlobalFlags(g); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	if *amountPaise <= 0 {
		fmt.Fprintln(errOut, "--amount-paise must be a positive integer.")
		return 2
	}

	in := bufio.NewReader(stdin)
	id, _, ok := unlockForReadOnly(g, *passphrase, *mnemonic, in, out, errOut)
	if !ok {
		return 1
	}
	defer account.ZeroMasterSecret(&id.MasterSecret)

	m := buildManager(g, id)
	info, err := m.Deposit(context.Background(), *amountPaise)
	if err != nil {
		printCLIError(errOut, g.json, err, renderError)
		return 1
	}

	// ADR-035: intent_url is server-owned. info.PrimaryOutput is exactly
	// what manage.Deposit decoded from the server's intent_url field when
	// present (manage/escrow.go's own DepositInfo doc comment) — rendered
	// verbatim by renderDepositOutput below. This file never builds a UPI
	// deep-link string of its own in either output mode.
	fmt.Fprintln(out, renderDepositOutput(*amountPaise, info, g.json))
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
	fmt.Fprintf(&b, "Deposit of %s initiated.\n", formatPaise(amountPaise))
	if info.UsesIntentURL {
		fmt.Fprintf(&b, "Pay via: %s\n", info.PrimaryOutput) // the server's intent_url, rendered exactly as returned
	} else {
		fmt.Fprintf(&b, "Pay to VPA: %s\n", info.PrimaryOutput)
	}
	fmt.Fprintf(&b, "QR code: %s", info.QRCodeURL)
	return b.String()
}
