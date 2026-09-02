// upload and retrieve, wired over internal/client/upload and
// internal/client/retrieve per MVP §8.3 and IC §5.9. This file calls
// upload.UploadFile and upload.ResumeUpload (via the *upload.Orchestrator
// orch returned by upload.NewOrchestrator) and retrieve.RetrieveFile (via
// retrieve.NewOrchestrator's *retrieve.Orchestrator) — never reimplements
// encode, transfer, decode, or assignment logic itself.
//
// Progress reporting: IC §5.9's UploadFile signature (preserved exactly by
// internal/client/upload) is one blocking call with no progress callback
// and no way to learn file_id before it returns — there is no hook to
// report true incremental progress from outside the call. This file
// instead polls upload.SaveSessionState's own on-disk session file
// (already exported, written before transfer begins and updated as shards
// are acknowledged — see internal/client/upload/session.go) from a
// background goroutine while UploadFile runs, and derives a percentage
// from AckStatus. This is real progress, not a fabricated animation, built
// entirely from already-exported machinery — no internal/client/upload
// change was needed or made. Progress goes to errOut — in the real
// invocation path (main.go -> run() -> dispatchUpload/dispatchRetrieve),
// errOut is os.Stderr; dispatch_test.go/account_cmds_test.go's own tests
// pass a bytes.Buffer instead so progress output doesn't pollute stdout in
// --json mode and so this file stays testable without a real terminal.
//
// [REF: IC §5.9, MVP §8.3, internal/client/upload/session.go,
// internal/client/retrieve/orchestrator.go]
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/account"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/retrieve"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/client/upload"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/crypto"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/erasure"
	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// renderTransferError renders the four IC §14-relevant error paths TASK
// step 4 names explicitly, with copy specific to each, falling back to
// renderError's generic table lookup for everything else. Two of the four
// (ErrTooFewShards, ErrCanaryMismatch) are client-detected conditions the
// server never issues an error_code for — IC §14.1's table has no row for
// either, since that table maps server error_codes specifically — so the
// copy below is written in that section's own voice rather than left to
// renderError's generic "no server error_code at all" fallback, since
// these are common, well-understood failure modes worth naming precisely
// rather than folding into a catch-all message.
func renderTransferError(err error) string {
	switch {
	case errors.Is(err, upload.ErrInsufficientEscrow):
		return formatCopy(copyTable["INSUFFICIENT_ESCROW_BALANCE"]) + "\nRun `cmd/client deposit` to add funds, then retry the upload."
	case errors.Is(err, upload.ErrNetworkNotReady):
		// A normal state, not an alarm (TASK step 4's own framing) — IC
		// §14.1's NETWORK_NOT_READY row already reads this way ("Retrying
		// automatically — no action needed").
		return formatCopy(copyTable["NETWORK_NOT_READY"])
	case errors.Is(err, retrieve.ErrTooFewShards):
		return "Not enough providers were reachable to retrieve this file right now.\nThis isn't necessarily permanent — try again in a moment, or check your network connection."
	case errors.Is(err, crypto.ErrCanaryMismatch):
		return "This file's data could not be verified after decoding — it may be corrupted.\nTry retrieving again; if this persists, contact support with the file_id."
	default:
		return renderError(err)
	}
}

// localCodedError lets a purely client-detected condition (never a server
// error_code) still carry a real IC §14.1-style code through --json
// output, by implementing the exact codedError interface render.go's
// generic errorCodeOf/renderErrorJSON already check for — no changes
// needed there.
type localCodedError struct {
	error
	code string
}

func (e *localCodedError) ErrorCode() string { return e.code }
func (e *localCodedError) Unwrap() error     { return e.error }

// withTransferErrorCode maps two of renderTransferError's four local
// sentinels to the same IC §14.1 codes for --json mode (the other two,
// ErrTooFewShards/ErrCanaryMismatch, have no IC §14.1 row at all — see
// renderTransferError's own note — so they're left unwrapped and fall
// through to errorCodeOf's ordinary fallback).
//
// [Bug found and fixed, live TestDemoCLIUploadFailsBeforeDeposit run]
// printCLIError's --json path always called the generic errorCodeOf,
// which has no knowledge of local sentinels — only renderTransferError
// (the human-readable path) did. A live run got error_code="" instead of
// INSUFFICIENT_ESCROW_BALANCE because of exactly this gap; every call
// site below now wraps err before handing it to printCLIError. Wrapping
// preserves errors.Is/errors.As on the original sentinel via Unwrap, so
// renderTransferError's own switch above still matches correctly on the
// wrapped value.
func withTransferErrorCode(err error) error {
	switch {
	case errors.Is(err, upload.ErrInsufficientEscrow):
		return &localCodedError{error: err, code: "INSUFFICIENT_ESCROW_BALANCE"}
	case errors.Is(err, upload.ErrNetworkNotReady):
		return &localCodedError{error: err, code: "NETWORK_NOT_READY"}
	default:
		return err
	}
}

// buildHostAndEngine constructs the p2p.Host (client-only: no ListenAddr,
// so it accepts no inbound streams — this is a data-owner CLI, not a
// provider daemon) and erasure.Engine every upload/retrieve call shares.
// Callers must Close() the returned host when done.
func buildHostAndEngine(profile config.NetworkProfile, signingKey []byte) (p2p.Host, *erasure.Engine, error) {
	host, err := p2p.NewHost(p2p.HostConfig{PrivateKey: signingKey, ListenAddr: ""})
	if err != nil {
		return nil, nil, fmt.Errorf("cmd/client: construct p2p host: %w", err)
	}
	engine, err := erasure.NewEngine(profile)
	if err != nil {
		_ = host.Close()
		return nil, nil, fmt.Errorf("cmd/client: construct erasure engine: %w", err)
	}
	return host, engine, nil
}

func uploadSessionDir(dataDir string) string {
	return filepath.Join(dataDir, "upload-sessions")
}

// ── upload ───────────────────────────────────────────────────────────────

func dispatchUpload(args []string, stdin io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	resume := fs.String("resume", "", "Resume an interrupted upload by its file_id (session_id) instead of uploading a new file (upload.ResumeUpload).")
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
	if *resume == "" && len(rest) < 1 {
		fprintln(errOut, "usage: cmd/client upload <path> [flags]   OR   cmd/client upload --resume <file_id> [flags]")
		return exitUsage
	}

	profile := config.SelectProfile(g.mode)
	if err := config.ValidateStartupGuards(profile); err != nil {
		fprintln(errOut, err)
		return 1
	}

	in := bufio.NewReader(stdin)
	id, err := loadIdentity(g.dataDir, *passphrase, *mnemonic, in, out, profile)
	if err != nil {
		printCLIError(errOut, g.json, err, renderError)
		return 1
	}
	defer account.ZeroMasterSecret(&id.MasterSecret)

	host, engine, err := buildHostAndEngine(profile, id.SigningKey)
	if err != nil {
		printCLIError(errOut, g.json, err, renderError)
		return 1
	}
	defer func() { _ = host.Close() }()

	sessionDir := uploadSessionDir(g.dataDir)
	orch := upload.NewOrchestrator(g.microserviceURL, id.Token, &http.Client{Timeout: cliHTTPClientTimeout}, host, engine, profile, id.SigningKey, sessionDir)

	ctx := context.Background()

	if *resume != "" {
		fileID, err := uuid.Parse(*resume)
		if err != nil {
			fprintf(errOut, "--resume must be a valid file_id (UUID): %v\n", err)
			return exitUsage
		}
		stopProgress := startUploadProgress(sessionDir, fileID, errOut)
		err = orch.ResumeUpload(ctx, id.MasterSecret, id.OwnerID, fileID)
		stopProgress()
		if err != nil {
			printCLIError(errOut, g.json, withTransferErrorCode(err), renderTransferError)
			return 1
		}
		printUploadResult(g.json, fileID, out)
		return 0
	}

	path := rest[0]
	plaintext, err := os.ReadFile(path)
	if err != nil {
		fprintf(errOut, "Could not read %s: %v\n", path, err)
		return 1
	}

	stopProgress := startUploadProgressForNewSession(sessionDir, errOut)
	fileID, err := orch.UploadFile(ctx, id.MasterSecret, id.OwnerID, plaintext)
	stopProgress()
	if err != nil {
		if errors.Is(err, upload.ErrUploadIncomplete) {
			fprintf(errOut, "Upload incomplete; resume later with: cmd/client upload --resume %s\n", fileID)
		}
		printCLIError(errOut, g.json, withTransferErrorCode(err), renderTransferError)
		return 1
	}
	printUploadResult(g.json, fileID, out)
	return 0
}

func printUploadResult(jsonMode bool, fileID uuid.UUID, out io.Writer) {
	if jsonMode {
		data := marshalJSONNoEscape(struct {
			FileID string `json:"file_id"`
		}{FileID: fileID.String()})
		fprintln(out, data)
	} else {
		fprintln(out, fileID.String())
	}
}

const uploadProgressPollInterval = 500 * time.Millisecond

// progressPercentScale converts an acked/total shard ratio to a percentage
// for reportUploadProgress's display text below.
const progressPercentScale = 100

// startUploadProgressForNewSession watches sessionDir for the new session
// file UploadFile is about to create (its file_id isn't known to the
// caller until UploadFile returns), then reports percentage from it.
// Returns a stop function; safe to call even if no session file ever
// appeared (a very fast or very small upload).
func startUploadProgressForNewSession(sessionDir string, errOut io.Writer) (stop func()) {
	before := map[string]bool{}
	if entries, err := os.ReadDir(sessionDir); err == nil {
		for _, e := range entries {
			before[e.Name()] = true
		}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(uploadProgressPollInterval)
		defer ticker.Stop()
		var tracking uuid.UUID
		tracked := false
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if !tracked {
					entries, err := os.ReadDir(sessionDir)
					if err != nil {
						continue
					}
					for _, e := range entries {
						if before[e.Name()] {
							continue
						}
						fileID, ok := fileIDFromSessionFileName(e.Name())
						if !ok {
							continue
						}
						tracking, tracked = fileID, true
						break
					}
				}
				if tracked {
					reportUploadProgress(sessionDir, tracking, errOut)
				}
			}
		}
	}()
	return func() { close(done); fprintln(errOut) }
}

// startUploadProgress is the --resume variant: file_id is already known.
func startUploadProgress(sessionDir string, fileID uuid.UUID, errOut io.Writer) (stop func()) {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(uploadProgressPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				reportUploadProgress(sessionDir, fileID, errOut)
			}
		}
	}()
	return func() { close(done); fprintln(errOut) }
}

func fileIDFromSessionFileName(name string) (uuid.UUID, bool) {
	const suffix = ".upload-session.json"
	if !strings.HasSuffix(name, suffix) {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(strings.TrimSuffix(name, suffix))
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}

func reportUploadProgress(sessionDir string, fileID uuid.UUID, errOut io.Writer) {
	sess, err := upload.LoadSessionState(sessionDir, fileID)
	if err != nil {
		return // not written yet, or already cleaned up (upload finished) — not an error for progress purposes
	}
	total, acked := 0, 0
	for _, seg := range sess.AckStatus {
		total += len(seg)
		for _, a := range seg {
			if a {
				acked++
			}
		}
	}
	if total == 0 {
		return
	}
	pct := acked * progressPercentScale / total
	fprintf(errOut, "\rUploading  %s  %d%%  (%d/%d shards)", uploadProgressBar(acked, total), pct, acked, total)
}

// uploadProgressBarWidth is the cell count of the upload bar. Matches
// cmd/operator's progressBarWidth so the two surfaces of this demo look
// like one product; they are separate constants because the packages do not
// import each other (cmd/ is wiring only, IC §11) and a shared internal
// package for one integer would need its own depguard rule.
const uploadProgressBarWidth = 24

// uploadProgressBar renders acked/total as a filled bar.
//
// [Added, Session 18.1.5] The percentage this replaces was real but easy to
// miss: it redraws in place on one line, so on a large upload a viewer sees
// a number that looks static for long stretches. A bar makes the same data
// legible from across a room, which is the whole reason it changed.
//
// The blocks are U+2588 and U+2591, both single-column, so the bar's
// display width equals uploadProgressBarWidth exactly.
//
// This is a presentation of a genuine ratio — acked shards over total
// shards, read from the upload session state on disk — not an animation on
// a timer. If the transfer stalls, the bar stalls with it, which is the
// correct and useful behaviour.
func uploadProgressBar(acked, total int) string {
	if total <= 0 {
		return strings.Repeat("\u2591", uploadProgressBarWidth)
	}
	filled := acked * uploadProgressBarWidth / total
	if filled > uploadProgressBarWidth {
		filled = uploadProgressBarWidth
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("\u2588", filled) + strings.Repeat("\u2591", uploadProgressBarWidth-filled)
}

// ── retrieve ─────────────────────────────────────────────────────────────

// defaultRetrieveOutputPath is TASK step 2's "-o out. Default filename from
// the pointer file" — factored out as a pure function for direct testing.
// RetrieveFile's own return signature has no display-name output at all
// (IC §5.9), and upload.Orchestrator.UploadFile never populates one in
// practice (see -o's own flag description in dispatchRetrieve below), so
// pointerDisplayName is "" for anything actually uploaded through this
// system today; the fileID fallback is what always happens in practice.
// The parameter exists so this doesn't silently do nothing if a future
// session closes the upload-side filename gap.
func defaultRetrieveOutputPath(outFlag string, fileID uuid.UUID, pointerDisplayName string) string {
	if outFlag != "" {
		return outFlag
	}
	if pointerDisplayName != "" {
		return pointerDisplayName
	}
	return fileID.String()
}

func dispatchRetrieve(args []string, stdin io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("retrieve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	outPath := fs.String("o", "", "Output file path. Defaults to the pointer file's display name if one was set at upload time, or <file_id> otherwise — the current upload path never actually sets a display name (see internal/client/upload/orchestrator.go's own header note on IC §5.9's missing filename parameter), so the <file_id> fallback is what happens in practice today.")
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
		fprintln(errOut, "usage: cmd/client retrieve <file_id> [-o out] [flags]")
		return exitUsage
	}
	fileID, err := uuid.Parse(rest[0])
	if err != nil {
		fprintf(errOut, "<file_id> must be a valid UUID: %v\n", err)
		return exitUsage
	}

	profile := config.SelectProfile(g.mode)
	if err := config.ValidateStartupGuards(profile); err != nil {
		fprintln(errOut, err)
		return 1
	}

	in := bufio.NewReader(stdin)
	id, err := loadIdentity(g.dataDir, *passphrase, *mnemonic, in, out, profile)
	if err != nil {
		printCLIError(errOut, g.json, err, renderError)
		return 1
	}
	defer account.ZeroMasterSecret(&id.MasterSecret)

	host, engine, err := buildHostAndEngine(profile, id.SigningKey)
	if err != nil {
		printCLIError(errOut, g.json, err, renderError)
		return 1
	}
	defer func() { _ = host.Close() }()

	orch := retrieve.NewOrchestrator(g.microserviceURL, id.Token, &http.Client{Timeout: cliHTTPClientTimeout}, host, engine, profile)

	// [Changed, Session 18.1.5] No percentage here, deliberately.
	// RetrieveFile (IC §5.9) is ONE blocking call with no progress
	// callback, and unlike upload it writes no session state to disk, so
	// there is nothing this layer can observe to compute a ratio from —
	// upload's bar is real precisely because acked shards are readable
	// mid-flight, and retrieval has no equivalent. A spinner or a timed
	// bar here would be an animation with nothing behind it, which is the
	// one thing this demo's surfaces do not do.
	//
	// What IS said instead is true and worth saying out loud: the
	// reconstruction only needs DataShards of TotalShards per segment, so
	// the line states the redundancy the network is actually exercising.
	// Giving retrieval a real bar means adding a progress callback to
	// internal/client/retrieve — a contract change, tracked rather than
	// faked.
	fprintf(errOut, "Retrieving  (rebuilding each segment from any %d of %d shards)...",
		profile.DataShards, profile.TotalShards)
	startedAt := time.Now()
	plaintext, err := orch.RetrieveFile(context.Background(), id.MasterSecret, id.OwnerID, fileID)
	elapsed := time.Since(startedAt)
	fprintln(errOut)
	if err != nil {
		printCLIError(errOut, g.json, withTransferErrorCode(err), renderTransferError)
		return 1
	}

	outFile := defaultRetrieveOutputPath(*outPath, fileID, "")

	// privateFilePermissions (localstore.go): a retrieved file is decrypted
	// plaintext of the owner's own data, same privacy bar as the local
	// keystore — owner-only read/write.
	if err := os.WriteFile(outFile, plaintext, privateFilePermissions); err != nil {
		fprintf(errOut, "Downloaded but could not write %s: %v\n", outFile, err)
		return 1
	}

	if g.json {
		data := marshalJSONNoEscape(struct {
			FileID     string `json:"file_id"`
			OutputPath string `json:"output_path"`
			Bytes      int    `json:"bytes"`
		}{FileID: fileID.String(), OutputPath: outFile, Bytes: len(plaintext)})
		fprintln(out, data)
	} else {
		fprintf(out, "Retrieved %d bytes to %s\n", len(plaintext), outFile)
		// [Added, Session 18.1.5] Measured, not estimated: wall-clock
		// around the one RetrieveFile call, over the byte count it
		// actually returned. Reported after the fact for the same reason
		// no bar is drawn during — see the note at the call site.
		fprintf(errOut, "  rebuilt in %s (%s)\n", roundRetrieveDuration(elapsed), retrieveThroughput(len(plaintext), elapsed))
	}
	return 0
}

// roundRetrieveDuration renders a retrieval's wall-clock time at a
// precision a person reads rather than a benchmark does.
func roundRetrieveDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

// bytesPerMB is the divisor for the throughput line. 1<<20, matching the
// binary MB the rest of this system measures storage in.
const bytesPerMB = 1 << 20

// retrieveThroughput renders observed MB/s, or "—" when the elapsed time is
// too small to divide by meaningfully. A tiny file retrieved in under a
// millisecond would otherwise print an enormous rate that says nothing
// about the network.
func retrieveThroughput(n int, d time.Duration) string {
	if d <= 0 || n <= 0 {
		return "rate n/a"
	}
	mbps := (float64(n) / bytesPerMB) / d.Seconds()
	if mbps < 0.01 {
		return "rate n/a"
	}
	return fmt.Sprintf("%.1f MB/s", mbps)
}
