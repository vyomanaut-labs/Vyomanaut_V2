// Package main — `operator otp <phone>` (M17-E Session 17.6.1, ADR-084
// §D-3, F-D-2).
//
// This command tails the delivery log internal/api's FileOtpSender writes
// (cmd/microservice's own --otp-delivery-log / VYOMANAUT_OTP_DELIVERY_LOG)
// and prints the most recent code for one phone number — the network
// operator's half of the two-party cooperation ADR-084 §D-3 designs:
// `provider onboard` (cmd/provider/onboard.go) sends the OTP and prompts
// the volunteer for the code; this command is how the operator reads it
// off, without ever touching otp_codes (which stores a hash, not the code)
// or any other database table. No database import exists anywhere in this
// package — I-DEMO-1, main.go's own doc comment.
//
// [Corrected against ADR-084 §D-3's own illustrative log line] That
// section's example line shows FOUR whitespace-separated fields —
// timestamp, phone, a purpose token ("PROVIDER_REGISTER"), and the code.
// Reading internal/api/otp.go's FileOtpSender.SendOTP directly (the actual
// shipped implementation, Session 17.4.2) shows it writes exactly
// fmt.Sprintf("%s  %s  %s\n", timestamp, phoneNumber, code) — THREE
// fields, no purpose token. The M17E handoff's own summary of that session
// agrees with the code, not the ADR's example. otpLogFields below matches
// the real, shipped format; a purpose field was never implemented and this
// parser does not expect one.
//
// [REF: ADR-084 D-3; internal/api/otp.go FileOtpSender (Session 17.4.2);
// build_M17E.md Phase 17.6 Session 17.6.1]
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

func dispatchOtp(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("operator otp", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var g globalFlags
	addGlobalFlags(fs, &g)
	deliveryLog := fs.String("otp-delivery-log", "", "Path to the FileOtpSender delivery log written by cmd/microservice (its own --otp-delivery-log flag). Falls back to VYOMANAUT_OTP_DELIVERY_LOG if unset.")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	rest := fs.Args()
	if len(rest) != 1 {
		fprintln(errOut, "usage: operator otp <phone> --otp-delivery-log=<path> [flags]")
		return exitUsage
	}
	phone := rest[0]

	logPath := *deliveryLog
	if logPath == "" {
		logPath = os.Getenv("VYOMANAUT_OTP_DELIVERY_LOG")
	}
	if logPath == "" {
		fprintln(errOut, "--otp-delivery-log is required (or set VYOMANAUT_OTP_DELIVERY_LOG)")
		return exitUsage
	}

	// ADR-084 §D-3: reading the delivery log is demo-track theatre, not a
	// production operator capability — the same gate
	// cmd/microservice/main.go's own --otp-delivery-log flag enforces
	// fatally at startup (F-D-2's rejected alternatives table: a
	// demo-mode-gated bypass is exactly the kind of thing that survives
	// into production by accident, so the gate is checked here too, not
	// assumed from the log simply not existing outside demo mode).
	profile := config.SelectProfile(g.mode)
	if profile.Mode != "demo" {
		fprintf(errOut, "vyomanaut operator otp: refused outside demo mode (profile.Mode = %q)\n", profile.Mode)
		return 1
	}

	code, sentAt, err := mostRecentCodeForPhone(logPath, phone)
	if err != nil {
		fprintf(errOut, "vyomanaut operator otp: %v\n", err)
		return 1
	}
	if code == "" {
		fprintf(errOut, "vyomanaut operator otp: no OTP found for %s in %s\n", phone, logPath)
		return 1
	}

	if g.json {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			Phone  string `json:"phone_number"`
			Code   string `json:"code"`
			SentAt string `json:"sent_at"`
		}{Phone: phone, Code: code, SentAt: sentAt})
		return 0
	}
	fprintf(out, "%s (sent %s)\n", code, sentAt)
	return 0
}

// otpLogFields is the exact whitespace-separated field count
// FileOtpSender.SendOTP (internal/api/otp.go) writes per line — see this
// file's header note on the correction against ADR-084 §D-3's own
// illustrative example.
const otpLogFields = 3

// mostRecentCodeForPhone scans path — FileOtpSender's own delivery log,
// append-only, oldest line first — for every line matching phone and
// returns the LAST match's code and timestamp. A linear scan, not an
// index: this log is a human-scale demo artifact (a handful of onboarding
// events per run), not a production SMS gateway's real delivery history.
// A phone with no match returns ("", "", nil) — not found is not itself an
// error; dispatchOtp above turns an empty code into its own message.
func mostRecentCodeForPhone(path, phone string) (code, sentAt string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("open delivery log: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != otpLogFields {
			continue // malformed or foreign line — skip rather than fail the whole scan
		}
		ts, ph, c := fields[0], fields[1], fields[2]
		if ph == phone {
			code, sentAt = c, ts // log is oldest-first; keep overwriting so the last match wins
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", fmt.Errorf("read delivery log: %w", err)
	}
	return code, sentAt, nil
}

// resolveOtpDeliveryLog applies the same flag-then-environment fallback
// dispatchOtp uses inline, so `operator watch --otp-delivery-log` and
// `operator otp --otp-delivery-log` resolve identically. Returns "" when
// neither is set — an absent path is not an error for watch, which simply
// runs without the OTP feed (unlike `operator otp`, whose whole job it is).
//
// [Added, Session 18.1.4]
func resolveOtpDeliveryLog(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("VYOMANAUT_OTP_DELIVERY_LOG")
}

// otpLogEntry is one parsed delivery-log line.
type otpLogEntry struct {
	sentAt string
	phone  string
	code   string
}

// readOtpLog parses the whole delivery log, oldest first. It shares
// mostRecentCodeForPhone's tolerance for malformed lines (skip, don't
// fail) and its assumption that this file is a human-scale demo artifact —
// re-reading it once per fetch cycle is cheap at the handful-of-lines
// scale it actually reaches, and avoids holding a file handle open across
// the console's whole run.
//
// A missing file is not an error: the microservice creates the log lazily
// on the first OTP, so "not there yet" is the normal state for the first
// minute of every run.
//
// [Added, Session 18.1.4]
func readOtpLog(path string) []otpLogEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var out []otpLogEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != otpLogFields {
			continue
		}
		out = append(out, otpLogEntry{sentAt: fields[0], phone: fields[1], code: fields[2]})
	}
	return out
}
