package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// TestMnemonicAbsentFromJSONOutput proves the guarantee structurally, not
// just empirically: registerOutput/recoverOutput have no field capable of
// carrying a mnemonic at all, so no value of identity.Mnemonic could ever
// appear no matter what register.go does upstream. Reflecting over the
// struct's JSON tags is a stronger check than string-searching one
// rendered sample, since it holds for every possible input, not just the
// one this test happens to construct.
func TestMnemonicAbsentFromJSONOutput(t *testing.T) {
	assertNoMnemonicField := func(t *testing.T, v any) {
		t.Helper()
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			tag := rt.Field(i).Tag.Get("json")
			if strings.Contains(strings.ToLower(tag), "mnemonic") {
				t.Errorf("%s has a json-tagged field %q referencing mnemonic", rt.Name(), tag)
			}
			if strings.Contains(strings.ToLower(rt.Field(i).Name), "mnemonic") {
				t.Errorf("%s has a field named %q referencing mnemonic", rt.Name(), rt.Field(i).Name)
			}
		}
	}
	assertNoMnemonicField(t, registerOutput{})
	assertNoMnemonicField(t, recoverOutput{})

	// Belt-and-braces: render actual values and confirm the word
	// "mnemonic" (and a sample real BIP-39 word list wouldn't fit here
	// anyway, since the struct has no slot for it) never appears in the
	// rendered JSON string.
	ownerID := uuid.New()
	registerJSON := renderRegisterJSON(ownerID)
	if strings.Contains(strings.ToLower(registerJSON), "mnemonic") {
		t.Errorf("renderRegisterJSON output contains %q: %s", "mnemonic", registerJSON)
	}
	recoverJSON := renderRecoverJSON(ownerID, true)
	if strings.Contains(strings.ToLower(recoverJSON), "mnemonic") {
		t.Errorf("renderRecoverJSON output contains %q: %s", "mnemonic", recoverJSON)
	}

	// And confirm what IS there parses back to exactly the expected shape.
	var decoded registerOutput
	if err := json.Unmarshal([]byte(registerJSON), &decoded); err != nil {
		t.Fatalf("renderRegisterJSON did not produce valid JSON: %v", err)
	}
	if decoded.OwnerID != ownerID.String() || !decoded.Registered {
		t.Fatalf("unexpected decoded register output: %+v", decoded)
	}
}

// TestRegisterJSONFailsFastAgainstConfirmationRequiredProfile is a
// regression test for the second half of the same live failure
// TestPromptLineRejectsImmediateEOF documents: register --json against a
// profile with SkipMnemonicConfirm == false (i.e. any non-demo profile)
// has no way to satisfy mnemonic confirmation, since --json never prints
// the mnemonic. This must be caught immediately, not several network
// round-trips later.
func TestRegisterJSONFailsFastAgainstConfirmationRequiredProfile(t *testing.T) {
	cfg := registerConfig{
		g:       globalFlags{json: true, microserviceURL: "https://example.invalid", dataDir: t.TempDir()},
		profile: config.ProductionProfile, // SkipMnemonicConfirm == false
	}
	var out, errOut bytes.Buffer
	code := runRegister(context.Background(), cfg, bufio.NewReader(strings.NewReader("")), &out, &errOut)
	if code == 0 {
		t.Fatal("runRegister returned success for an unsupported --json + confirmation-required combination")
	}
	if !strings.Contains(errOut.String(), "SkipMnemonicConfirm") {
		t.Errorf("error message = %q, want it to explain the actual constraint (SkipMnemonicConfirm)", errOut.String())
	}
}

func TestPromptLineTrimsInput(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("  hello world  \n"))
	var out strings.Builder
	got, err := promptLine(&out, in, "label: ")
	if err != nil {
		t.Fatalf("promptLine: %v", err)
	}
	if got != "hello world" {
		t.Fatalf("got %q, want %q", got, "hello world")
	}
	if !strings.Contains(out.String(), "label: ") {
		t.Fatalf("prompt label not written to out: %q", out.String())
	}
}

// TestPromptLineAcceptsFinalLineWithoutTrailingNewline confirms EOF is not
// always an error: a caller's last write with no trailing "\n" is valid
// input, not a closed pipe.
func TestPromptLineAcceptsFinalLineWithoutTrailingNewline(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("last response, no newline"))
	var out strings.Builder
	got, err := promptLine(&out, in, "label: ")
	if err != nil {
		t.Fatalf("promptLine: %v", err)
	}
	if got != "last response, no newline" {
		t.Fatalf("got %q, want the full final line", got)
	}
}

// TestPromptLineRejectsImmediateEOF is a regression test for a real bug a
// live TestDemoCLIFullLifecycle run caught: promptLine used to treat a
// stdin that closed before giving anything at all (line == "", err ==
// io.EOF) the same as "user pressed enter on an empty line" — silently
// returning ("", nil). That masked a test harness closing stdin one
// prompt too early behind a confusing downstream "mnemonic word did not
// match" error, many steps away from the actual problem. This must now be
// a clear, immediate error instead.
func TestPromptLineRejectsImmediateEOF(t *testing.T) {
	in := bufio.NewReader(strings.NewReader(""))
	var out strings.Builder
	_, err := promptLine(&out, in, "Confirm word #12: ")
	if err == nil {
		t.Fatal("promptLine on an already-closed/empty input source returned no error, want one")
	}
	if !strings.Contains(err.Error(), "Confirm word #12") {
		t.Errorf("error %q should name which prompt was waiting for input, to make this diagnosable", err.Error())
	}
}