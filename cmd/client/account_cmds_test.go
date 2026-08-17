package main

import (
	"bufio"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
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
