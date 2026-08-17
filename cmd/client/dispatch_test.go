package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

func TestDispatchRecognisesAllEightSubcommands(t *testing.T) {
	// Exit code alone is ambiguous here: register/recover legitimately
	// return 2 when required flags are missing, the same code an unknown
	// subcommand gets. Recognition is instead checked by the one signal
	// that's unambiguous: an unknown subcommand always prints run's usage
	// banner; a recognised one never does, however it fails otherwise.
	for _, sub := range knownSubcommands {
		var out, errOut bytes.Buffer
		run([]string{sub}, strings.NewReader(""), &out, &errOut)
		if strings.Contains(errOut.String(), "usage: cmd/client <subcommand>") {
			t.Errorf("subcommand %q was not recognised (got the unknown-subcommand usage banner)", sub)
		}
	}
	if len(knownSubcommands) != 8 {
		t.Fatalf("knownSubcommands has %d entries, want 8 per MVP §8.3", len(knownSubcommands))
	}
}

func TestUnknownSubcommandExitsTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"nonsense"}, strings.NewReader(""), &out, &errOut)
	if code != 2 {
		t.Fatalf("got exit code %d, want 2", code)
	}
}

func TestNoSubcommandExitsTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, strings.NewReader(""), &out, &errOut)
	if code != 2 {
		t.Fatalf("got exit code %d, want 2", code)
	}
}

func TestModeFlagOverridesEnvVar(t *testing.T) {
	t.Setenv("VYOMANAUT_MODE", "prod")

	var g globalFlags
	g.mode = "demo" // simulates --mode=demo having been parsed

	// Mirrors exactly what dispatchRegister/dispatchRecover hand to
	// config.SelectProfile: the parsed flag value, not the env var.
	profile := config.SelectProfile(g.mode)
	if profile.Mode != "demo" {
		t.Fatalf("got profile.Mode=%q with --mode=demo and VYOMANAUT_MODE=prod, want demo (flag must win, MVP §5.3)", profile.Mode)
	}

	// Sanity check the other direction: empty flag falls back to the env var.
	fallback := config.SelectProfile("")
	if fallback.Mode != "prod" {
		t.Fatalf("got profile.Mode=%q with no --mode flag and VYOMANAUT_MODE=prod, want prod (env fallback)", fallback.Mode)
	}
}

func TestValidateGlobalFlagsRequiresMicroserviceURL(t *testing.T) {
	if err := validateGlobalFlags(globalFlags{}); err == nil {
		t.Fatal("expected an error when --microservice-url is empty")
	}
	if err := validateGlobalFlags(globalFlags{microserviceURL: "https://example.test"}); err != nil {
		t.Fatalf("unexpected error with microservice-url set: %v", err)
	}
}
