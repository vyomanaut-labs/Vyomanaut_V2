// Tests for the departure-threshold override logic in main.go (M17-E
// Session 17.7.1, ADR-084 §D-4).
//
// Tests:
//   - TestDepartureThresholdBelowFloorIsFatal
//   - TestDepartureThresholdFloorDerivedFromProfileNotLiteral
//   - TestDepartureThresholdRejectedInProductionMode
//   - TestEmptyOverrideLeavesProfileValueUnchanged
//   - TestDepartureThresholdAtOrAboveFloorIsAccepted
package main

import (
	"strings"
	"testing"
	"time"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/config"
)

// TestEmptyOverrideLeavesProfileValueUnchanged confirms the documented
// default: an empty override string passes profile.DepartureThreshold
// through completely unchanged, in both demo and production mode —
// DemoProfile itself is never edited by this feature, so
// TestViabilityActiveTransitionAtTenMinutes (internal/repair) keeps
// passing against the real 10-minute constant with no special-casing.
func TestEmptyOverrideLeavesProfileValueUnchanged(t *testing.T) {
	got, err := validateDepartureThresholdOverride(config.DemoProfile, "")
	if err != nil {
		t.Fatalf("validateDepartureThresholdOverride(DemoProfile, \"\") returned an error: %v", err)
	}
	if got != config.DemoProfile.DepartureThreshold {
		t.Errorf("got %v, want profile.DepartureThreshold unchanged (%v)", got, config.DemoProfile.DepartureThreshold)
	}

	got, err = validateDepartureThresholdOverride(config.ProductionProfile, "")
	if err != nil {
		t.Fatalf("validateDepartureThresholdOverride(ProductionProfile, \"\") returned an error: %v", err)
	}
	if got != config.ProductionProfile.DepartureThreshold {
		t.Errorf("got %v, want profile.DepartureThreshold unchanged (%v)", got, config.ProductionProfile.DepartureThreshold)
	}
}

// TestDepartureThresholdRejectedInProductionMode confirms a non-empty
// override is a fatal configuration error in production mode — "a runtime
// departure-threshold override has no legitimate production use"
// (validateDepartureThresholdOverride's own doc comment).
func TestDepartureThresholdRejectedInProductionMode(t *testing.T) {
	_, err := validateDepartureThresholdOverride(config.ProductionProfile, "90s")
	if err == nil {
		t.Fatal("validateDepartureThresholdOverride(ProductionProfile, \"90s\") returned no error, want a fatal rejection")
	}
	if !strings.Contains(err.Error(), "demo-mode only") {
		t.Errorf("error = %q, want it to state this is demo-mode only", err.Error())
	}
}

// TestDepartureThresholdFloorDerivedFromProfileNotLiteral proves the floor
// is computed from the profile's own fields — not a hardcoded 70-second
// constant — by constructing a profile with deliberately unusual timing
// fields (nothing DemoProfile or ProductionProfile actually uses) and
// checking the floor moves exactly as the formula predicts:
// max(2×(HeartbeatInterval+HeartbeatJitter), 2×DeparturePollingInterval).
func TestDepartureThresholdFloorDerivedFromProfileNotLiteral(t *testing.T) {
	profile := config.DemoProfile

	// Case 1: the heartbeat term dominates.
	profile.HeartbeatInterval = 40 * time.Second
	profile.HeartbeatJitter = 10 * time.Second
	profile.DeparturePollingInterval = 5 * time.Second
	want := 2 * (40*time.Second + 10*time.Second) // 100s, vs 2*5s=10s
	if got := departureThresholdFloor(profile); got != want {
		t.Errorf("departureThresholdFloor = %v, want %v (heartbeat term dominates)", got, want)
	}

	// Case 2: the polling-interval term dominates.
	profile.HeartbeatInterval = 1 * time.Second
	profile.HeartbeatJitter = 1 * time.Second
	profile.DeparturePollingInterval = 45 * time.Second
	want = 2 * 45 * time.Second // 90s, vs 2*(1s+1s)=4s
	if got := departureThresholdFloor(profile); got != want {
		t.Errorf("departureThresholdFloor = %v, want %v (polling-interval term dominates)", got, want)
	}

	// Case 3: DemoProfile's own real values reproduce ADR-084 §D-4's own
	// worked example exactly: max(2×(30s+5s), 2×30s) = max(70s, 60s) = 70s.
	if got, want := departureThresholdFloor(config.DemoProfile), 70*time.Second; got != want {
		t.Errorf("departureThresholdFloor(DemoProfile) = %v, want %v (ADR-084 §D-4's own worked example)", got, want)
	}
}

// TestDepartureThresholdBelowFloorIsFatal confirms an override below the
// derived floor is a fatal configuration error, with the arithmetic stated
// in the message — "punishing an honest provider... is not an acceptable
// failure mode, so this is checked, not merely documented."
func TestDepartureThresholdBelowFloorIsFatal(t *testing.T) {
	floor := departureThresholdFloor(config.DemoProfile)
	belowFloor := floor - time.Second

	_, err := validateDepartureThresholdOverride(config.DemoProfile, belowFloor.String())
	if err == nil {
		t.Fatalf("validateDepartureThresholdOverride(DemoProfile, %s) returned no error, want a fatal rejection (floor is %s)", belowFloor, floor)
	}
	if !strings.Contains(err.Error(), "safety floor") {
		t.Errorf("error = %q, want it to name the safety floor", err.Error())
	}
	// The arithmetic itself must be stated, not just asserted — an
	// audience (or an operator debugging a refused startup) should be
	// able to verify the floor by eye from the error text alone.
	if !strings.Contains(err.Error(), "HeartbeatInterval") || !strings.Contains(err.Error(), "DeparturePollingInterval") {
		t.Errorf("error = %q, want it to state the floor's own derivation", err.Error())
	}
}

// TestDepartureThresholdAtOrAboveFloorIsAccepted is the positive
// complement to TestDepartureThresholdBelowFloorIsFatal: exactly at the
// floor, and comfortably above it (ADR-084 §D-4's own recommended 90s demo
// value), both succeed.
func TestDepartureThresholdAtOrAboveFloorIsAccepted(t *testing.T) {
	floor := departureThresholdFloor(config.DemoProfile)

	got, err := validateDepartureThresholdOverride(config.DemoProfile, floor.String())
	if err != nil {
		t.Fatalf("validateDepartureThresholdOverride(DemoProfile, floor=%s) returned an error: %v", floor, err)
	}
	if got != floor {
		t.Errorf("got %v, want exactly the floor %v", got, floor)
	}

	got, err = validateDepartureThresholdOverride(config.DemoProfile, "90s")
	if err != nil {
		t.Fatalf("validateDepartureThresholdOverride(DemoProfile, \"90s\") returned an error: %v (ADR-084 §D-4's own recommended demo value)", err)
	}
	if got != 90*time.Second {
		t.Errorf("got %v, want 90s", got)
	}
}
