package main

import (
	"net"
	"testing"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// TestAdvertiseResolution is a thin wrapper so `go test -run TestAdvertiseResolution`
// matches every test below — same pattern as dispatch_test.go's
// TestDispatchRouting.
func TestAdvertiseResolution(t *testing.T) {
	t.Run("TestAdvertiseAddrPrefersNonLoopbackIPv4", TestAdvertiseAddrPrefersNonLoopbackIPv4)
	t.Run("TestAdvertiseAddrFallsBackToLoopbackWithWarning", TestAdvertiseAddrFallsBackToLoopbackWithWarning)
	t.Run("TestAdvertiseAddrExplicitSkipsAutodetection", TestAdvertiseAddrExplicitSkipsAutodetection)
	t.Run("TestAdvertiseAddrExplicitStripsPortComponent", TestAdvertiseAddrExplicitStripsPortComponent)
	t.Run("TestRegistrationAndHeartbeatShareOneAdvertisedAddress", TestRegistrationAndHeartbeatShareOneAdvertisedAddress)
}

// TestAdvertiseAddrPrefersNonLoopbackIPv4 verifies firstNonLoopbackIPv4
// skips both loopback and link-local candidates before returning the first
// genuinely routable address — the exact three-address shape a real
// interface listing produces (lo, a self-assigned 169.254/16 fallback when
// DHCP is slow, then the real address).
func TestAdvertiseAddrPrefersNonLoopbackIPv4(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1").To4(), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("169.254.1.5").To4(), Mask: net.CIDRMask(16, 32)},
		&net.IPNet{IP: net.ParseIP("192.168.1.42").To4(), Mask: net.CIDRMask(24, 32)},
	}
	got, ok := firstNonLoopbackIPv4(addrs)
	if !ok {
		t.Fatalf("firstNonLoopbackIPv4(%v) = (_, false), want a match", addrs)
	}
	if got != "192.168.1.42" {
		t.Fatalf("firstNonLoopbackIPv4(%v) = %q, want %q", addrs, got, "192.168.1.42")
	}
}

// TestAdvertiseAddrFallsBackToLoopbackWithWarning verifies the fallback
// branch deterministically, via an injected autodetect that always reports
// "nothing found" — not dependent on this test runner's own interfaces.
func TestAdvertiseAddrFallsBackToLoopbackWithWarning(t *testing.T) {
	noInterfaces := func() (string, bool) { return "", false }
	host, warning := resolveAdvertiseHostUsing("", noInterfaces)
	if host != loopbackAdvertiseHost {
		t.Fatalf("resolveAdvertiseHostUsing(\"\", noInterfaces) host = %q, want %q", host, loopbackAdvertiseHost)
	}
	if warning == "" {
		t.Fatalf("resolveAdvertiseHostUsing(\"\", noInterfaces) returned no warning for the loopback fallback")
	}
}

// TestAdvertiseAddrExplicitSkipsAutodetection verifies an explicit
// --advertise-addr wins outright and autodetection is never even
// attempted — proven by an autodetect stub that fails the test if called.
func TestAdvertiseAddrExplicitSkipsAutodetection(t *testing.T) {
	called := false
	autodetect := func() (string, bool) {
		called = true
		return "10.0.0.9", true
	}
	host, warning := resolveAdvertiseHostUsing("203.0.113.9", autodetect)
	if called {
		t.Fatalf("autodetect was called even though --advertise-addr=203.0.113.9 was explicit")
	}
	if host != "203.0.113.9" {
		t.Fatalf("resolveAdvertiseHostUsing(\"203.0.113.9\", ...) host = %q, want %q", host, "203.0.113.9")
	}
	if warning != "" {
		t.Fatalf("resolveAdvertiseHostUsing with an explicit host returned an unexpected warning: %q", warning)
	}
}

// TestAdvertiseAddrExplicitStripsPortComponent verifies a host:port form of
// --advertise-addr keeps only the host — cfg.listenPort is the sole
// authority for the port in every multiaddr this daemon publishes, so a
// second, possibly-disagreeing port source is never introduced.
func TestAdvertiseAddrExplicitStripsPortComponent(t *testing.T) {
	autodetect := func() (string, bool) {
		t.Fatal("autodetect must not be called when --advertise-addr is explicit")
		return "", false
	}
	host, warning := resolveAdvertiseHostUsing("203.0.113.9:9999", autodetect)
	if host != "203.0.113.9" {
		t.Fatalf("resolveAdvertiseHostUsing(\"203.0.113.9:9999\", ...) host = %q, want %q (port stripped)", host, "203.0.113.9")
	}
	if warning != "" {
		t.Fatalf("resolveAdvertiseHostUsing with an explicit host:port returned an unexpected warning: %q", warning)
	}
}

// TestRegistrationAndHeartbeatShareOneAdvertisedAddress verifies
// advertiseMultiaddr is deterministic: identical inputs — the same
// advertiseHost, port, and peerID main.go's two call sites (registration
// and heartbeat) always pass — produce byte-identical multiaddr strings.
// F-D-4's fix depends on this: main.go computes advertiseHost exactly once
// and both call sites read that same variable (see main.go's F-D-4
// comments at each site).
func TestRegistrationAndHeartbeatShareOneAdvertisedAddress(t *testing.T) {
	peerID := p2p.PeerID("test-peer")
	registrationAddr := advertiseMultiaddr("203.0.113.9", 4001, peerID)
	heartbeatAddr := advertiseMultiaddr("203.0.113.9", 4001, peerID)
	if registrationAddr != heartbeatAddr {
		t.Fatalf("registration multiaddr %q != heartbeat multiaddr %q for identical inputs", registrationAddr, heartbeatAddr)
	}
	want := "/ip4/203.0.113.9/tcp/4001/p2p/test-peer"
	if registrationAddr != want {
		t.Fatalf("advertiseMultiaddr(...) = %q, want %q", registrationAddr, want)
	}
}
