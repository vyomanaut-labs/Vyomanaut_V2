// Package main — advertised-address resolution (M17-E Session 17.4.1,
// ADR-084 D-7, finding F-D-4).
//
// Prior to this session, both places this daemon publishes an address to
// the network — POST /api/v1/provider/register's initial_multiaddrs and
// the heartbeat/DHT's CurrentAddrs (main.go) — hardcoded
// "/ip4/127.0.0.1/tcp/<port>/p2p/<peerID>". That is correct only when every
// peer runs on the same host, which is exactly what every test in this
// repository has done to date (--sim-count, single process) — so the
// defect was invisible until read directly against the eleven founding
// requirements. On two genuinely separate desktops, every dialer connected
// back to ITS OWN machine and never reached this provider at all.
//
// This file resolves ONE advertise host per instance startup —
// resolveAdvertiseHost, called once from runProviderInstance (main.go) —
// and advertiseMultiaddr builds the wire string from it. Both of main.go's
// call sites pass that same resolved value; there is exactly one place
// this host is computed per instance.
//
// [REF: ADR-084 D-7, Answers Q2; build_M17E.md Phase 17.4 Session 17.4.1]
package main

import (
	"fmt"
	"net"

	"github.com/vyomanaut-labs/Vyomanaut_V2/internal/p2p"
)

// loopbackAdvertiseHost is the last-resort fallback when no non-loopback
// IPv4 address can be found on this host — single-host-only, and always
// logged as a warning when taken (resolveAdvertiseHost's caller, main.go).
const loopbackAdvertiseHost = "127.0.0.1"

// autodetectFunc matches autodetectAdvertiseHost's signature. Indirected so
// resolveAdvertiseHostUsing is unit-testable without depending on whatever
// network interfaces happen to exist on the machine running `go test`.
type autodetectFunc func() (string, bool)

// resolveAdvertiseHost decides the IPv4 host this daemon instance should
// advertise to the network (registration's initial_multiaddrs and
// heartbeat's CurrentAddrs, main.go), in three steps:
//
//  1. explicit (--advertise-addr / providerFlags.advertiseAddr), if
//     non-empty — the operator's choice always wins outright; no
//     autodetection is attempted. Accepts a bare host or a host:port pair
//     (a port component, if present, is stripped and ignored —
//     cfg.listenPort is the sole authority for the port in every multiaddr
//     this daemon publishes; two disagreeing port sources is its own class
//     of bug this deliberately does not introduce).
//  2. autodetection — the first IPv4 unicast address, on any interface,
//     that is neither loopback nor link-local (firstNonLoopbackIPv4).
//  3. loopback fallback, ONLY when autodetection finds nothing. The caller
//     (main.go) logs this as a warning naming it reachable from this host
//     only — silence here would let a multi-desktop demo fail with no
//     signal pointing at why.
//
// warning is empty except in case 3.
func resolveAdvertiseHost(explicit string) (host string, warning string) {
	return resolveAdvertiseHostUsing(explicit, autodetectAdvertiseHost)
}

// resolveAdvertiseHostUsing is resolveAdvertiseHost's core logic, taking
// the autodetection step as a parameter so tests can force each of the
// three branches deterministically
// (TestAdvertiseAddrFallsBackToLoopbackWithWarning,
// TestAdvertiseAddrExplicitSkipsAutodetection — advertise_test.go) without
// touching this process's real network interfaces.
func resolveAdvertiseHostUsing(explicit string, autodetect autodetectFunc) (host string, warning string) {
	if explicit != "" {
		if h, _, err := net.SplitHostPort(explicit); err == nil {
			return h, ""
		}
		return explicit, ""
	}
	if h, ok := autodetect(); ok {
		return h, ""
	}
	return loopbackAdvertiseHost, fmt.Sprintf(
		"no non-loopback IPv4 address found on this host; advertising %s — this provider will be reachable from THIS HOST ONLY (pass --advertise-addr to fix, or see ADR-084 F-D-4)",
		loopbackAdvertiseHost,
	)
}

// autodetectAdvertiseHost is resolveAdvertiseHost's default autodetect step
// against this process's real network interfaces.
func autodetectAdvertiseHost() (string, bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", false
	}
	return firstNonLoopbackIPv4(addrs)
}

// firstNonLoopbackIPv4 scans addrs — net.InterfaceAddrs' real return value,
// or a synthetic slice of *net.IPNet in tests — for the first IPv4 unicast
// address that is neither loopback (127.0.0.0/8) nor link-local
// (169.254.0.0/16, the address a host assigns itself when DHCP fails —
// never reachable from another machine even on the same LAN segment).
// IPv6 addresses are skipped outright: this daemon's multiaddrs are /ip4
// only (ADR-063's transport substitution never introduced IPv6 support).
func firstNonLoopbackIPv4(addrs []net.Addr) (string, bool) {
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}
		if ip4.IsLoopback() {
			continue // 127.0.0.0/8 — reachable from this host only
		}
		if ip4.IsLinkLocalUnicast() {
			continue // 169.254.0.0/16 — never reachable from another machine
		}
		return ip4.String(), true
	}
	return "", false
}

// advertiseMultiaddr builds the /ip4/<host>/tcp/<port>/p2p/<peerID>
// multiaddr string this daemon publishes to the network. Pure and
// deterministic: called from exactly two sites in main.go
// (runProviderInstance's registration and heartbeat blocks), both passing
// the SAME advertiseHost resolved once by resolveAdvertiseHost — see that
// function's doc comment and main.go's F-D-4 comments at both call sites
// for why a single shared source matters.
func advertiseMultiaddr(host string, port int, peerID p2p.PeerID) string {
	return fmt.Sprintf("/ip4/%s/tcp/%d/p2p/%s", host, port, peerID)
}
