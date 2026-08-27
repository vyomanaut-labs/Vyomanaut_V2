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
// [F-17E-20] Extended after a Design Council review of a proposed (and
// rejected) Docker-based demo deployment surfaced a related blind spot:
// net.InterfaceAddrs()'s "first non-loopback, non-link-local" heuristic
// treats a Docker bridge or VM virtual-switch address exactly like a real
// LAN address, since such addresses are neither loopback nor link-local.
// This applies even to a host that merely HAS Docker or a hypervisor
// installed and runs the provider natively — not only to a containerized
// provider. See autodetectAdvertiseHost and firstNonLoopbackIPv4 below for
// the fix (interface-name filtering plus a narrow Docker-bridge-subnet
// check).
//
// [REF: ADR-084 D-7, Answers Q2; build_M17E.md Phase 17.4 Session 17.4.1;
// F-17E-20]
package main

import (
	"fmt"
	"net"
	"strings"

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
//
// [F-17E-20] Previously used net.InterfaceAddrs(), which discards
// interface names entirely — a Docker bridge, a Docker container's own
// veth pair, or a VMware/VirtualBox/Hyper-V virtual switch's address could
// be chosen exactly as readily as a real LAN interface's, and (being
// neither loopback nor link-local) slipped past every check firstNonLoopbackIPv4
// applied at the time. Found not in the field but by a Design Council
// review of a proposed (and rejected) Docker-based demo deployment — the
// same blind spot applies equally to a host machine that merely HAS
// Docker or a VM hypervisor installed, regardless of whether the provider
// itself is ever containerized, since net.InterfaceAddrs() enumerates
// every interface with no notion of which one is "real." Now walks
// net.Interfaces() so each interface's own Name is available to
// isSuspectVirtualInterfaceName below.
func autodetectAdvertiseHost() (string, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	for _, iface := range ifaces {
		if isSuspectVirtualInterfaceName(iface.Name) {
			continue // F-17E-20: never autodetect onto a container/VM bridge
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		if host, ok := firstNonLoopbackIPv4(addrs); ok {
			return host, true
		}
	}
	return "", false
}

// suspectVirtualInterfacePrefixes names interface-name substrings actually
// observed across this project's own M17-E cross-platform test fleet (a
// Mac and a Windows machine both running Docker Desktop, plus a Linux
// guest running inside VMware) — not an attempt at an exhaustive list of
// every virtualization product, which would be both incomplete and a
// moving target. Matched case-insensitively, as a substring, against the
// interface's own Name. [F-17E-20]
var suspectVirtualInterfacePrefixes = []string{
	"docker",    // Docker Engine's own bridge (docker0) and per-network bridges (br-<id>)
	"veth",      // Docker's per-container virtual ethernet pairs
	"br-",       // Docker user-defined bridge networks
	"vmnet",     // VMware's host-side virtual switches (Mac/Windows/Linux hosts)
	"vboxnet",   // VirtualBox's host-only/NAT virtual adapters
	"vethernet", // Windows Hyper-V/WSL2/Docker Desktop virtual switches ("vEthernet (...)")
}

// isSuspectVirtualInterfaceName reports whether name looks like a
// container or VM bridge/virtual-switch adapter rather than a real,
// externally-reachable network interface. See
// suspectVirtualInterfacePrefixes' own comment for scope and provenance.
// [F-17E-20]
func isSuspectVirtualInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range suspectVirtualInterfacePrefixes {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// dockerDefaultBridgeNet is Docker Engine's own documented default bridge
// subnet (docker0, unless overridden in daemon.json) — narrow and specific
// deliberately: this project does not attempt to guess every possible
// custom Docker network or every other vendor's default range, since a
// broad RFC1918 172.16.0.0/12 range check would false-positive on ordinary
// corporate LANs that happen to use nearby-but-different 172.16.0.0/12
// addressing. [F-17E-20]
var dockerDefaultBridgeNet = &net.IPNet{IP: net.IPv4(172, 17, 0, 0), Mask: net.CIDRMask(16, 32)}

// firstNonLoopbackIPv4 scans addrs — net.InterfaceAddrs' real return value,
// or a synthetic slice of *net.IPNet in tests — for the first IPv4 unicast
// address that is neither loopback (127.0.0.0/8) nor link-local
// (169.254.0.0/16, the address a host assigns itself when DHCP fails —
// never reachable from another machine even on the same LAN segment), nor
// inside Docker's own default bridge subnet (172.17.0.0/16 — [F-17E-20],
// see dockerDefaultBridgeNet's own comment for why this one specific
// subnet, not a broader RFC1918 heuristic).
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
		if dockerDefaultBridgeNet.Contains(ip4) {
			continue // F-17E-20: Docker's own default bridge — host-private unless published
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
