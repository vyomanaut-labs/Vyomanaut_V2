//go:build !windows

// Package test is declared in helpers_test.go. This file is the Unix half
// of a platform split (M17-E, cross-platform hardening pass following
// Session 17.8.1): every POSIX-only process-group primitive
// helpers_test.go and demo_timeline_test.go used unconditionally —
// syscall.SysProcAttr{Setpgid: true}, syscall.Kill, and a `ps`-based
// identity check — moved here behind a build tag, with
// daemon_process_windows.go providing this platform's answer to each.
//
// Found by actually cross-compiling `go vet -tags integration
// ./scripts/test/...` with GOOS=windows, not by inspection: before this
// split, the entire integration suite failed to compile on Windows with
// "unknown field Setpgid in struct literal of type syscall.SysProcAttr" —
// meaning every test in Phase 17.8's own steps 5-7 was unreachable on the
// project's declared primary rig platform (ADR-010, ADR-041).
//
// [REF: F-17E-14 (the original Setpgid/syscall.Kill introduction);
// build_M17E.md Phase 17.8; ADR-010, ADR-041 (Windows-primary-rig)]
// DO NOT EDIT.
package test

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// setNewProcessGroup marks cmd to start as the leader of a new OS process
// group (Setpgid) so killProcessGroupOS below can terminate the whole
// group — including any of its own children — in one call, not just the
// direct child. Called once, at spawn time, by every daemon-starting
// helper (startMicroservice, startMicroserviceWithFlags, startProviders).
func setNewProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroupOS sends SIGKILL to the process group pid leads (see
// setNewProcessGroup), then to pid itself as a fallback in case it was not
// its own group leader (a race at process start, or a re-exec that
// dropped group leadership) — the exact two-call sequence
// killDaemonProcessGroup and reapOrphanedDaemons (helpers_test.go) used
// inline before this split.
func killProcessGroupOS(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// processMatchesOS reports whether pid is currently a live process whose
// command line (argv[0], via `ps -o args=`) is exactly binPath — the
// identity check that makes reaping a possibly-recycled PID safe.
// syscall.Kill(pid, 0) is the classic Unix existence probe: it sends no
// actual signal, only checks deliverability.
func processMatchesOS(pid int, binPath string) bool {
	if syscall.Kill(pid, 0) != nil {
		return false // no such process (already dead), or no permission
	}
	out, err := exec.Command("ps", "-o", "args=", "-p", fmt.Sprintf("%d", pid)).Output()
	if err != nil {
		return false
	}
	args := strings.TrimSpace(string(out))
	return args == binPath || strings.HasPrefix(args, binPath+" ")
}
