//go:build windows

// Package test is declared in helpers_test.go. This file is the Windows
// half of the platform split daemon_process_unix.go's header documents in
// full — see that file for why this split exists.
//
// Windows has no POSIX process-group concept, so the three primitives the
// Unix side builds on (Setpgid, negative-PID SIGKILL, `ps`) each need a
// genuinely different mechanism here, not a thin wrapper over the same
// syscalls:
//   - setNewProcessGroup is a no-op — see killProcessGroupOS below for why.
//   - killProcessGroupOS uses `taskkill /T /F`, the standard Windows
//     mechanism for killing a process and its full child tree in one call
//     (Windows' answer to "kill the whole process group").
//   - processMatchesOS uses PowerShell's Get-Process (guaranteed present,
//     Windows PowerShell 5.1 ships with every supported Windows release)
//     rather than `ps`, which does not exist on Windows outside a POSIX
//     compatibility layer this project does not require.
//
// [REF: daemon_process_unix.go; F-17E-14; build_M17E.md Phase 17.8;
// ADR-010, ADR-041 (Windows-primary-rig)]
package test

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// setNewProcessGroup is a no-op on Windows: killProcessGroupOS below kills
// pid's entire child tree via `taskkill /T`, which needs no cooperation
// from how the process was spawned, unlike Unix's Setpgid-at-spawn-time
// requirement.
func setNewProcessGroup(cmd *exec.Cmd) {
	_ = cmd
}

// killProcessGroupOS kills pid and every descendant process it spawned.
// `/T` is taskkill's tree-kill flag; `/F` forces termination (SIGKILL's
// closest Windows equivalent — there is no graceful variant here, matching
// the Unix sibling, which also only ever sends SIGKILL, never SIGTERM).
func killProcessGroupOS(pid int) {
	_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)).Run()
}

// processMatchesOS reports whether pid is currently a live process whose
// executable path matches binPath (by full path, or by base name alone —
// Windows' own path normalization, e.g. 8.3 short names or a relative vs.
// absolute invocation, makes a strict string-equality check on the full
// path less reliable here than on the Unix side's `ps -o args=`, which
// reports the exact argv this project's own exec.Command call built).
func processMatchesOS(pid int, binPath string) bool {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("(Get-Process -Id %d -ErrorAction SilentlyContinue).Path", pid)).Output()
	if err != nil {
		return false
	}
	path := strings.TrimSpace(string(out))
	if path == "" {
		return false // no such process, or its Path is unavailable
	}
	return strings.EqualFold(path, binPath) || strings.EqualFold(filepath.Base(path), filepath.Base(binPath))
}
