# Runbooks

Per-platform setup and test-execution procedures for Vyomanaut V2's three-machine
development fleet (Mac, Windows, Linux). Pinned toolchain versions referenced
throughout live in [`../scripts/versions.env`](../scripts/versions.env) — update that
file, not each runbook individually, when a version changes.

| Platform | Status |
|---|---|
| [macos.md](macos.md) | **Tested, green** — the reference procedure |
| [linux.md](linux.md) | Unverified draft, translated from macOS |
| [windows.md](windows.md) | Unverified draft, translated from macOS |

Windows and Linux are drafts until run end-to-end and corrected against what actually
happens — report every divergence rather than silently working around it, the same
discipline this project applies to product code.
