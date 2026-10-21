# Architecture

The repository is currently a small Node.js CLI with domain parsers in `apps/cli/src/main.js` and unit tests under `tests/unit`. It has no external runtime dependencies. The next seams should separate orchestration, input parsing, analysis ports/adapters, translation, runtime services, verification, diagnostics, and content-addressed artifacts. CLI commands must not claim a downstream stage passed unless that stage independently produced and validated its artifact.

Current data flow is `CLI -> bounded input read -> SHA-256 identity -> ELF/ISO metadata parser -> structured JSON`. A recognized MIPS ELF is only a candidate; no PS2-specific loader or semantic profile is asserted. ISO parsing currently reads only the primary descriptor and root directory. There are no REA, Ghidra, PS2Recomp, PCSX2, or PS2SDK adapters yet.
