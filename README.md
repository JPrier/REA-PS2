# REA-PS2

REA-PS2 is an early PlayStation 2 static recompilation workflow. It inspects ISO/ELF input, invokes the pinned PS2Recomp analyzer and translator, attaches generated functions to its native runtime, builds a host executable, and can launch it. A PS2SDK-built smoke ELF has been dispatched through generated native code. This does not yet verify instruction results against an independent reference or establish playability.

Requires Node.js 22.19+ (tested with Node 24). Run from the repository:

```sh
npm test
node apps/cli/src/main.js doctor --json
node apps/cli/src/main.js inspect /path/to/file.iso --json
node apps/cli/src/main.js analyze /path/to/boot.elf --json
node apps/cli/src/main.js recompile /path/to/boot.elf --json
node apps/cli/src/main.js run /path/to/boot.elf --timeout-ms 60000 --json
```

Build the upstream PS2Recomp tools and runtime at the immutable revision in `DEPENDENCY_LOCK.json`, or set `REA_PS2_ANALYZER`, `REA_PS2_RECOMP`, and `REA_PS2RECOMP_SOURCE`. `analyze` reports heuristic evidence and uses a content-addressed workspace. `recompile` adds translated C++, function registration, and a per-workspace native executable. `run` launches that executable; `--timeout-ms` bounds an automated run and records a structured timeout report. These reports do not prove correct behavior. For the source-owned PS2SDK smoke fixture, see `tooling/build-ps2sdk-smoke.sh`. Ghidra 12.1.4 with EE Reloaded v2.1.38 has passed a real headless import of that fixture, but Ghidra analysis is not yet connected to the CLI pipeline. See [TESTING.md](TESTING.md).

ELF inspection validates headers and load-segment file bounds and reports little-endian MIPS32 executables as candidates only. ISO inspection reads an ISO9660 primary descriptor and root directory, then reads a root-level `SYSTEM.CNF` and resolves a root-level `BOOT2=cdrom0:` executable when present. Nested directory traversal, Joliet/Rock Ridge, and extraction to a persistent workspace are not implemented. These results are not proof of game compatibility.

Upstream revisions and locally resolved PS2Recomp build dependencies are recorded in [DEPENDENCY_LOCK.json](DEPENDENCY_LOCK.json). See [COMPATIBILITY.md](COMPATIBILITY.md) for current evidence and [branch protection instructions](docs/branch-protection.md).
