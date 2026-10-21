# Compatibility status

Evidence status as of the current checkout:

| Capability | Status | Evidence |
|---|---|---|
| Node.js CLI | Implemented | `node apps/cli/src/main.js doctor --json` |
| ELF header and load-segment bounds | Implemented, limited | Unit tests in `tests/unit/input.test.js` |
| ISO9660 PVD, root listing, root SYSTEM.CNF/BOOT2 lookup | Implemented, limited | Unit fixture; nested traversal is unsupported |
| PS2 EE identification | Candidate heuristic only | ELF class, endian, type, and machine fields only |
| PS2Recomp heuristic analysis | Implemented and exercised on synthetic and PS2SDK-linked ELF inputs | Pinned `ps2_analyzer` emitted analysis artifacts; still not exhaustive |
| PS2Recomp instruction translation | Implemented and exercised on a synthetic ELF | Real pinned `ps2_recomp` emitted one C++ function and registration table, zero unhandled instructions |
| PS2Recomp native runtime and dispatch | Smoke-exercised; instruction state not independently verified | Generated runner loaded the PS2SDK-linked ELF and entered/exited its generated function 293 times in a 3-second bounded run; no missing-entry error occurred |
| Ghidra Emotion Engine Reloaded | Installed and validated for headless PS2 ELF import | Ghidra 12.1.4 and extension v2.1.38 successfully imported a PS2SDK-linked ELF with `r5900:LE:32:default`; a REA provider/export adapter remains unimplemented |
| PS2SDK fixture toolchain | Installed in Ubuntu 24.04 WSL2 and exercised | ps2dev v2.0.0 GCC 15.2.0 produced a MIPS object and a linked PS2 EE ELF; the upstream `hello` sample currently fails under this GCC due its obsolete `-mno-crt0` option |
| Generated native executable | Built from synthetic and PS2SDK-linked ELF inputs; limited execution evidence | CLI attached generated C++ and registration, linked the upstream runtime, and dispatched the PS2SDK smoke function; register/memory results have no independent oracle yet |
| PCSX2 reference execution | Installed; only process startup validated | PCSX2 2.8.2 launches, but no BIOS files are present and PINE did not listen; emulator-backed reference execution is unverified |
| Interactive native recompilation | Unavailable | No fixture or runtime |

No instruction, runtime service, host recompilation target, or commercial title is currently advertised as supported.
