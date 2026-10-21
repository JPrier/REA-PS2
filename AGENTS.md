# Repository engineering contract

Before changing code, read `ARCHITECTURE.md`, `TESTING.md`, and `COMPATIBILITY.md`. Identify the owning subsystem and keep dependencies flowing from CLI/orchestration to services, domain logic, abstract ports, and adapters.

For every behavior change, add or update deterministic tests, run focused checks, and run all applicable required checks before declaring completion. Do not weaken tests, hide skips, or claim real provider coverage when only a mock ran. Preserve content identity, structured errors, reproducibility, and accurate capability reporting. Never silently bypass unsupported PS2 behavior or claim playability without independently verified gameplay evidence. Prefer reusable platform fixes, preserve upstream licenses, and report exact evidence, limitations, and unresolved failures.
