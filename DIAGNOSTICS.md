# Diagnostics

CLI errors are JSON objects on stderr with `schemaVersion`, `status`, and an `error` containing `code`, `message`, and bounded `details`. Exit codes are: 0 success, 2 invalid input, 3 prerequisite missing, 4 unsupported capability, 5 analysis failure, 6 compilation failure, 7 runtime failure, 8 verification failure, 9 cancellation, 10 internal error, and 11 execution timeout. Native run timeout and cancellation reports are retained in the workspace; they do not claim successful behavioral verification.
