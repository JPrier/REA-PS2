# Security

Input files are treated as untrusted. Current inspection rejects empty files, files over 8 GiB, malformed ELF structures, out-of-bounds load segments, and malformed ISO root records. No input payload is executed. This is not a sandbox: further parser and resource-limit review is required before analyzing arbitrary commercial disc images. Do not commit copyrighted game data or BIOS files.
