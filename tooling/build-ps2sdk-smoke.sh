#!/usr/bin/env bash
set -euo pipefail

: "${PS2DEV:?Set PS2DEV to the installed ps2dev root}"
: "${PS2SDK:?Set PS2SDK to the installed PS2SDK root}"

prefix="${EE_TOOL_PREFIX:-mips64r5900el-ps2-elf-}"
cc="${prefix}gcc"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$root/.rea-ps2/fixtures/ps2sdk-smoke.elf}"
mkdir -p "$(dirname "$out")"
"$cc" -G0 -nostdlib -Wl,--build-id=none \
  -T "$PS2SDK/ee/startup/linkfile" \
  -o "$out" "$root/fixtures/sources/ps2sdk-smoke.S"
"${prefix}objdump" -f "$out"
printf 'Built source-owned PS2SDK smoke ELF: %s\n' "$out"
