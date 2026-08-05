#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 2 ]] || { echo "use: audit-module.sh MODULE TARGET_SYMBOLS" >&2; exit 1; }
ko=$(realpath "$1")
symbols=$(realpath "$2")
tool=${LLVM_BIN:-}
readelf=${tool:+$tool/}llvm-readelf
nm=${tool:+$tool/}llvm-nm
modinfo=${MODINFO:-modinfo}

for cmd in "$readelf" "$nm" "$modinfo"; do command -v "$cmd" >/dev/null || { echo "missing tool: $cmd" >&2; exit 1; }; done
[[ -s "$ko" && -s "$symbols" ]] || { echo "module or target symbols are empty" >&2; exit 1; }

sections=$($readelf -SW "$ko")
grep -qE '[[:space:]]\.symtab[[:space:]]' <<<"$sections" || { echo ".symtab is gone" >&2; exit 1; }
grep -qE '[[:space:]]\.strtab[[:space:]]' <<<"$sections" || { echo ".strtab is gone" >&2; exit 1; }
version_size=$(awk '$2 == "__versions" {print $6}' <<<"$sections")
[[ $version_size == 000000 ]] || { echo "__versions must be empty, got ${version_size:-missing}" >&2; exit 1; }

if [[ -n ${TARGET_RELEASE:-} ]]; then
    vermagic=$($modinfo -F vermagic "$ko")
    [[ $vermagic == "$TARGET_RELEASE "* ]] || { echo "wrong vermagic: $vermagic" >&2; exit 1; }
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
$nm -u "$ko" | awk '{print $2}' | sort -u > "$tmp/needed"
awk 'NF >= 3 {print $3; next} NF {print $1}' "$symbols" | sort -u > "$tmp/target"
comm -23 "$tmp/needed" "$tmp/target" > "$tmp/missing"
if [[ -s "$tmp/missing" ]]; then
    echo "missing target symbols:" >&2
    cat "$tmp/missing" >&2
    exit 1
fi
echo "module audit ok: $(wc -l < "$tmp/needed") imports, 0 missing"
