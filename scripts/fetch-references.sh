#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
case "$root" in /mnt/*) echo "copy or clone this project into the WSL Linux file system" >&2; exit 1;; esac
. "$root/pins.env"
refs=${REFS_DIR:-$root/.refs}

fetch() {
    local url=$1 commit=$2 path=$3
    if [[ ! -d "$path/.git" ]]; then
        mkdir -p "$path"
        git -C "$path" init -q
        git -C "$path" remote add origin "$url"
    fi
    [[ $(git -C "$path" remote get-url origin) == "$url" ]] || { echo "wrong origin: $path" >&2; exit 1; }
    git -C "$path" fetch -q --depth 1 origin "$commit"
    git -C "$path" checkout -q --detach FETCH_HEAD
    [[ -z $(git -C "$path" status --short) ]] || { echo "dirty checkout: $path" >&2; exit 1; }
}

fetch https://github.com/NebuSec/CyberMeowfia.git "$NEBUSEC_COMMIT" "$refs/CyberMeowfia"
fetch https://github.com/BuSung-dev/CVE-2026-43499-S25U.git "$S25U_COMMIT" "$refs/CVE-2026-43499-S25U"
