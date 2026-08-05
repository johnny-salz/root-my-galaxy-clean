#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
case "$root" in /mnt/*) echo "copy or clone this project into the WSL Linux file system" >&2; exit 1;; esac
. "$root/pins.env"
deps=${DEPS_DIR:-$root/.deps}

fetch_full() {
    local url=$1
    local commit=$2
    local path=$3

    if [[ ! -d "$path/.git" ]]; then
        mkdir -p "$path"
        git -C "$path" init -q
        git -C "$path" remote add origin "$url"
    fi
    if [[ $(git -C "$path" remote get-url origin) != "$url" ]]; then
        echo "wrong origin: $path" >&2
        exit 1
    fi
    if [[ $(git -C "$path" rev-parse --is-shallow-repository) == true ]]; then
        git -C "$path" fetch -q --unshallow origin
    else
        git -C "$path" fetch -q origin
    fi
    git -C "$path" fetch -q origin "$commit"
    git -C "$path" checkout -q --detach "$commit"
    if [[ -n $(git -C "$path" status --short) ]]; then
        echo "dirty checkout: $path" >&2
        exit 1
    fi
}

# AI: KernelSU derives its protocol code from git commit count.
fetch_full https://github.com/tiann/KernelSU.git "$KERNELSU_COMMIT" "$deps/KernelSU"
