#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
case "$root" in /mnt/*) echo "copy or clone this project into the WSL Linux file system" >&2; exit 1;; esac
. "$root/pins.env"

: "${KERNEL_DIR:?set KERNEL_DIR to the exact Samsung kernel source tree}"
: "${KERNEL_CONFIG:?set KERNEL_CONFIG to the live uncompressed config}"
: "${TARGET_RELEASE:?set TARGET_RELEASE to uname -r from the phone}"
: "${TARGET_SYMBOLS:?set TARGET_SYMBOLS to the phone kallsyms file}"
: "${KERNEL_CLANG_DIR:?set KERNEL_CLANG_DIR to clang-r416183b bin}"
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to Android NDK r29}"

for path in "$KERNEL_DIR" "$KERNEL_CONFIG" "$TARGET_SYMBOLS" "$KERNEL_CLANG_DIR" "$ANDROID_NDK_HOME"; do
    [[ $path != /mnt/* ]] || { echo "slow WSL Windows path: $path" >&2; exit 1; }
done
grep -q "Pkg.Revision = $ANDROID_NDK_REVISION" "$ANDROID_NDK_HOME/source.properties" || { echo "wrong NDK" >&2; exit 1; }
"$KERNEL_CLANG_DIR/clang" --version | grep -q "$ANDROID_CLANG_REVISION" || { echo "wrong kernel clang" >&2; exit 1; }

"$root/scripts/fetch.sh"
build=${BUILD_DIR:-$root/.build}
out=${OUT_DIR:-$root/out}
ksu=$build/KernelSU
mkdir -p "$build" "$out"
if [[ ! -d "$ksu/.git" ]]; then
    git clone -q --shared "$root/.deps/KernelSU" "$ksu"
    git -C "$ksu" checkout -q --detach "$KERNELSU_COMMIT"
fi
if [[ $(git -C "$ksu" rev-parse --is-shallow-repository) == true ]]; then
    git -C "$ksu" fetch -q --unshallow origin
fi
[[ $(git -C "$ksu" rev-parse HEAD) == "$KERNELSU_COMMIT" ]] || { echo "wrong KernelSU work tree" >&2; exit 1; }
ksu_version_count=$(git -C "$ksu" rev-list --count HEAD)
ksu_version_code=$((30000 + ksu_version_count))
echo "-- KernelSU version code: $ksu_version_code"

apply_once() {
    local tree=$1 patch=$2
    if git -C "$tree" apply --check "$patch"; then
        git -C "$tree" apply "$patch"
    elif ! git -C "$tree" apply --reverse --check "$patch"; then
        echo "patch does not match: $patch" >&2
        exit 1
    fi
}

apply_once "$KERNEL_DIR" "$root/patches/samsung-module-build.patch"
apply_once "$ksu" "$root/vendor/root-my-galaxy-payloads/kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch"
apply_once "$ksu" "$root/patches/kernelsu-a53-rkp-no-syscall-table.patch"

cp "$KERNEL_CONFIG" "$KERNEL_DIR/.config"
base=$(make -s -C "$KERNEL_DIR" kernelversion)
[[ $TARGET_RELEASE == "$base"* ]] || { echo "target release does not match kernel source: $base" >&2; exit 1; }
"$KERNEL_DIR/scripts/config" --file "$KERNEL_DIR/.config" --set-str LOCALVERSION "${TARGET_RELEASE#$base}"
"$KERNEL_DIR/scripts/config" --file "$KERNEL_DIR/.config" --disable LOCALVERSION_AUTO
"$KERNEL_DIR/scripts/config" --file "$KERNEL_DIR/.config" --set-str UNUSED_KSYMS_WHITELIST ""
if [[ -s "$KERNEL_DIR/Module.symvers" ]]; then
    echo "do not use a Module.symvers from another build" >&2
    exit 1
fi

export PATH="$KERNEL_CLANG_DIR:$PATH"
make_args=(ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu- PLATFORM_VERSION_FOR_GPU=12)
make -C "$KERNEL_DIR" "${make_args[@]}" olddefconfig
make -C "$KERNEL_DIR" "${make_args[@]}" modules_prepare
make -C "$KERNEL_DIR" "${make_args[@]}" scripts/selinux/genheaders/genheaders
"$KERNEL_DIR/scripts/selinux/genheaders/genheaders" \
    "$KERNEL_DIR/security/selinux/flask.h" \
    "$KERNEL_DIR/security/selinux/av_permissions.h"
actual=$(sed -n 's/^#define UTS_RELEASE "\(.*\)"/\1/p' "$KERNEL_DIR/include/generated/utsrelease.h")
[[ $actual == "$TARGET_RELEASE" ]] || { echo "wrong UTS_RELEASE: $actual" >&2; exit 1; }

make -C "$KERNEL_DIR" "${make_args[@]}" KBUILD_MODPOST_WARN=1 \
    CONFIG_KSU=m CONFIG_KSU_SAMSUNG_KDP=y CONFIG_KSU_SAMSUNG_RKP=y \
    CONFIG_KSU_SAMSUNG_DEFEX=y CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y \
    M="$ksu/kernel" modules -j"${JOBS:-$(nproc)}"

"$KERNEL_CLANG_DIR/llvm-strip" -d "$ksu/kernel/kernelsu.ko" -o "$out/kernelsu.ko"
TARGET_RELEASE=$TARGET_RELEASE LLVM_BIN=$KERNEL_CLANG_DIR "$root/scripts/audit-module.sh" "$out/kernelsu.ko" "$TARGET_SYMBOLS"
cp "$out/kernelsu.ko" "$ksu/userspace/ksud/bin/aarch64/android12-5.10_kernelsu.ko"
touch "$ksu/userspace/ksud/src/assets.rs"

ndk_bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
export PATH="$ndk_bin:$PATH"
export LIBCLANG_PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/lib"
export CARGO_TARGET_DIR="$build/cargo-target"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk_bin/aarch64-linux-android24-clang"
export CC_aarch64_linux_android="$ndk_bin/aarch64-linux-android24-clang"
export AR_aarch64_linux_android="$ndk_bin/llvm-ar"
unset LD_LIBRARY_PATH
(cd "$ksu" && cargo +"$RUST_TOOLCHAIN" build --release --target aarch64-linux-android -p ksud)
cp "$CARGO_TARGET_DIR/aarch64-linux-android/release/ksud" "$out/ksud"
sha256sum "$out/kernelsu.ko" "$out/ksud"
