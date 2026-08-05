# Source trail

## Build inputs

| Input | Exact source |
| --- | --- |
| KernelSU | `https://github.com/tiann/KernelSU.git`, tag `v3.2.5`, commit `b0bc817b4e966aa6aa830834eaf6ef765d821d40` |
| Samsung KDP/RKP/DEFEX patch and root helper | Two files from `https://github.com/BuSung-dev/Root-My-Galaxy-Payloads.git` at commit `75bdeb2f4b1a2ca81ac78651168351297af67114`; paths and hashes below |
| Kernel source for the checked A53 profile | Manually downloaded `SM-A536B.zip` from Samsung Open Source; inner `SM-A536B_16_Opensource.zip`, then `Kernel.tar.gz` |
| Kernel clang | Android clang archive `clang-r416183b.tar.gz` from the `android12-release` branch |
| Android user-space clang | Google NDK `29.0.14206865`; Linux archive `android-ndk-r29-linux.zip`, size `783549481`, official SHA-1 `87e2bb7e9be5d6a1c6cdf5ec40dd4e0c6d07c30b` |
| Rust | rustup toolchain `nightly-2026-04-07` |
| Live ABI data | This phone: `uname -r`, `/proc/config.gz`, `/proc/kallsyms`, trace event IDs |

KernelSU must be fetched with full git history. Its kernel protocol code is
`30000 + git rev-list --count HEAD`; a shallow checkout of the pinned commit
builds a false `30001` driver instead of v3.2.5's `32525`.

File hashes are in [checksums.txt](checksums.txt).

## Download provenance

- `SM-A536B.zip` is a Samsung Open Source wrapper. Downloaded it by hand in a browser from the Samsung Open Source Release Center. Recreate this by searching the target model,
  selecting the source release, clicking the Source download icon, and recording
  the wrapper name and SHA-256 before extraction.
- Stock firmware is a separate FUS package. It is not needed for the checked
  ready-made run; it is needed when deriving a new profile. Use `samloader.exe` with model SM-A536E`, region`, and the four-part `A536EXXSNGZG3/...` version. For a new target, repeat the same FUS query/download flow with that target's live model, region, and version.

The repository vendors these two paths from commit:

- `vendor/root-my-galaxy-payloads/kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch` —
  `ffd02ec8f681613bf9e63c755bbdbacfacc43863aff0d99c71de980098ee4110`
- `vendor/root-my-galaxy-payloads/src/su_daemon.c` —
  `d9d9dc8fe8c60a2e2dd6925c947f7b1455e144072409761d308598586d2992ea`


## PoC source trail

`exploit/poc.c` and `exploit/bridge.c` are this project's A536E port. They are
the original new work in a source code form. The base bug and chain came from these two refs:

- `https://github.com/NebuSec/CyberMeowfia.git`, commit
  `2c83bfb0c9230dc063e1bbfc3e06228d45dd938f`, path
  `IonStack/CVE-2026-43499`
- `https://github.com/BuSung-dev/CVE-2026-43499-S25U.git`, commit
  `f6f582a47ee056e44ba66368d382923ecb4bdaf5`

Run `scripts/fetch-references.sh` to get those exact trees. The A53 port is not a
small text diff on either ref. Its reclaim shape, trace leak, direct-map aliases,
and workqueue bridge are target work.

## Other small patches

- `patches/samsung-module-build.patch` fixes the split kernel/UAPI ioctl guard, adds the missing kernel ioctl header, and includes it where Samsung needs it.
- `patches/kernelsu-a53-rkp-no-syscall-table.patch` skips the syscall-table write before it can reach the Exynos RKP hypervisor. This is the only A53-only
  KernelSU source change.
- `patches/rmg-root-helper.patch` gives the fetched RMG helper a neutral loader name and passes `--allow-shell`. The upstream helper path loads the module but leaves adb shell root off.
