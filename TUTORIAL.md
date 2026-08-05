# Stock Galaxy A53 shell root and live KernelSU

This tutorial runs one checked profile. For a new phone or firmware, read
[`PORTING.md`](PORTING.md) first; its inputs are larger than the run path.

This is the small, checked path. It roots one stock A53 build, then loads
KernelSU in RAM. It does not flash or unlock the boot loader. A reboot removes
root and the loaded module.

Checked target:

```text
model:  SM-A536E
build:  A536EXXSNGZG3
kernel: 5.10.237-android12-9-31999025-abA536EXXSNGZG3
KMI:    android12-5.10
```

Live proof on this build:

- The clean shell-root chain reached `uid=0`, SELinux context `u:r:kernel:s0`.
- The final `ksud` loaded the embedded KernelSU module and stayed live in
  `/proc/modules`.
- `/system/bin/su -c id` returned `uid=0` in `u:r:ksu:s0` after a clean reboot.
- The official Manager then showed `Working <LKM>`, `32525-2`, with no mismatch.
- A second exploit run while KernelSU was live caused a later `reboot,shell`.
  Do not run the exploit again in that state. The script now stops first.

Bad target data can crash the phone or write to a bad kernel address. Back up
data. Use this only on a phone you own.

## What is fixed, and what must change

| Item | Exact A53 build | New phone or build |
| --- | --- | --- |
| Model, build, kernel release | Must match the profile | Make a new profile |
| Trace event IDs | `104`, `260`, `253` | Read live IDs; never copy them |
| Kernel addresses and struct offsets | In `target.h` | Derive from that exact kernel image |
| Samsung source | Operator-downloaded `SM-A536B.zip` wrapper, then its A536B source zip and `Kernel.tar.gz` | Manually get the closest exact release from Samsung; prove ABI match |
| Kernel config | Read live from `/proc/config.gz` | Always replace |
| Kernel clang | `r416183b`, checked and used | Match `/proc/version` as close as the vendor source allows |
| Kernel release and vermagic | Exact full string above | Always replace |
| KernelSU | v3.2.5 exact commit | Keep the pin unless the patch is ported and re-audited |
| Samsung KernelSU patch | Exact RMG patch file and commit | Keep the pin unless re-audited |
| NDK | r29, exact build pin | Newer may work, but is not this checked build |
| Rust | nightly 2026-04-07 | A build pin, not a phone ABI fact |
| adb, Linux distro, job count, paths | Any sound host set | Replace as fit |

KernelSU's driver version is not an app cache. The driver computes its version
from the full KernelSU git history (`30000 + commit count`). A shallow clone
builds the wrong driver (`30001` here). `scripts/fetch.sh` therefore unshallows
KernelSU, and `build-kernelsu.sh` prints the expected code (`32525` for v3.2.5).

“Same 5.10 kernel” is not enough. The PoC constants and module ABI can change in
one firmware update.

## Get tools and source

When using WSL it is better for performance to copy the project once to a Linux path such as `~/root-my-galaxy-clean`

Install host tools:

```bash
sudo apt update
sudo apt install -y git make bc bison flex build-essential libssl-dev \
  libelf-dev dwarves kmod zstd unzip curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly-2026-04-07 --profile minimal \
  --target aarch64-linux-android
```

Install Android NDK `29.0.14206865` with the Android SDK manager:

```bash
sdkmanager 'ndk;29.0.14206865'
```

Or get the Linux zip straight from Google:

```bash
curl -fLO https://dl.google.com/android/repository/android-ndk-r29-linux.zip
echo '87e2bb7e9be5d6a1c6cdf5ec40dd4e0c6d07c30b  android-ndk-r29-linux.zip' | sha1sum -c -
unzip android-ndk-r29-linux.zip -d "$HOME"
```

That SHA-1 and size `783549481` come from Google's current official SDK
repository metadata. In both install forms, `source.properties` must say
`Pkg.Revision = 29.0.14206865`. With the direct zip, use
`ANDROID_NDK_HOME="$HOME/android-ndk-r29"` in later commands.

Get the large-build source from that native WSL copy:

```bash
cd ~/root-my-galaxy-clean
bash scripts/fetch.sh
```

This gets the full KernelSU history. The two small Root-My-Galaxy-Payloads
inputs are already vendored under `vendor/root-my-galaxy-payloads/`

The two PoC reference trees are optional, only for port research:

```bash
bash scripts/fetch-references.sh
```

Get the Samsung Open Source bundle by hand from
`https://opensource.samsung.com/`. Search the target model, choose the source
release that covers the target build, and click its Source download icon. Save
the downloaded wrapper and record its exact name and SHA-256. The wrapper contains the inner source zip and regional
A536B/A536E source zips. Pick the source package that covers the target build.
Then check and extract the inner source archive:

```bash
sha256sum SM-A536B.zip
unzip SM-A536B.zip SM-A536B_16_Opensource.zip
sha256sum SM-A536B_16_Opensource.zip
unzip SM-A536B_16_Opensource.zip Kernel.tar.gz
sha256sum Kernel.tar.gz
mkdir -p ~/src/kernel-a536
tar -xzf Kernel.tar.gz -C ~/src/kernel-a536
```

The inner source and `Kernel.tar.gz` hashes are in `checksums.txt` for the
checked input. The outer wrapper hash is not a source identity: it can contain
many regional packages. For another target, select the matching inner package. Do not force this A536B source on another model.

Get Android clang from this official archive URL:

```text
https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/android12-release/clang-r416183b.tar.gz
```

Then:

```bash
mkdir -p ~/toolchains/clang-r416183b
tar -xzf clang-r416183b.tar.gz -C ~/toolchains/clang-r416183b
~/toolchains/clang-r416183b/bin/clang --version
```

It must say Android clang 12.0.5 based on `r416183b`. The stock kernel says
clang 12.0.4 based on `r416183`; this is the checked vendor compiler family.
Do not use distro clang for the module.

## Check phone facts

With adb on Windows:

```powershell
adb shell getprop ro.product.model
adb shell getprop ro.build.version.incremental
adb shell uname -r
adb shell cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id
```

All four values must match `exploit/profiles/a536e-a536exxsngzg3`. The two kmem
trace ID files are root-only on this stock build. Their pinned values are used
by the chain, then `root.ps1` verifies both through the root helper as soon as
shell root exists. If an open value differs, stop before any write. Make a new
profile from the exact kernel.

## Build and get shell root

Build the small exploit C files from any convenient WSL path:

```bash
export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/29.0.14206865"
bash scripts/build-exploit.sh
```

On Windows, run the chain. Add `-Reboot` for a clean reboot if needed:

```powershell
.\scripts\root.ps1 -Artifacts C:\path\to\exploit\out
```

The script fails if the phone facts differ. It waits for full boot, gets the new
slide for this boot, runs one chain, and proves root with the fetched RMG root
helper. The slide must be read again after every reboot. Zero is a valid slide.
If two runs reboot at the same exploit point, stop. Save the chain log and debug
that point before another try.

After a reboot, unlock the phone. `sys.boot_completed=1` is not enough on this
Samsung build: user data can still be locked while services start. The runner
waits for `sys.user.0.ce_available=true` before touching the exploit.

If `/proc/modules` already has `kernelsu`, do not run the exploit again. Use
`adb shell /system/bin/su -c '<cmd>'`, or reboot and start one fresh chain.

## Get the live ABI inputs

While shell root is live:

```powershell
.\scripts\collect-target.ps1 -OutDir C:\path\to\target-input
```

Copy `target-input` once into native WSL. Then unpack the config:

```bash
gzip -dc ~/target-input/kernel.config.gz > ~/target-input/kernel.config
```

The live config carries CFI, shadow call stack, module version, KDP, RKP, DEFEX, and other ABI facts. The build clears only its stale `CONFIG_UNUSED_KSYMS_WHITELIST` path, which points at Samsung's private build server and is not an ABI fact.

## Build the small KernelSU delta

The build starts from clean KernelSU v3.2.5. It applies:

1. The pinned upstream RMG Samsung KDP/RKP/DEFEX patch.
2. One local A53 patch that skips the RKP-fatal syscall-table write.
3. The small ioctl fix to the checked Samsung source tree.

The exploit build also patches the vendored RMG root helper by two facts: use a
neutral loader name and pass `--allow-shell`. Its bind-load path is needed because
Samsung DEFEX kills direct exec of `ksud` from `/data/local/tmp`.

It does not add `dynsyms.c`. `ksud late-load` already reads `/proc/kallsyms`,
relocates undefined module symbols, and calls `init_module`.

Run:

```bash
export KERNEL_DIR="$HOME/src/kernel-a536"
export KERNEL_CONFIG="$HOME/target-input/kernel.config"
export TARGET_SYMBOLS="$HOME/target-input/kallsyms.txt"
export TARGET_RELEASE='5.10.237-android12-9-31999025-abA536EXXSNGZG3'
export KERNEL_CLANG_DIR="$HOME/toolchains/clang-r416183b/bin"
export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/29.0.14206865"
bash scripts/build-kernelsu.sh
```

The script stops on a wrong NDK, wrong clang, stale `Module.symvers`, wrong
release, non-empty module `__versions`, lost symbol tables, or a missing target
symbol. It also makes the two generated SELinux headers which Samsung's
`modules_prepare` leaves out. A good end says 202 imports and zero missing for
this profile.

The `Module.symvers is missing` warning during `modpost` is expected. Do not copy
one from another kernel build to hide it. The link is allowed to finish only so
`ksud` can relocate names from the live `/proc/kallsyms`; `audit-module.sh` is
the required name and ELF-layout gate.

The script makes:

```text
out/kernelsu.ko
out/ksud
```

`ksud` embeds the stripped module as `android12-5.10_kernelsu.ko`. Keep
`kernelsu.ko` for audit. The phone load needs only `ksud`.

To read kernel logs while this kernel-context root is alive, run:

```powershell
.\scripts\read-kernel-log.ps1 -OutFile C:\path\to\kernel-log.txt
```

Run this before `ksud late-load`. After KernelSU loads, the old helper can no
longer serve kernel-context requests. Do not run the exploit again just to get
logs; reboot first.

## Reboot and live-load KernelSU

Copy only `out/ksud` to Windows. Then:

```powershell
.\scripts\root.ps1 -Artifacts C:\path\to\exploit\out -KsudPath C:\path\to\out\ksud -Reboot
```

The script does this:

1. Reboots and waits for `sys.boot_completed=1`.
2. Waits for `sys.user.0.ce_available=true`; unlock the phone after boot.
3. Checks exact model, build, and kernel.
4. Reads this boot's slide and gets shell root.
5. Pushes `ksud` to the loader path and to `/data/local/tmp/.ksud-stage` (the
   path KernelSU uses while installing `ksud`).
6. Uses the RMG helper's private bind mount to run `ksud late-load --allow-shell`.
7. Proves `kernelsu` in `/proc/modules` and proves `/system/bin/su -c id`.

All seven steps passed in one clean reboot test. A later log-only exploit rerun
while the module was live ended in `reboot,shell`; that unsafe rerun is now
blocked by `root.ps1`.

Do not loop a module that reboots the phone at step 6. That means its source,
ABI, or RKP path is wrong.

## Manager app

Install the official KernelSU Manager v3.2.5 APK from
`https://github.com/tiann/KernelSU/releases/tag/v3.2.5` if app grants are wanted.
The v3.2.5 module pin expects signing hash:

```text
c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6
```

`--allow-shell` gives adb shell root before a manager grant. It does not grant
all Android apps.

`--allow-shell` is a KernelSU module parameter. It sets `allow_shell=1`, so UID
2000 (`adb shell`) is always allowed to call `su`. It is not needed to load the
driver itself. It does widen access: any accepted, authorized ADB host can get
root, so keep USB debugging and host trust under control. This runner needs it
because its final control and proof use `adb shell /system/bin/su`. Without it,
the bootstrap root can still load KernelSU, but this shell path loses root; use
the Manager allowlist or a trusted root broker instead. That no-shell variant is
not tested here.

This does not bypass ADB transport security. USB or wireless debugging must be
on, and the device must have accepted that host's ADB key. An unknown host is
`unauthorized` and cannot reach the shell or root. Any program on an already
trusted host that can use its ADB server can reach shell root while debugging
and the KernelSU driver are active. Revoke old ADB authorizations and turn
debugging off when done. This per-boot runner needs debugging on again after a
reboot.

The screen lock is not a second ADB password. A host key accepted earlier can
still use ADB while the screen is locked. This runner waits for the first user
unlock because Android then makes credential-encrypted data available; a later
screen lock does not hide that data from a process that already has root. Root
also does not normally unlock the Samsung bootloader, and it cannot promise
recovery of credential-encrypted data before the first unlock.

The official v3.2.5 APK is a GitHub release asset. Do not use a random store
repack: the module checks the Manager signature hash above. The Manager is only
the control UI; it does not replace the exploit or make root persistent.

Check the driver, not only the Manager card:

```powershell
adb shell /system/bin/su -c 'id'
adb shell /system/bin/su -V       # ksud/userspace version
adb shell /system/bin/su -c 'cat /proc/modules' | findstr kernelsu
```

The Manager card reads the live kernel ioctl. If it says `30001-2` while the
Manager says `32525`, an old `kernelsu.ko` was loaded earlier in this boot.
`ksud late-load` skips loading when any KernelSU driver is already live; it does
not replace that driver. Reboot, unlock, and run one clean pass with the new
`out/ksud`. Do not tap the app's install action while a driver is already live.

## Why the runner uses ADB

The A53 slide leak is in `exploit/poc.c`. It opens tracefs control, enables
`sched_blocked_reason`, and reads per-CPU `trace_pipe_raw`. The bridge also
opens `perf_event_open` for the allocator events used by the chain. The stock
SELinux policy permits these paths in the ADB shell domain, not in the normal
app domain. A native app copy of the same code is not enough.

The only current ways around ADB are to run the whole chain in a trusted
privileged broker, or to build a new app-domain path that can do both the
slide leak and the perf calls. Supplying `A53_SLIDE` removes only the tracefs
read; it does not fix the app-domain perf denial. A slide from an old boot is
useless because KASLR changes it. `/proc/kallsyms` is also restricted before
root, so KernelSU's post-root resolver cannot replace this first leak. Shizuku,
if used, still needs an external privileged start.

## What is not in this kit

There is no Root-My-Galaxy APK payload for this A53 profile. The working slide
leak needs tracefs, and the root bridge was proved in the adb shell domain.

There is also no persistent boot change. `/data/adb` files can remain, but the
module and root state are gone after reboot. Run the checked chain again.
