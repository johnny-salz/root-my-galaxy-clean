# Root My Galaxy: A53 kit

This kit gives shell root, then live-loads KernelSU on one checked stock build:

`SM-A536E / A536EXXSNGZG3 / 5.10.237-android12-9-31999025-abA536EXXSNGZG3`

No boot unlock. No flash. Root is lost on reboot.

## APK route (development branch)

The APK route and the investigation described below belong to the
[`agent/root-my-galaxy-clean`](https://github.com/johnny-salz/root-my-galaxy-clean/tree/agent/root-my-galaxy-clean)
branch. They are not part of the standalone baseline kept on `main`. The branch
contains the rootless prefetch and KernelSnitch code, the APK-safe lifetime
cleanup, and the structured discovery and oracle notes. Raw run logs and crash
dumps remain local artifacts and are intentionally not tracked.

The hard port is now exposed through the simple
[Root My Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy) APK flow. The
model payload and feed entry are in
[Root-My-Galaxy-Payloads PR #168](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/pull/168).
Until that PR is merged, use a build with the PR payload bundled or served from
its branch.

For the user, the flow is: wait about one minute after a full boot, open the
app, and start root. The APK launches the native chain itself; no `adb shell`,
external slide, tracefs, or perf permission is needed. It finds the KASLR slide,
finds and reclaims the kernel page, installs the root primitive, and late-loads
the matching KernelSU module. Root and KernelSU are volatile, so run the app
again after each reboot.

The final clean-reboot test ran from the normal `untrusted_app` SELinux domain,
reached `ARW_OK`, `PATCH_OK`, and `ROOT_OK`, closed and reaped the forged-fops
workers, loaded KernelSU v3.2.5 (`32525`), and passed `/system/bin/su -c id`.
The Manager showed `Working <LKM>`, `32525-2`.

## What this port had to change

The original APK-to-native launch model was already valid. The missing part on
this firmware was rootless discovery: tracefs and `perf_event_open` worked for
shell calibration but are blocked in the app domain. The development branch
therefore adds:

- an instruction-prefetch KASLR slide finder, with no tracefs runtime fallback;
- KernelSnitch discovery constrained to the verified low and high physmap
  windows for this firmware;
- exact `mm_struct` and SLUB geometry derived from the matching Samsung source
  (`sizeof=0x3b8`, cache stride `0x3c0`, 34 objects in an order-3 slab);
- a Samsung-SLUB-specific drain: CPU-pinned full trigger pages and an extra
  allocation force the frozen target slab out of CPU partial state before an
  order-3 SKB reclaims it;
- first-page-only fake fops, lock, marker, and usercopy data, because the buddy
  allocator may split the reclaimed order-3 slab;
- strict lifetime cleanup: close the forged ARW fd after root, use an explicit
  release path only for oracle runs, and terminate and reap all holder processes.

These values are not generic A53 values. A port to another model or firmware
must rederive the kernel offsets, KASLR anchor, physmap windows, structure and
cache layout, reclaim geometry, and KernelSU compatibility from that exact
kernel. Perf and the rooted oracle are useful as calibration ground truth, but
neither is part of the final APK runtime.

Read [TUTORIAL.md](TUTORIAL.md) for the standalone flow. The development branch
holds the detailed
[empirical record](https://github.com/johnny-salz/root-my-galaxy-clean/blob/agent/root-my-galaxy-clean/DISCOVERY-PROGRESS.md)
and [debug-oracle guide](https://github.com/johnny-salz/root-my-galaxy-clean/blob/agent/root-my-galaxy-clean/ORACLE-HOWTO.md).
See [PORTING.md](PORTING.md) and [PROVENANCE.md](PROVENANCE.md) before adapting
it to another phone.

This can crash the phone. Bad target data can write to a bad kernel address.

Use it only on a phone you own. Back up data first.
