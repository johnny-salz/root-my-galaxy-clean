# Clean discovery progress

## 2026-08-06

Scope is only `root-my-galaxy-clean`. The old payload and forks are not part of
the implementation.

Known base:

- `cve-2026-43499-write` is the working A536 pselect primitive.
- `cve-2026-43499-bridge` reaches `ROOT_OK` when shell supplies a fresh slide.
- The bridge still finds its page with `perf_event_open`; this is not fixed yet.
- The write helper still reads slide from tracefs unless a source is selected.

First implementation step:

- `exploit/poc.c` now has a prefetch-only slide probe.
- Run `cve-2026-43499-write prefetch` to print mapped/unmapped controls,
  candidate timings, and the best candidate.
- Set `A53_SLIDE_SOURCE=prefetch` to make the normal write helper use that
  probe. The default tracefs path stays intact until the oracle validates the
  classifier.
- The probe uses only `prfm`, `cntvct_el0`, `mmap`, and `munmap`. It does not
  open tracefs or call `perf_event_open`.

Next proof:

1. Run the probe on one healthy boot.
2. Use the existing clean shell root path as oracle to record the true slide.
3. Compare the best candidate and the timing profile.
4. Tune the classifier only from that evidence, then make prefetch the clean
   default.

Observed on the current boot:

- Tracefs oracle reported slide `0x118000`.
- Data prefetch (`A53_PREFETCH_KIND` unset) had no useful edge.
- Instruction prefetch (`A53_PREFETCH_KIND=instruction`) had a sharp edge:
  candidates below `0x118000` were about `q10=112..156`, while
  `0x118000` and later were `q10=14`.
- The best candidate was `0x118000`, matching the oracle exactly.
- This is only one boot. It is not yet the final classifier or root result.

The first anchor bug is fixed: candidates now start at the A536 image base
`0xffffffc008000000`, not the broad lower bound `KERNEL_TEXT_MIN`.

Second check on the same boot after the classifier change:

- The tracefs oracle reported `0xb0000`.
- The prefetch scan saw the first low pair at `0xb0000` and `0xb8000`.
- It returned the first edge, `0xb0000`; it no longer returns the later minimum.
- The scan default now covers `MAX_PHYSICAL_SLIDE`, not only the low 2 MiB.
- Instruction prefetch is now the default. `A53_PREFETCH_KIND=data` keeps the
  old data variant for comparison, and `A53_SLIDE_SOURCE=tracefs` is oracle-only.

This proves self-contained slide discovery on two boots. It does not yet prove
the full root chain, because page discovery in `bridge.c` still uses the shell-
only perf path.

## Root oracle live check

The same boot then ran the clean shell chain with the prefetch slide and the
existing perf page path. It reached `ROOT_OK` without reboot:

- slide: `0xb0000`
- fops page PFN: `0x8c80c5`
- fops page direct alias: `0xffffff88480c5000`
- root helper: `uid=0`, `context=u:r:kernel:s0`
- post-root shadow ARW read of the workqueue returned kernel bytes

The oracle is still held by the live clean bridge under
`/data/local/tmp/clean-oracle`. Requests must be written atomically: write a
temporary file, then rename it to `request`.

The client is [scripts/shadow-arw.ps1](scripts/shadow-arw.ps1); a read of the
live workqueue through it returned `OK 70e15b1588ffffff`.

## Page discovery probe

`exploit/prefetch-page-probe.c` is a diagnostic only. Root translated its fixed
user page through `/proc/<pid>/pagemap`; the shadow ARW oracle then read the
same direct alias and returned the page marker `0x41`. This validates the
oracle's PFN/alias translation.

The first direct-map cache test is not a classifier yet. Correct and adjacent
wrong PFNs overlap under the current timing/eviction scheme. No page-discovery
code was switched to it, and no blind physical sweep was started.

## Gate and per-boot failures

- A fresh boot gave a prefetch edge of `0x1a38000`, while the shell tracefs
  oracle gave `0x1d8000`. The old two-sample edge rule accepted a false short
  mapped island.
- The KernelSnitch page probe now has an interactive `page-go` gate. It found
  `mm=0xffffff882cac3fc0` and waited before reclaim. A raw shadow read of that
  candidate rebooted the phone. The candidate is not trusted just because it
  is in the direct-map address range.
- Stopping the live pselect helper with `SIGSTOP` also rebooted the phone.
  The bridge now supports `A536_ORACLE_DETACH=1`: after `ROOT_OK` it terminates
  selinux/write/patch helpers and leaves only the fops shadow server alive.
- For the next checks, use the existing shell `perf_event_open` path as the
  page oracle. Do not raw-read a KernelSnitch candidate until a safe validity
  check exists.
- Prefetch edge default is now hardened from 2 to 8 consecutive low samples;
  `A53_PREFETCH_EDGE_RUN` can tune it during controlled checks.
- `chain-auto` was built and its prefetch consensus path was tested. The first
  post-reboot full run stopped before root because this boot has no KernelSU
  and `perf_event_open(mm_page_alloc)` returns `EACCES` for shell. The same
  perf page path reached `ROOT_OK` before that reboot when perf capability was
  live. This is an environment gate, not a new exploit failure.

## Perf and KernelSnitch calibration mode

`exploit/page-leak-probe.c` now has an opt-in `PAGE_LEAK_CALIBRATE=1` mode.
It opens `mm_page_alloc` and `kmem_cache_alloc` perf events before any clone or
spray, with inheritance enabled. It records PFN/order/page-base events and
`mm_struct` allocation pointers in the same run as KernelSnitch.

The probe prints KernelSnitch collision parameters, timing output (with
`PAGE_LEAK_VERBOSE=1`), leaked `mm_struct`, slab offset, object index, cache
geometry, marker location, and a strict comparison line. A candidate is
rejected before reclaim if perf did not see the same object or order-3 slab
page. No q2 write is present in this probe.

`scripts/run-page-calibration.ps1` holds at that gate, asks the live shadow
oracle to read the perf-confirmed candidate page, releases the probe only
after a non-zero read, then checks the `RMG-CLEAN-PAGE` marker after reclaim.

The first safe device check after the last reboot stopped before any spray:

```
PAGE_CALIBRATION_PERF_UNAVAILABLE kind=mm_page_alloc errno=13 Permission denied
```

So the calibration code builds and fails closed, but a real same-run comparison
still needs a boot where the existing shell perf permission is live.

## Geometry audit: A536 runtime ground truth

The A536 oracle boot was restored with a tracefs slide and reached `ROOT_OK`.
The live kernel then reported:

```
mm_struct            769    952    960   34    8
task_struct         2700   2838   4736    6    8
```

For `mm_struct`, the live SLUB object size is `960 = 0x3c0`, with 34 objects
in an order-3 (`0x8000`) slab. This confirms the current KernelSnitch scan
geometry `0x3c0` and order `3` for this device. The name `MM_STRUCT_SZ` in the
probe is really the cache stride; it must not be confused with C `sizeof`.

The offsets probe compiled against the locally merged A536 kernel source emits
`sizeof(struct mm_struct) = 0x3b8`. That source-side size and the runtime
SLUB stride can differ because SLUB rounds the object. The old recovered
artifact also says `0x3b8`; neither value should replace the live cache stride
without a new device check.

The clean bridge has more hard-coded layout offsets for workqueue, configfs,
cred and fops data. They are proven by the live `ARW_OK`, `PATCH_OK` and
`ROOT_OK` checks, but they are not all generated from one checked-in BTF/offset
manifest yet. That is a separate layout-audit task.

Issue #51 in `Root-My-Galaxy-Payloads` is a useful warning, not an A536 source:
it targets SM-S928B on Android 6.1.145. It explicitly separates BTF struct
size from SLUB cache object size and reports a different geometry. Do not copy
its raw values to A536; use the live A536 slab line as the oracle.

The first task-list scanner test was stopped: a read-only scan caused a device
reboot. No more raw task-list reads are allowed until their offsets and read
path are revalidated against the A536 kernel.

## Hardening pass (2026-08-06 evening, live-verified)

1. **Safe kernel reads (crash fix).** The configfs string read path strnlen-faults
   on unmapped VAs (no exception table) and rebooted the device on the task-list
   scan. Added a PTE-walk mapped? gate in bridge.c (`shadow_is_mapped`, guarded
   by `init_mm.pgd` + low-window table translation) applied to every public
   `kernel_read`. Live proof: reading the unmapped hole `0xffffff8100000000`
   now returns `ERR kernel-read` instead of rebooting; mapped reads still work
   (`init_task` returns bytes); hole writes already safe (`ERR kernel-write`).
   Bug found on the way: `init_mm.pgd` is swapper_pg_dir in the kernel image
   (0xffffffc0...) - the first guard rejected it and broke ALL reads (ARW_FAIL);
   fixed by only rejecting `pgd_va < PAGE_OFFSET`.
   `A536_NO_GATE=1` bypasses the gate; `A536_ARW_DEBUG=1` prints gate results.

2. **Window discovery (`windows` shadow command).** Live result:
   `ffffff8000000000-ffffff8080000000` (low physmap 2GB),
   `ffffff8800000000-ffffff8980000000` (high physmap 1.5GB),
   `ffffffc000000000-ffffffc040000000` (kernel image),
   `ffffffd100000000-ffffffd140000000` (vmemmap),
   `fffffffe80000000-ffffffff40000000` (vmalloc/fixmap).
   Feeds `KSNITCH_IDENTITY_WINDOWS`; harness sets it automatically.

3. **KernelSnitch fingerprints.** `approx_time` now the low quartile of 8
   baseline measurements; `KSNITCH_VALIDATE_COLLISIONS` two-pass rejection
   (candidates that do not drop in time after unpiling are dropped). With the
   narrowed windows the brute force ran in seconds and found a real mm:
   `mm=0xffffff8937af7440` (high-window slab, index 31), 3/3 collisions.
   Candidate field verification via the oracle was interrupted by a device
   reboot caused by the probe's own sprays (not by the reads).

4. **Harness.** `run-page-calibration.ps1` now: queries `windows` from the
   oracle, passes `KSNITCH_IDENTITY_WINDOWS` + `KSNITCH_VALIDATE_COLLISIONS`,
   verifies the probe stays alive after start, and fails with the full log.
   `shadow-arw.ps1` gained the `windows` operation.

5. **Ops notes.** Run the clean chain DETACHED from the adb session
   (`setsid sh -c '...' > log 2>&1 < /dev/null &` from a plain adb shell);
   otherwise killing the adb session SIGHUPs the bridge (the umh rmg-root
   survives - it is kernel-spawned). The root-now bootstrap is NOT needed for
   the clean chain (perf + tracefs are shell-accessible).

## Hardcoded identity windows (2026-08-06)

`KERNELSNITCH_IDENTITY_WINDOWS` is now a compile-time constant in
`profiles/a536e-a536exxsngzg3/target.h` (low physmap 2GB + high physmap 2GB,
with a DEVICE-SPECIFIC comment: derive per firmware, do not copy). The oracle
`windows` command remains for deriving it on new firmware; no runtime oracle
dependency for the unprivileged path. Documented in target.env too.

## Session status 2026-08-06 late (KS page integration)

### What works (live-verified)
- Safe kernel reads: PTE-walk gate in bridge.c `kernel_read` (hole read -> ERR,
  no crash). `A536_NO_GATE`/`A536_ARW_DEBUG` switches.
- `windows` shadow command (mapped-window map: low/high physmap, image,
  vmemmap, vmalloc). Hardcoded into target.h (`KERNELSNITCH_IDENTITY_WINDOWS`)
  with a DEVICE-SPECIFIC comment - no runtime oracle dependency.
- kernelsnitch: low-quartile approx_time, two-pass collision validation,
  hardcoded windows -> mm found in seconds (3/3 collisions).
- Slide auto: CPU0-pinned prefetch consensus. Normal chain-auto/chain-ks-auto
  never opens tracefs. `A536_SLIDE_CALIBRATE_TRACEFS=1` enables same-boot
  comparison and selects the tracefs truth only for an explicit debug run.
- chain-ks ordering: KS probe FIRST (clean futex state, pile fully unwinds),
  then selinux trigger, then write. The probe ran, page faulted, fops stage
  reached with pfn=0 (KS base), selinux+write triggers fired.

### What does NOT work yet (the blocker)
- **Cross-cache reclaim miss**: the faulted anonymous page does not land on
  the freed mm slab (base). Symptom: `ARW_FAIL open forged ashmem errno=19`
  (fops table points to garbage -> /dev/ashmem open ENODEV). PAGE_LEAK_DRAIN_PREP
  added to the fops-ks envs to free more slabs (untested).
- Reboots: the GhostLock trigger leaves rt_mutex residue; a later kworker
  crashes in task_blocks_on_rt_mutex (delayed crash). This is the trigger's
  inherent risk - one chain per boot, reboot between runs.

### Ops notes
- one-shot.ps1: build -> size-check push -> launch (kill stale by pidof,
  timestamped log) -> poll. Logs: /data/local/tmp/chain-<ts>.log,
  pointer at chain-latest.log.
- Clean chain does NOT need a perf stage (perf errno=13 boots are SELinux-
  flaky; chain-ks has no perf dependency at all - the point of the work).
- Never run multiple chains/probes per boot (residue accumulation).

### Next
- Tune the reclaim (DRAIN_PREP, freed-slab count, PCP handling, fault timing
  after FREE_OK) so the fault lands on base with high probability, then the
  existing ARW prove validates it end-to-end.
- If reclaim cannot be made reliable: reclaim with a user-mapped memfd page
  (the probe's memfds are user-mapped) instead of an anonymous fault, or
  accept the retry loop (reboot per attempt).

## Perf ground truth beside KernelSnitch (2026-08-06)

The bridge now has an opt-in debug check, `A536_KS_PERF_CHECK=1`. It starts
the working `mm_page_alloc` perf event before the fresh anonymous target page
is faulted, then converts the reported PFN to the A536 physmap alias. It logs
that alias beside the KS slab base and stops before qroute if they differ.

Live result on boot `32b6c7ec-1f14-4abb-b0a8-241ebcaaf6ef`:

```
KS predicted base=0xffffff89335f8000
perf actual alias=0xffffff88b33e1000
match=0
```

With the debug-only `A536_KS_PERF_USE_ACTUAL=1` override, qroute was given the
perf alias in the same run. The fops proof returned `ARW_OK`. This proves the
clean qroute/fops path and the perf locator are sound; the current failure is
the KS freed-mm-page reclaim, not slide, PTE translation, or ARW.

The earlier full KS run also confirms the danger of ignoring this gate: the
predicted base reached qroute and the delayed crash dump shows
`rb_insert_color+0x38`, with `x1=ffffff89329b8008` and
`x3=ffffff89329b8000` (the KS base). Do not run the write trigger unless the
perf check passes, or use the explicit actual-page debug override.

Next work is only in `page-leak-probe.c`: improve the mm-cache drain/reclaim
sequence, then repeat this side-by-side check. The final chain must not depend
on perf; perf is calibration ground truth only.

## Reclaim calibration notes (2026-08-06 late)

- The first probe-side perf check returned `EINVAL` even though the clean
  bridge perf path worked. The probe passed four syscall arguments to
  `perf_event_open`; the missing `group_fd=-1` made the flag land in the wrong
  slot. Fixed and live-verified: `PAGE_CALIBRATION_PERF_READY` now opens both
  tracepoints.
- A late perf mode starts the ring after KS collision collection, so prep
  allocation noise does not fill the ring. It showed clean order-3 samples,
  but the KS low-window candidate did not match any SKB allocation.
- The probe now has a debug-only `PAGE_LEAK_SKB_RECLAIM` path. Its ordering
  follows the old source: pcp send first, one post neighbor held, late prep
  drain, SKB sends, then optional KS bruteforce. No qroute or kernel write is
  reached by this mode.
- Four late-bruteforce calibration attempts so far all missed the exact page.
  This is expected to be probabilistic; the old A536 notes report about one
  positive landing per forty attempts. The perf side-by-side check is now
  valid and safe, but it has not yet produced a positive KS-to-SKB match.

## Same-run KS/perf audit and oracle read failure (2026-08-06 night)

The comparison is not split across boots. In one probe process KS first leaks
the freed `mm` slab base, then the same process sends the SKB payload while the
late perf ring records the order-3 allocations. The compare uses the raw base,
so time spent before a later oracle read cannot turn a real match into
`accepted=0`. Repeated attempts on one settled boot gave the same result:

```
PAGE_CALIBRATION_COMPARE candidate=... accepted=0
PAGE_CALIBRATION_REJECT skb_not_on_candidate
```

This means the KS base was not among the SKB allocation bases observed in that
attempt. It is not a delayed-read race. The root-oracle process may perturb the
allocator before the attempt, but it cannot change the already-recorded raw
base comparison.

For direct inspection, `page-leak-probe.c` now has a debug-only
`PAGE_LEAK_HOLD_ON_REJECT=1` mode. It keeps the SKB/socket alive after a failed
perf gate and prints `PAGE_LEAK_FREE_OK`, without entering q0. On boot
`2aa1fc25-cc75-4194-a8b2-6fd7321ac68e` it held:

```
candidate mm=0xffffff8044464b00 base=0xffffff8044460000
perf free base=0xffffff804b5c8000
```

The shadow oracle first proved the candidate PTE was mapped (`phys=0xc4460000`),
but a raw configfs read of `base+0x100` then rebooted the phone. This is the
known second crash class: the PTE gate filters unmapped VAs, but regular
configfs `simple_read_from_buffer()` still runs hardened-usercopy checks on the
source object and can BUG when the requested range is outside that cache's
usercopy whitelist. Do not repeat raw shadow reads on unknown slab/buddy pages.

Current calibration truth:

```
KS candidate -> freed mm order-3 base
perf alloc   -> some order-3 SKB allocation base
oracle read  -> unsafe through the regular configfs read path
```

Next debug step is a safe readback channel (kernel-module/probe-kernel-read or
another kernel path with exception-table handling), then compare the held
candidate's marker/fops bytes. `PAGE_LEAK_HOLD_ON_REJECT` stays debug-only; it
must never be enabled for q0. Update this section after each live boot, probe
batch, or oracle change, before starting the next disruptive run.

## Exact crash path for raw oracle read (2026-08-06)

The crash is now identified from the A536 kernel source and the saved panic
stack. It is not a page-table fault. It is a deliberate hardened-usercopy
`BUG()`:

```
pread
  -> configfs_read_file
  -> simple_read_from_buffer
  -> copy_to_user
  -> __check_object_size
  -> __check_heap_object
  -> usercopy_abort
  -> BUG() / reboot
```

The saved stack is in
`artifacts/android/20260806-root-oracle/kp137/dumpstate_debug_history.lst`.
It shows `usercopy_abort -> __check_heap_object -> __check_object_size ->
simple_read_from_buffer -> configfs_read_file -> pread64`.

`configfs_read_file()` treats forged `buffer->page` as the source of a normal
userspace read. The PTE gate only proves that the source VA is mapped. For a
KS candidate, the source still lies in a `PageSlab` page owned by the
`mm_struct` cache. `__check_heap_object()` computes the SLUB object offset and
requires the requested range to be inside that cache's usercopy whitelist.
This kernel creates `mm_struct` with `kmem_cache_create_usercopy()` and
whitelists only `saved_auxv`; the arbitrary probe offsets are outside that
range. The range is rejected and `usercopy_abort()` calls `BUG()`. A mapped
freed object can therefore reboot the phone even when the PTE walk says
`mapped=1`.

Live root read of `/sys/kernel/slab/mm_struct` confirms `object_size=960`
(`0x3c0`) and `usersize=368` (`0x170`). The recovered exact layout puts
`saved_auxv` immediately before `rss_stat` at `0x2d8`, so its whitelist starts
at `0x168`. Reads such as candidate `+0x100` are outside the whitelist by
design; this is the kernel's own object-range check, not a size check added by
our bridge.

This also explains the perf mismatch. The KS candidate is an object freed back
to the mm SLUB freelist; it is not necessarily a whole order-3 buddy page.
`mm_page_free` (live trace ID `258`) reports whole-page buddy frees, not every
SLUB object free. The live trace IDs on this boot are
`kmem_cache_alloc=253`, `kmem_cache_free=257`, `mm_page_alloc=260`,
`mm_page_free=258`.

Do not use the regular configfs ARW path to inspect unknown slab pages. The next
oracle change must use an in-kernel no-fault copy path, or only inspect fields
already known to be safe. Add `kmem_cache_free` capture before another reclaim
change; it can show whether the exact KS object was freed while the slab page
stayed allocated. Keep the one-chain-per-boot rule.

### Safe whitelist proof (boot `726f56fb-010b-4bfb-bf07-12acb18bf2bd`)

I started one clean root oracle with shadow ARW, then ran KS free-only without
q0. KS found and held:

```
mm   = 0xffffff8022dea580
base = 0xffffff8022de8000
```

The oracle read `mm+0x168` for 8 bytes and for the full `0x170` byte whitelist
both returned normally. The 8-byte result was `2100000000000000`. This is a
live proof that the same mapped SLUB page is safe only inside the kernel's
`saved_auxv` usercopy window. The earlier `base+0x100` crash is therefore the
expected whitelist abort, not a bad PTE walk or a delayed allocator race.

The raw logs are in `artifacts/android/20260806-usercopy-safe/`. The probe was
released and all its children exited; the root oracle stayed live.

### Object-free proof (same boot)

Added optional `PAGE_LEAK_PERF_OBJECT_FREE=1` capture for trace ID `257`
(`kmem_cache_free`). On the same settled boot, KS found:

```
candidate mm   = 0xffffff892fff4ec0
candidate base = 0xffffff892fff0000
```

The same-run perf result was:

```
PAGE_CALIBRATION_PERF_PAGE id=260 samples=226 order3=35 lost=0
PAGE_CALIBRATION_PERF_FREE samples=265 order3=4 lost=0
PAGE_CALIBRATION_PERF_OBJECT_FREE samples=315 lost=0
PAGE_CALIBRATION_COMPARE candidate=0xffffff892fff0000 \
  kmem_exact=0 kmem_base=0 object_free_exact=1 object_free_base=1 \
  page_order3_base=0 page_free_base=0 accepted=1
```

This is the missing proof: KS points at an object that really emitted
`kmem_cache_free`, but its order-3 slab page did not emit the matching
`mm_page_free` or SKB order-3 allocation. The old perf page oracle was asking
the wrong question for this stage. It can validate whole buddy-page reclaim,
but not the initial SLUB object free. The reclaim bug is now narrowed to
draining/reclaiming that freed SLUB page, not KS address discovery.

The probe stopped before q0 and the phone stayed on boot
`726f56fb-010b-4bfb-bf07-12acb18bf2bd`. Raw log:
`artifacts/android/20260806-usercopy-safe/ks-object-free.log`.

## SLUB partial flush check (2026-08-06)

The kernel source and live sysfs agree on the reclaim model:

```
/sys/kernel/slab/mm_struct/cpu_partial = 13
/sys/kernel/slab/mm_struct/min_partial = 5
/sys/kernel/slab/mm_struct/objs_per_slab = 34
/sys/kernel/slab/mm_struct/order = 3
```

`cpu_partial` counts free objects, not slab pages. One empty `mm_struct` slab
therefore contributes 34 free objects and is enough to exceed the CPU partial
limit, but `put_cpu_partial(..., drain=1)` flushes the old CPU-partial chain
when a later free arrives on that same CPU. The just-added page can remain
there until the next free.

After unfreeze, an empty page is sent straight to buddy only when the node
partial count is already at least `min_partial`. Otherwise it stays on the
node partial list. This check happens while that page is being unfrozen; later
non-empty partial slabs do not retroactively discard it. Thus CPU flush is
necessary, but the exact free order also matters.

The current probe pins the main process to CPU0 inside `kernelsnitch_setup()`
before the target collision child is forked. Prep children are also pinned.
The early spray children are created before that pin, so their later memfd
closes need separate accounting. The next calibration must log per-page free
counts and make the candidate page's CPU and unfreeze order explicit.

Root-only `/sys/kernel/slab/mm_struct/shrink` is a useful calibration oracle:
the kernel implementation first calls `flush_all(s)` and then discards empty
node-partial slabs. It can prove that the candidate page is valid for SKB
reclaim, but it cannot be part of the final rootless chain.

Even with a green page-reclaim gate, fops placement remains a separate stage;
the earlier `ARW_FAIL open forged ashmem errno=19` is not evidence against KS.

### Shrink gate run (boot `ec8988e3-39d0-4060-9d3a-2888082c0635`)

The probe paused before its first SKB send. The live clean oracle then ran:

```
BEFORE: slabs=50 partial=0 slabs_cpu_partial=30(8) C0=2(2) C2=1(1) C6=27(5)
AFTER:  slabs=48 partial=5 slabs_cpu_partial=17(6) C2=17(6)
```

The perf window saw `mm_page_free order3=11`, but none of the 11 freed-page
bases matched the KS candidate. After the gate was released, SKB still did not
land on the candidate:

```
candidate base=0xffffff8936a90000
object_free_exact=1 object_free_base=1 object_free_page_frees=34
page_order3_base=0 page_free_base=0 accepted=1
PAGE_CALIBRATION_REJECT skb_not_on_candidate
```

The `34` value was an event count, not yet a count of distinct object pointers.
The probe now prints `object_free_page_unique`; the next run must use that value
before changing SLUB free order.

This run is red for `shrink -> SKB`, but it does not support a page-allocator
PCP explanation. In the exact kernel source, `free_the_page()` calls
`free_unref_page()` only for order 0; order-3 pages use `__free_pages_ok()` and
go straight to the buddy path. CPU affinity still matters for SLUB CPU-partial
ownership and for where the spray/free work runs, but not because shrink puts
this order-3 page in another CPU's page PCP.

### Shrink gate green run (same boot `ec8988e3-39d0-4060-9d3a-2888082c0635`)

The next probe used the unique-pointer counter and paused before SKB. Oracle
state was:

```
BEFORE: slabs=56 partial=0 slabs_cpu_partial=27(16) C0=9(9) C2=17(6) C3=1(1)
        objects_partial=0
AFTER:  slabs=48 partial=5 slabs_cpu_partial=17(6) C0=6(5) C1=11(1)
        objects_partial=13
```

The same-run result was:

```
candidate mm=0xffffff893965c740 base=0xffffff8939658000
PAGE_CALIBRATION_PERF_PAGE id=260 samples=229 order3=33 lost=0
PAGE_CALIBRATION_PERF_FREE samples=342 order3=1 lost=0
PAGE_CALIBRATION_PERF_OBJECT_FREE samples=419 lost=0
PAGE_CALIBRATION_COMPARE candidate=0xffffff8939658000 \
  kmem_exact=0 kmem_base=0 object_free_exact=1 object_free_base=1 \
  object_free_page_frees=34 object_free_page_unique=34 \
  page_order3_base=1 page_free_base=0 accepted=1
PAGE_CALIBRATION_SKB_ACCEPT alloc_confirmed=1
```

This closes the main question. KS found the real candidate object. All 34
objects in its slab emitted distinct free pointers. Root `shrink` flushed the
SLUB partial state; the next order-3 allocation observed by perf used the exact
candidate page. The earlier red run was not a KS miss: it had not yet proved
that its 34 free events were distinct.

The raw log is
`artifacts/android/20260806-slub-flush/ks-shrink-run2.log`.

### Rootless brute-before test (boot `e49ecd07-6327-48b6-86a0-3ca350b29ae6`)

The first rootless attempt learned the KS candidate before SKB, then closed all
remaining prep and spray refs on CPU0. Before SKB the root oracle showed:

```
partial=6
slabs_cpu_partial=13(13) C0=12(12) C7=1(1)
objects_partial=17
```

Perf still saw 34 distinct frees for the candidate, but no candidate page
allocation:

```
candidate base=0xffffff800f198000
object_free_page_frees=34 object_free_page_unique=34
page_order3_base=0 page_free_base=0
PAGE_CALIBRATION_REJECT skb_not_on_candidate
```

This means empty node-partial slabs can remain after the free burst. More frees
alone do not discard them. The next mode holds one full slab of new refs and
closes that batch (`PAGE_LEAK_FLUSH_ALLOC_ROUNDS`), so the allocator must take
an existing empty partial slab, refill it, and empty it again while
`nr_partial >= min_partial`.

The first held-batch run used `pages=8` and reverse free. It still missed the
candidate, but its slot proof was complete:

```
object_free_page_unique=34
object_free_page_slots=34
object_free_page_bitmap=0x00000003ffffffff
page_order3_base=0
```

The next run keeps the same batch and frees FIFO, so the last partial page
selected by allocation is emptied last.

### Batch refill result (same boot)

Two `34`-object refill batches were not enough. The probe paused with:

```
partial=7
slabs_cpu_partial=14(14) C0=14(14)
objects_partial=49
```

The candidate still had `object_free_page_unique=34`, but
`page_order3_base=0`. Live sysfs reports `destroy_by_rcu=0` for this cache, so
RCU grace delay is not the cause on this firmware. The next test increases the
batch count on a clean boot to walk all current partial pages.

The `16 x 34` run was also red. It used sixteen allocate/free rounds, so each
round put its current page back before the next round. That is not the required
partial-list experiment. The probe now supports one held batch of
`PAGE_LEAK_FLUSH_ALLOC_PAGES * 34` refs, then frees the whole batch in one
chosen order. It also prints a 34-bit slot bitmap, not only event and pointer
counts.

### No-reboot rotation and perf scope checks (2026-08-07)

Standalone probes are safe to repeat on the same boot. Each failed calibration
probe exited before the SKB send and left no trigger state. Between attempts the
live root oracle reset the cache with:

```
echo 1 > /sys/kernel/slab/mm_struct/shrink
echo 3 > /proc/sys/vm/drop_caches
```

The ordered dummy free was tested after a held `16 * 34` batch. It freed the
pulled-slab ref first, then all 34 target refs. The candidate still had a full
34-slot free bitmap, but no candidate `mm_page_free` event. The perf report saw
nine unrelated order-3 frees. This proves the old dummy order was not the only
miss: the dummy allocation did not select the KS page.

The probe now has an optional address-directed debug mode. It filters
`kmem_cache_alloc` to `bytes_req == 960`, holds every ref while walking the
cache, and keeps only 34 refs from the KS candidate base plus one next ref.
Tests with 4096 held allocations found no candidate-base allocation, both with
the normal `pid=0` scope and with `pid=-1,cpu=0` scope. The latter opened cleanly
and closed the perf blind zone for other tasks. The raw logs are
`artifacts/android/20260806-slub-flush/ks-target5.log` and
`artifacts/android/20260806-slub-flush/ks-target-cpu0.log`.

The rootless memory-pressure test used an anonymous 4096 MiB mapping for 20 s.
It changed live `mm_struct` partial state (`partial 7 -> 5`) but did not emit a
candidate order-3 free. In both PID and CPU-wide runs the candidate later had
34 exact `kmem_cache_alloc` events, yet SKB did not land on that page. Pressure
alone is therefore not a working drain. Logs:
`artifacts/android/20260806-slub-flush/ks-pressure.log` and
`artifacts/android/20260806-slub-flush/ks-pressure-cpu0.log`.
The standalone pressure helper was diagnostic only, is not used by the final
chain, and is intentionally omitted from the branch.

Current conclusion: KS candidate correctness remains proven by the green root
shrink run. The rootless blocker is the SLUB state transition from an empty
candidate slab to buddy; simple dummy order, held-batch refill, and memory
pressure have not produced that transition. Keep perf as a calibration gate,
but do not call a candidate rootless-valid until its own `mm_page_free` event is
seen.

### Interactive S1 rotation and reboot audit (2026-08-07)

The rewritten rotation was tested with `KEEP_PREP_CHILDREN=0` and an explicit
pause after the 34 target frees, before the S1 trigger. The run found 34 exact
allocations on the KS base and held S1 and S2 refs. Oracle state at the pause
was `partial=11`, `cpu_partial=13`, `slabs=19`, `objects=343`. Releasing S1
did flush other partial slabs (`slabs=18`, `partial=9`), but the candidate did
not emit `mm_page_free` and the perf gate stayed red (`order3=0`). Thus the
target was not in the CPU-partial chain drained by that S1 free, even though
the target had 34 distinct object frees. This is a real placement/CPU-state
miss, not proof that KS chose a wrong page.

An attempt to inspect the candidate's `struct page` through the configfs ARW
oracle was unsafe. The PTE gate returned `mapped=1` for the derived vmemmap
address, but the following string-path read disconnected the device and caused
a reboot. Do not use raw ARW reads of vmemmap/page metadata for this diagnosis;
use perf and the root slab sysfs oracle instead.

The next boot audit found a second reboot cause: after `scripts/root.ps1` had
already reached `ROOT_OK`, a second clean chain was launched on the same boot.
That violated the one-chain-per-boot rule and hit the known delayed
GhostLock/rt_mutex crash. The safe command is one detached chain after boot,
then only `/data/local/tmp/rmg-root -c ...` and standalone FREE_ONLY probes.
The current detached chain was verified with `uid=0` and sysfs access; no
second chain is allowed on this boot.

### Exact vmlinux callsite correction and live rotation (2026-08-07)

The exact recovered image is
`root-my-galaxy-investigation/analysis-a53x-ngzg3/stage5a/recovered/vmlinux.elf`.
It shows two real `mm_struct` allocation callsites:

```
mm_alloc:  bl kmem_cache_alloc at 0xffffffc0080cd558
            trace return address 0xffffffc0080cd55c
copy_mm:   bl kmem_cache_alloc at 0xffffffc0080d0c7c
            trace return address 0xffffffc0080d0c80
```

Live callsite `0xffffffc008148c80` is `copy_mm+0x6c` after slide `0x78000`,
not a foreign cache. The temporary filter for the unslid `mm_alloc` address
was wrong and was removed. The working perf filter stays `bytes_req == 960`;
the exact source zip supplied by the user is recorded at
`analysis-a53x-ngzg3/source/SM-A536B_16_Opensource_A536BXXSNGZG3_A536EXXSMGZF1_A536EXXSNGZG3.zip`.

The corrected probe now proves the KS address path on live runs:
`kmem_exact=1`, `kmem_page_unique=34`, and bitmap
`0x00000003ffffffff`. The 35th dummy allocation is on a different order-3
page. We also added a post-target full-slab trigger based on the exact
`put_cpu_partial`/`unfreeze_partials` path, plus waits for deferred
`kmem_cache_free` events. The target free wait sees all 34 original frees.

Three live runs with this sequence stayed safe and did not send SKB. The
candidate still had no observed `mm_page_free` event. One run had a perf result
buffer overflow; after increasing the result buffer to 16384, the run had
`free samples=4982`, `lost=0`, `order3=0`, and no free event inside the
candidate page. The post-target dummy-free wait saw `0/34` new frees, so the
dummy refs are not yet proven to have reached `__mmdrop` before the trigger.
This is now the next concrete gate: prove the second generation's 34 frees,
then re-run the post-target trigger. Do not infer KS failure from the red page
gate until that wait is green.

### Held trigger slabs and green page-free gate (2026-08-07)

The prior one-page post-trigger loop was not a valid SLUB test. It freed each
trigger page before allocating the next one, so the allocator reused the same
two pages. It also freed the KS target before making new trigger allocations,
which let later allocations take the target page again.

The probe now does the required order:

```
hold target 34
hold 14 distinct full mm_struct slabs (34 each)
hold one separate s2 object
free target 34
free one object from each trigger slab
free the remaining trigger objects and s2
```

The exact vmlinux code confirms why 14 trigger slabs are needed. On this
Samsung 5.10 tree, a full page becomes a frozen CPU-partial page on its first
slow free, so `pobjects` increases by 1, not by 34. The `put_cpu_partial` test
is `oldpage->pobjects > cpu_partial`; with `cpu_partial=13`, target plus 14
trigger pages reaches the `unfreeze_partials` path. The target is then checked
for `inuse==0` and discarded when the node partial count is already high.

Calibration run: `/data/local/tmp/ks-cpu3-pool5.log`. It used CPU3, the exact
current-boot `__mmdrop` free callsite filter, and a page perf filter
`order >= 3` to remove unrelated small-page noise. Results:

```
14 distinct trigger bases, 34 held objects each
target free wait: 34/34
object_free_page_unique: 34
mm_page_free candidate event: order=3, exact candidate base
PAGE_CALIBRATION_PAGE_FREE_GATE_OK
PAGE_LEAK_SKB_SENT sends=1
PAGE_LEAK_SKB_RECLAIM_DONE
PAGE_LEAK_FREE_OK
```

This is the first live proof that KernelSnitch's candidate page is real and
can be driven from SLUB to buddy on this boot. `PAGE_LEAK_FREE_ONLY=1` stopped
before the dangerous q0/root write, so this run validates page placement and
reclaim, not a new full root. `kmem_exact=0` in the final summary is expected:
the perf stream was restarted after the original candidate allocation window;
the independent 34-object free bitmap and the order-3 candidate free are the
valid checks for this stage.

The callsite correction and this SLUB result must stay separate: the old
unslid `mm_alloc` filter was a harness bug and remains removed; the
`copy_mm+0x6c` events are valid `mm_struct` fork allocations. The `pobjects`
freeze/drain issue is a different, real bug in the old rotation harness.

### Perf-free controlled KS group (2026-08-07)

The first no-perf target refill tried to reacquire the old KS base. It did not:
new controlled allocations went to other slabs, so the old page was still held
in SLUB or had a live foreign object. This was a drain/ownership issue, not a KS
miss.

The next dry probe removed that assumption. For each new controlled child it ran
KernelSnitch again, kept the child's `/proc/<pid>/mem` fd, and grouped the leaked
`mm` addresses by page base and slot. It stopped only on a page with all 34
unique `mm_struct` slots owned by these controlled fds.

Live result, no `perf_event_open`, no root oracle in the probe, and no SKB/q0:

```
first group: 33/34 slots (one foreign live mm)
second group: 34/34 slots
PAGE_LEAK_NO_PERF_GROUP_FULL group=1 base=0xffffff89367a0000
PAGE_LEAK_NO_PERF_GROUP_TARGET ok=1 max=150
```

The dry run exited cleanly and the phone stayed on the same boot. This proves a
viable perf-free ownership path: choose a fully controlled KS-leaked slab, free
its 34 refs, then apply the 14-page SLUB trigger and SKB. Perf is now only a
calibration check for that later trigger, not a runtime input.

The next no-perf dry run kept that full group, allocated `14 * 34` trigger refs
plus one separate `s2`, then completed the target/trigger free order:

```
PAGE_LEAK_NO_PERF_GROUP_FULL base=0xffffff8835308000
PAGE_LEAK_NO_PERF_TRIGGER_READY pages=14 refs=476 s2=513
PAGE_LEAK_NO_PERF_TARGET_FREED refs=34
PAGE_LEAK_NO_PERF_TRIGGER_DONE pages=14
```

It stopped before SKB and stayed on boot. This confirms the runtime path no
longer needs perf to select or free the target. The remaining check is whether
the blind 14-page trigger gives SKB the target page; use perf only in a separate
calibration run for that check, then remove the calibration flag.

### Perf-free KS load reduction (2026-08-07)

The first full `chain-ks-auto` test used the heavy repeated helper scan
(`collisions=8`, `appended=2048`). It stopped at helper attempt 27 with a NUL
tail and the phone rebooted. The log had not reached group-full, SKB send, or
q0. This was probe load/residue, not proof that perf was needed.

The no-perf helper now switches only its repeated scans to
`collisions=4`, `appended=256`; the initial candidate scan stays at the normal
settings. A standalone no-perf group+drain dry run then found a full group and
completed the trigger order on one boot:

```
PAGE_LEAK_NO_PERF_GROUP_FULL base=0xffffff8934f70000
PAGE_LEAK_NO_PERF_GROUP_TARGET ok=1 max=70
PAGE_LEAK_NO_PERF_TRIGGER_READY pages=14 refs=476 s2=513 cpu=2
PAGE_LEAK_NO_PERF_TARGET_FREED refs=34 cpu=2
PAGE_LEAK_NO_PERF_TRIGGER_DONE pages=14 cpu=2
```

No perf event, root read, SKB, or q0 was used. The phone did not reboot. The
next full-chain test will use this perf-free branch; perf remains an optional
calibration branch only.

### Fresh no-perf bridge and q0 boundary (2026-08-07)

One earlier full-chain result was invalid: the device had the old `rb3`
binary (42008 bytes), so it did not contain the fast-helper env. After pushing
the current bridge (42072 bytes) and checking its SHA-256 against the host,
the fops stage showed the fast marker and completed without perf:

```
PAGE_LEAK_NO_PERF_FAST_KS collisions=4 appended=256
PAGE_LEAK_NO_PERF_GROUP_TARGET ok=1
PAGE_LEAK_TRIGGER_DONE pages=14
PAGE_LEAK_SKB_SENT sends=1
PAGE_LEAK_SKB_RECLAIM_DONE
fops pid=... pfn=0 lock=... fops=...
```

The fresh full chain then reached the same no-perf group/reclaim and produced
the fops proof. It passed the selinux trigger and died only after q0 was
started; no `perf_event_open` path ran. A separate known clean chain reached
`ARW_OK` and `PATCH_REQUEST` before its own q0 patch reboot. Thus the current
blocker is q0 patch/trigger stability, not KS page discovery or perf.

Runtime rule is now explicit: normal `chain-ks-auto` sets
`A536_KS_SKB_PAYLOAD=1` but not `A536_KS_SKB_CALIBRATE`; the perf branch exists
only for an intentional calibration run.

### No-perf target-free wait and fresh chain (2026-08-07)

The no-perf group path now has an optional one-second wait after closing all
34 target `/proc/<pid>/mem` refs. This gives deferred `mmput/__mmdrop` work a
chance to finish before trigger frees. A standalone dry run stayed on boot:

```
PAGE_LEAK_NO_PERF_GROUP_FULL base=0xffffff8932f88000
PAGE_LEAK_NO_PERF_TARGET_WAIT ms=1000
PAGE_LEAK_NO_PERF_TARGET_FREED refs=34
PAGE_LEAK_NO_PERF_TRIGGER_DONE pages=14
```

The current bridge carries this wait and was hash-checked on device. A fresh
no-perf chain found a full group, completed the wait, trigger, SKB reclaim and
fops proof, then reached the selinux trigger. The phone rebooted during that
GhostLock/selinux stage before a stable q0 handoff. This is not a perf or KS
page-discovery failure; the no-perf page stage is still the furthest proven
boundary.

An opt-in `PAGE_LEAK_GROUP_CALIBRATE` debug switch was added to the probe to
compare that group path with perf free/alloc events when a rooted calibration
boot is available. It is never set by `chain-ks-auto`.

### Perf is not the no-perf blocker; stale q0 was (2026-08-07)

The q0 relay was added to the KS bridge. It showed the old q0 failure directly:

```
q0: physical slide=...
q0: start mode=write ...
q0: requeue returned=-1 errno=35
```

The device then panicked in `rt_mutex_adjust_pi`; no perf call was involved.
The saved Samsung dump identifies `qroutehold2` in
`rt_mutex_adjust_prio_chain`/`rb_insert_color`, matching the known one-chain
GhostLock residue. The relay is diagnostic only; it does not add perf.

The launcher had another stale-process bug: the probe changes its comm name to
`rmg-page-leak`, while cleanup killed only `page-leak-probe`. It now kills both
names. Old q0 processes can remain in an uninterruptible futex path, so a fresh
boot is required before another q0 run. The saved panic is in
`artifacts/android/20260807-kpanic/`.

Normal `chain-ks-auto` still sets `PAGE_LEAK_NO_PERF=1` and does not set
`A536_KS_SKB_CALIBRATE`; perf is optional ground truth only.

### Perf is not a runtime dependency (2026-08-07)

Clarification: the normal KS chain must not wait for, open, or compare against
perf. `A536_KS_SKB_CALIBRATE` is the only branch that enables late perf events.
The normal branch uses the KS group, SLUB trigger, and SKB reclaim alone. Perf
can be used later as a separate oracle run, but it is not an acceptance gate.

The fresh no-perf run reached the q0 trigger. The phone then rebooted on a new
q0 process, not in page discovery:

```
PC rt_mutex_adjust_prio_chain+0x168/0x8c8
task qroutehold2:25636
fault 0x339
x3=0xffffff8931148000  (the KS fake-lock page base)
```

Artifact: `artifacts/android/20260807-kpanic-0452/`.
This moves the active blocker to q0 PI geometry/lifetime. Do not add perf back
to the runtime chain to debug this; use q0 logs and the root oracle only when a
safe read is needed.

### No-perf reclaim gate before q0 (2026-08-07)

The panic dump exposed a separate false assumption in the no-perf bridge. The
KS base was passed to q0 without proving that SKB had reclaimed that exact
page. The dump showed the supposed fake-lock page still held old `mm_struct`
data (`base+0x10 == 0x301`) instead of the SKB payload. That is why q0 entered
`rt_mutex_adjust_prio_chain` with a bad waiter pointer. This is not a perf
failure: the no-perf path had no runtime perf call, but it lacked a page-identity
gate.

`bridge.c` now checks, after SELinux is disabled and before q0 starts:

- forged fops at `alias+0x100`;
- SKB marker `0x4135333652454144` at `alias+0x800`;
- zero fake-lock bytes at `alias+0x00..0x1f`.

The check uses the existing PTE-gated ARW read. A mismatch emits `ARW_FAIL`
and holds the probe; q0 is not launched. Perf stays only in the explicit
calibration branch.

### Target-last calibration and ARW read limit (2026-08-07)

The first perf calibration freed the candidate before its trigger pages. SKB
then took a trigger page, so that order was wrong. The probe now frees 33 of
34 target refs, frees all trigger refs and `s2`, then frees the final target ref
last. This makes the candidate the last buddy page seen by the SKB path.

With this order, a calibration run accepted the exact candidate page for both
free and later order-3 alloc. A separate no-perf group run, with perf started
only immediately around the drain for measurement, showed the same result:

```
PAGE_LEAK_NO_PERF_DRAIN_CPU cpu=0
PAGE_LEAK_NO_PERF_TARGET_TAIL_FREE cpu=0
PAGE_CALIBRATION_PERF_PAGE ... base=<candidate>
PAGE_CALIBRATION_COMPARE ... page_order3_base=1 page_free_base=1 accepted=1
```

This is calibration evidence only. The normal bridge still does not open perf
and does not receive a page address from perf.

The q0 payload read gate cannot be used as ground truth for this reclaimed
page. On a no-perf candidate the PTE walk returned `-1`/`ERANGE`; with the gate
disabled the configfs read returned `EIO`. These are failures of the ARW read
transport, not proof that KS picked a wrong page.

One explicit debug run skipped that read gate and let q0 write. The phone
rebooted in the q0 PI path. That run was intentionally blind and is not a
valid KS verdict; it only confirms that raw q0 write must not run without a
real page-content proof. The skip flag is debug-only and is not set by the
normal launcher.

After the reboot, an immediate clean shell probe also hit `perf_event_open`
permission denied. Waiting for boot settling is needed for the old clean
oracle, but this does not change the no-perf runtime rule.

### Analysis check: EINVAL and the PTE-gate "hole" theory (2026-08-07)

Two external-review claims were checked against code, vmlinux, and the live
boot log:

1. **`ARW_FAIL q0 lock clear errno=22` really means f_op was not replaced.**
   This kernel's `drivers/staging/android/ashmem.c` has NO write method at all
   (only read_iter/llseek/mmap). A pwrite on the real ashmem fops therefore
   returns `-EINVAL` from the VFS, not from an `asma->file == NULL` check as
   upstream says. Verdict stands: EINVAL = f_op replacement did not take, so
   the forged configfs table was not in place at the reclaimed page.
2. **The "page-table pages live in a 4GB-36.5GB phys hole" theory is FALSE
   for this firmware.** Boot log (`[MEM_NODE] System Memory Nodes`) lists the
   only system RAM as 6 blocks: low `0x80000000-0x100000000` and high
   `0x880000000-0xa00000000` (contiguous 6GB). There is no allocatable RAM in
   the gap, so page-table pages cannot be allocated there. Widening
   `ks_phys_to_low_va` into the hole (e.g. `KS_LINEAR_LOW_END=0x280000000`)
   would only turn bogus table entries into crash-prone unmapped reads. The
   current two-window gate already covers every possible table page.
3. **Calibration callsite filter was dead.** `PAGE_LEAK_PERF_OBJECT_FILTER`
   used `0xffffffc0080cd1f4`, which vmlinux disassembly shows is `ldr x19,
   [sp,#16]` inside `mm_alloc` - not a kmem_cache_alloc/free call site. Any
   calibration run using it could not match mm events. Removed from the
   `A536_KS_SKB_CALIBRATE` env set; the `bytes_req == 960` filter is the
   verified gate.

### Diagnostics added to check_q0_page (2026-08-07)

`check_q0_page` no longer aborts on the first failing check. One run now
prints all verdicts before any `hold_dirty_failure`:

```
Q0_PAGE_CHECK alias=... fops=0/1 marker=0/1/[value]
  marker-1page=0/1 marker+1page=0/1 lock=0/1
```

Marker is probed at `alias+0x800-0x1000`, `alias+0x800`, `alias+0x800+0x1000`
so a one-page SKB data offset error is visible. With `A536_ARW_DEBUG=1` each
gated read also prints `gate=... va=... errno=...`, separating "PTE gate
failed" from "page readable but payload wrong".

### Run q0diag1: panic was GhostLock residue, not a payload verdict (2026-08-07)

Launched `chain-ks-auto` with `A536_KS_SKB_PAYLOAD=1 A536_ARW_DEBUG=1`
(payload check enabled, no skip) ~95s after boot. The KS probe and group
drain progressed normally. ~3s after the selinux/GhostLock trigger the phone
panicked in a random system process, before/around the q0 check:

```
ActivityManager do_exit -> process_notifier -> rt_mutex_trylock
  -> try_to_take_rt_mutex+0xc4  fault at ffffffc03166bc98
Kernel panic - not syncing: Oops: Fatal exception
```

Artifact: `artifacts/android/20260807-q0-gate/panic-1039.lst`. This is the
known rt_mutex residue from the trigger, hitting an active PI-futex user
during early-boot churn (trigger fired at ~176s, system still busy). It is
NOT evidence about the payload page.

The chain log did not survive the panic: `/data/local/tmp` is f2fs on /data,
and the unclean shutdown rolled the f2fs checkpoint back past the freshly
written log and binaries. Old files from stable checkpoints survived. Next
run procedure: wait >= 5 min after boot before the trigger, and run `sync`
while polling so a panic cannot roll back the log.

### GhostLock residue theory: cleanup exit built, not yet proven live (2026-08-07)

The 10:50 panic was the old selinux trigger (`qroutehold2` spins forever
after `consume done`), and it hit a kworker ~25s after the trigger. A
`qroutehold2-clean` build (poc.c selinux mode now `_exit(0)` after
`consume done` instead of `spin_forever`, built 16024 bytes) exists but was
NOT yet exercised: the `chain-cleanup1` run never reached the selinux stage
(stuck before/at the drain), and the 10:50 panic in that boot came from the
earlier q0diag2 trigger residue. The earlier "stayed up" observation was
misread - the cleanup trigger never ran.

The transport blocker is unchanged: the reclaimed page cannot be read.
`check_q0_page` on a reclaimed base printed `gate=-1` for every VA (ERANGE
from the PTE walk, EFAULT for `base+0x100`), so the configfs string read
cannot prove the SKB payload/fops table. Next test uses the write side as
the oracle: with `A536_Q0_SKIP_PAYLOAD_CHECK=1`, `pwrite` on the ashmem fd
either goes through the forged configfs fops (returns length) or returns
EINVAL from the real ashmem fops. That verdict does not need the page to be
readable.

### The "residue" is the trigger's own PI-mutex state, not a leftover waiter (2026-08-07)

Panic traces are consistent across all runs and prove the crash is the
trigger's own success, not a stale process:

```
WifiRssiBasePol do_exit -> process_notifier -> rt_mutex_trylock
  -> try_to_take_rt_mutex+0xc4  fault at ffffffc0330dbc98 (unmapped)
```

Same pattern in ActivityManager (1039), kworker (105037), WifiRssiBasePol
(1104). `process_notifier` runs `rt_mutex_trylock` on every do_exit, so ANY
system process that exits (or wakes the lockscreen, per display_state logs
immediately before 1104) touches the corrupted PI-futex and panics. The
lockscreen wake is a plausible detonator, not the cause.

The trigger (`FUTEX_CMP_REQUEUE_PI` with a target that the q0 chain later
zeroes) leaves a real rt_mutex/PI-state machine with a dangling owner/waiter
chain in the target futex. Making the trigger process exit cleanly
(`qroutehold2-clean`, `_exit(0)` after `consume done`) did NOT prevent it -
`chain-cleanup2` still panicked ~80s later. So the fix is not "unwind the
trigger"; the corrupted PI state must be repaired with ARW while the bridge
is still alive, or the trigger must avoid corrupting the shared state in the
first place (e.g. restore the target lock/owner fields with ARW immediately
after the q0 write, before any other process can touch the futex).

Next candidate: after the q0 write, use the still-valid fops/ARW to
restore the original futex lock word / PI owner fields, then verify with a
short `do_exit` of a sacrificial process that no panic follows. That also
validates whether ARW can repair this class of state at all.

### Correction: the panic is a chain-failure side effect, not trigger poison (2026-08-07)

Old full runs with the SAME selinux trigger completed root cleanly and did
not panic:

```
chain-clean.log:      selinux consume done; arw slots=ok; ROOT_OK
chain-inspect-rb8.log: same; ROOT_OK
oracle-chain-boot2.log: same; ROOT_OK
```

So the trigger itself does not poison the kernel when the chain completes.
The panic appears only when the chain stops early (our q0 payload read
fails with gate=-1 and the bridge holds), leaving the PI/futex state
unwound. Root cause of the current block is therefore still the read-only
transport: the reclaimed page cannot be read, so the chain never finishes.

Next step is to stop treating the payload read as a gate and let the chain
proceed to ROOT_OK exactly like the old perf runs: launch with
`A536_Q0_SKIP_PAYLOAD_CHECK=1` (already supported, debug-only) so q0 write
and the root path run. If ROOT_OK is reached, the panic class disappears
with it, matching the old runs.

### Verdict: SKB payload does not land on the reclaimed page (2026-08-07)

`chain-skip1` (`A536_Q0_SKIP_PAYLOAD_CHECK=1`, `qroutehold2-clean`):

```
selinux: consume done; exit clean
Q0_PAGE_CHECK_SKIPPED alias=0xffffff89328e0000
ARW_FAIL q0 lock clear errno=22 EINVAL
```

The q0 write (`pwrite` on the ashmem fd after the q0 trigger) returns EINVAL,
which on this kernel means the write went to the real ashmem fops - the
forged configfs fops table is NOT on the reclaimed page. Combined with the
read side (`gate=-1` on every VA of the reclaimed base), this closes the
loop:

- the page IS reclaimed and held (SKB_RECLAIM_DONE / FREE_OK print the base);
- the SKB payload/fops table is NOT at `base+0x100` (EINVAL on write, and
  reads cannot be used to prove otherwise);
- the q0 chain cannot go further without the forged table.

Also confirmed live: `qroutehold2-clean` (trigger exits after `consume
done`) removes the delayed rt_mutex panic - the phone stayed up past the
old ~25-80s crash window after the selinux trigger. The trigger cleanup is
real, but the remaining blocker is payload placement.

Next: debug why `fill_skb_fops` content is not at `base+0x100`. Candidates:
SKB data offset differs from `SKB_DATA_DELTA=-0xe80` on this kernel
(payload starts at another page offset), or the reclaimed page is not the
one that received the SKB data (two pages / wrong skb). Use perf calibration
only as an oracle to confirm which page the SKB actually fills before
removing it again.

### SKB geometry fix tried; EINVAL persists - content oracle still missing (2026-08-07)

Source check of `net/unix/af_unix.c` + `net/core/skbuff.c`:
`sock_alloc_send_pskb` -> `alloc_skb_with_frags` -> `alloc_skb` ->
`__alloc_skb` sets `skb->data = skb->head = kmalloc buffer start` with NO
`skb_reserve(NET_SKB_PAD)` (unlike `__netdev_alloc_skb`). So the earlier
`SKB_DATA_DELTA=-0xe80` / `payload=base-0xe80` assumption was wrong: data
starts at the buffer base. Fixed `page-leak-probe.c`:

- `fill_skb_fops` now writes at blob offset `0x100` (was `0xe80+0x100`);
- marker at `0x800`, usercopy lock/value zeroing at `0x900/0xa00` without
  the `+0xe80` shift;
- `payload = base` everywhere (was `base - 0xe80`).

Live `chain-fix1` (probe 66632, `A536_Q0_SKIP_PAYLOAD_CHECK=1`,
`qroutehold2-clean`): still `ARW_FAIL q0 lock clear errno=22 EINVAL`, i.e.
the write still hit the real ashmem fops. So the payload/fops table is still
not at `base+0x100`, or `base` is not the page the SKB filled. The offset
fix alone is not enough.

Confirmed again: `qroutehold2-clean` prevents the delayed rt_mutex panic -
the phone stayed up >2min after the selinux trigger on this boot.

The missing piece is a content oracle: perf sees the page allocated
(`SKB_ACCEPT` in old calibrations) but never proves the payload bytes are on
that page. Reads through the ARW gate return `gate=-1` on reclaimed pages,
and the q0 pwrite returns EINVAL. Next: use the perf calibration branch
(`A536_KS_SKB_CALIBRATE=1`) to watch where SKB data lands, or add a
raw `skb->head` read via the bridge from a known-mapped page, then compare
with the reclaimed base.

### pwrite offset probe added; needs a fresh boot (2026-08-07)

Added to `clear_q0_lock` (debug-only, gated by
`A536_Q0_SKIP_PAYLOAD_CHECK=1`): pwrite probes at
`alias+{0x100,0x800,0xf00,0x1000+0x100,0xe80+0x100,0xe80+0x800,
0xf00+0x100,0x2000+0x100,0x3000+0x100}`. If the forged configfs fops table
landed at a different offset than `base+0x100`, one probe returns length
instead of EINVAL and reveals the true SKB data offset. No perf involved.

Current boot has already run one chain (`chain-fix1`); per the one-chain-per
boot rule (rt_mutex residue class, even with cleanup) a second chain must
not run on the same boot. `adb reboot` is denied for shell and there is no
root on this boot (kernelsu not loaded, `rmg-root` has no daemon). The
pwrite probe (`rb3-pwprobe`, 45480) is pushed and ready; it needs a fresh
boot before the next `chain-ks-auto` run.

### ROOT CAUSE of the delayed panics: we zero `uid_lock` and never restore it (2026-08-07)

The "delayed rt_mutex panic" is not a GhostLock trigger residue at all. It is
our own ARW proof step:

`prove_and_restore_fops` writes 32 zero bytes to `UID_LOCK_ALIAS + slide`,
reads them back to prove kernel write, then RESTORES selinux and fops but
NEVER restores `uid_lock`. Samsung's `drivers/misc/uid_sys_stats.c`
registers `process_notifier` on `PROFILE_TASK_EXIT` and calls
`rt_mutex_trylock(&uid_lock)` on every process exit. `UID_LOCK_ALIAS`
(0xffffff8002286e18) is exactly the physmap alias of that global
`uid_lock` (vmlinux: `ffffffc00a286e18 t uid_lock`, image offset
0x2286e18). After our write the rt_mutex is all-zeros; the next do_exit
walks the corrupted mutex and panics in `try_to_take_rt_mutex+0xc4` via
`process_notifier`. This explains every delayed crash (25s..>3min later,
in WifiRssiBasePol/ActivityManager/kworker) and why the power button
"triggers" a reboot: the button causes some process to exit.

Fixed in bridge.c: save the original 0x20 bytes of `uid_lock` before the
zero write and restore them immediately after the readback (same ARW
session, while the fops are still forged). The ARW proof now verifies
restore too (`uid_lock=%zd/%zd/%zd/%zd`: write/read/restore/readrestore).

Live evidence chain: panic 112746 happened at 440s uptime, during the KS
group phase of chain-pw1 (log stopped at attempt=80, before the selinux
trigger), with the same `process_notifier -> try_to_take_rt_mutex` trace -
consistent with a do_exit touching the zeroed `uid_lock` from the PREVIOUS
chain (chain-fix1) that had reached ARW.

### Root oracle via serve proves SKB does not reclaim the target page (2026-08-07)

The working shell perf path (`chain-auto` with the live spin `qroutehold2`)
reaches `ROOT_OK` and leaves a live `A536_SHADOW_DIR` serve process that can
read kernel pages directly. Verified: `uid=0`, serve responds to
`shadow-arw.ps1 read`.

Direct readback of a KS/SKB target page before and after the SKB send:

```
before send: base+0x000 = SLUB freelist ptr 0xffffff8930ee82d8
after  send: base+0x000 = same SLUB freelist (unchanged)
             base+0x100 = SLUB object ptrs
             base+0x800 = 0xffffff893b678888 (in-page freelist ptr, no marker)
```

The SKB marker `0x4135333652454144` is NOT on the page, and the page still
looks like a SLUB slab, not a buddy/SKB buffer. Combined with perf
`page_free_base=0` (no order-3 free on the candidate), this closes the
question: SKB reclaim is not taking the target page. The page never reaches
the buddy allocator (freed mm objects stay in the mm_struct SLUB cache), so
the SKB allocation picks a different page and the payload is never on
`base+0x100`.

Why the page stays in SLUB: freed mm slabs sit in per-CPU partial
(`cpu_partial=13` observed full, `partial` growing) and are not discarded
into buddy. The trigger-page/free ordering needs to overflow one CPU's
partial (all frees pinned to one core with > cpu_partial empty slabs) or the
target slab must be provably empty (all 34 objects freed AND not reused)
before SKB is allowed to run. The serve oracle can now validate the
"provably empty" condition directly instead of guessing.

### Confirmed with serve: page never reaches buddy, SKB takes another page (2026-08-07)

Repeated standalone KS+SKB probes with the live serve oracle (read target
page before/after SKB send, including a no-wait fast run):

```
before send: base+0x000 = SLUB freelist ptr / 0x301
after  send: base+0x000 = same SLUB freelist (unchanged)
             base+0x100 = SLUB object ptrs (0xd855d81d59...)
             base+0x800 = in-page freelist ptr 0xffffff8047d28808 (no marker)
```

Control reads prove serve is correct: uid_lock shows valid rt_mutex ptrs,
init_task shows kernel text ptrs, different addresses give different bytes.
The SKB marker `0x4135333652454144` never appears on the target page, with or
without the SKB wait gate. The freed mm slab stays in the SLUB cache
(per-CPU partial), never discarded to buddy, so the SKB order-3 allocation
always takes a different page. This is the root cause of `EINVAL` on q0
pwrite and `gate=-1` on reads: the payload is simply not on the page the
bridge believes it reclaimed.

Next experiment (root oracle available): after the probe frees all 34 target
objects, run `echo 1 > /sys/kernel/slab/mm_struct/shrink` as root, then SKB
send. If the page then reaches buddy and SKB takes it, the fix for the
rootless path is to overflow per-CPU partial on one core (pin all frees to
CPU0 + enough empty slabs), which is what the calibration mode already
tries. The serve oracle can verify the page is a buddy page (zeros +
first-touch data) before accepting.

### Discard mechanics from source + shrink test result (2026-08-07)

Source (this kernel's `mm/slub.c`):

- `unfreeze_partials` discards an empty frozen page only when
  `n->nr_partial >= s->min_partial` (5). Otherwise it is re-added to node
  partial.
- `unfreeze_partials` is called from `put_cpu_partial` when `drain &&
  pobjects > slub_cpu_partial(s)` (13 here) and from `__flush_cpu_slab`
  (sysfs shrink, cpu-dead). `__flush_cpu_slab` does `flush_slab(c->page)`
  then `unfreeze_partials(c)` - so sysfs shrink DOES reach per-CPU partial.
- `__kmem_cache_shrink` (sysfs shrink) then discards empty slabs from node
  partial.

Root-shrink test while a KS probe held a freed target slab:

```
before: slabs=11 partial=2 cpu_partial=13
after : slabs=9  partial=3 cpu_partial=13   (2 slabs discarded)
target page bytes: unchanged (still SLUB freelist/object data)
```

So shrink discards SOME empty slabs but not our target slab. Combined with
the freed-object reads, the conclusion is the target slab is not empty
(objects still in use / re-used by the system between group collection and
drain), OR it is frozen as `c->page` on a CPU and the flush raced. The
rootless fix must therefore either (a) guarantee all 34 target objects are
freed and not reused before SKB (shrink the window, pin collection+drain to
one CPU), or (b) overflow `pobjects > 13` on one CPU with empty slabs so
`unfreeze_partials` discards the target while it is provably empty.

### Oracle runbook written

`ORACLE-HOWTO.md` documents the exact end-to-end procedure that made
reclaimed-page reads work: perf path `chain-auto` + spin `qroutehold2` +
`A536_SHADOW_DIR=/data/local/tmp/clean-oracle`, `ROOT_OK`, then
`scripts/shadow-arw.ps1 read` (one request at a time; parallel requests
corrupt the request file and serve answers `ERR request`).

### Repro of the green SLUB run and the no-perf ordering gap (2026-08-07)

The green run (`/data/local/tmp/ks-cpu3-pool5.log`, 02:47) used the PRE-
`44f7768` probe: perf-addressable `flush_target_rotate` on CPU3 with
`POST_TRIGGER_PAGES=14 POST_TRIGGER_POOL=2000`, order
`free target 34 -> alloc 14 full trigger slabs -> free 1 obj each trigger ->
free rest + s2 -> target tail last`, and produced:

```
object_free_page_unique=34 object_free_page_slots=34
page_free_base=1 PAGE_CALIBRATION_PAGE_FREE_GATE_OK
PAGE_LEAK_SKB_RECLAIM_DONE base=<candidate>
```

That proves the 14-page/pobjects mechanism works on this kernel when the
trigger slabs are allocated AFTER the target frees and the target tail is
freed LAST (nr_partial >= 5 at that moment).

The current no-perf `drain_no_perf_group` does NOT reproduce that order: it
allocates the 14 trigger slabs BEFORE freeing the target (clone_memfd up
front), frees target 33, then frees trigger head+rest and s2, then target
tail. The trigger slabs are not allocated in the target's wake, so they do
not fill the per-CPU partial chain in the required order, and the target
tail free does not see `nr_partial >= 5` with the target in node partial.
Result: `page_free_base=0`, page stays in SLUB, SKB misses (confirmed by
serve readback: page still has SLUB freelist data, no SKB marker).

Next: rewrite `drain_no_perf_group` to allocate the 14 trigger slabs AFTER
the 34 target frees (via `leak_one_controlled_mm` grouping, no perf), then
free 1 obj per trigger, rest + s2, target tail last. The serve oracle can
verify the target page becomes a buddy page (zeros/first-touch) before SKB
is allowed.

### Fast no-perf trigger + serve readback usercopy crash (2026-08-07)

Rewrote `drain_no_perf_group` to mirror the green perf order without perf:
free 33 target refs -> allocate 14 trigger pages via `clone_memfd` + one s2
(fast, no KS) -> free each trigger page (one fd each) -> free s2 -> free
target tail last. Run `skb-fix4` reached:

```
GROUP_FULL base=0xffffff804fab0000
TARGET_FREED refs=33
TRIGGER_READY pages=14 refs=14 s2=17
TARGET_TAIL_FREE
SKB_WAIT
```

Before SKB, a serve readback of the target page crashed the device with
`usercopy_abort` (RCNT 169, `usercopy.c:99`). This is the known
configfs/string-read usercopy hazard, not a trigger failure: reading some
SLUB/reclaimed pages through the serve path trips the usercopy check and
reboots. Serve reads are safe for the pages already verified (uid_lock,
init_task, freed mm slabs) but NOT for arbitrary addresses; vmemmap-style
reads are off-limits.

The fast trigger reached SKB_WAIT quickly and without rt_mutex residue, so
the ordering itself is viable. The page-discard verification must use the
root slab sysfs oracle (slabs/partial counts + buddyinfo) instead of serve
readback, or a PTE-gated read that never touches the configfs string path.

### Confirmed: full 476-ref trigger discards the target to buddy (2026-08-07)

Restored the original `drain_no_perf_group` from `20a5aa6` (476 trigger
refs = 14 full slabs created up front, then free all 34 target refs, then
free 1 obj per trigger slab, then rest + s2). Live run `skb-fix5`:

```
GROUP_FULL base=0xffffff8819e88000
TRIGGER_READY pages=14 refs=476 s2=513
TRIGGER_DONE pages=14
SKB_WAIT
```

Serve readback of the target page at SKB_WAIT (after drain, before SKB):

```
base+0x000 = 0000000000000000   (was SLUB freelist before; now zeroed)
mapped=1 phys=0x899e88000
```

The page really reached the buddy allocator with the 476-ref trigger. The
earlier red runs used either 14 one-ref triggers (my over-simplification,
pobjects never > 13) or a broken free order. The green mechanism is:
14 full mm_struct slabs held, target frees all 34, then each trigger slab
is emptied (head slow free -> put_cpu_partial drain -> unfreeze), and the
empty target is discarded when `nr_partial >= min_partial`.

After SKB send, the target page was reused by the mm_struct cache again
(freelist data back at +0x000), and the SKB marker was not present. So the
remaining blocker is now purely payload placement: SKB takes a different
buddy page than the discarded target, or writes at different offsets. The
discard problem itself is solved.

### Geometry proven: fops table IS on the reclaimed page (2026-08-07)

Standalone probe with full green geometry (64KB send, 0xe80 offset,
tail-last drain, 476 trigger refs, 64 sends) on a fresh boot with a live
serve oracle:

```
GROUP_FULL base=0xffffff88d7f48000
SKB_SENT sends=64
SKB_RECLAIM_DONE base=0xffffff88d7f48000
serve read base+0x100:
  +0x08 = 0xffffffc0083809dc = ASHMEM_FOPS_08_IMAGE + 0x8000 (slide)
  +0x10 = 0xffffffc00844f488 = ASHMEM_FOPS_10_IMAGE + 0x8000
```

The SKB payload with the forged fops table is exactly at `base+0x100`. So
the discard -> SKB reclaim -> payload placement chain is fully proven
end-to-end (with the slide offset 0x8000 in this boot).

### EINVAL root cause: race between fops swap and ashmem open (2026-08-07)

In `run_chain_ks`, the q0 write trigger (which replaces
`ASHMEM_MISC_FOPS` with the forged table pointer) was spawned
asynchronously and `clear_q0_lock` opened `/dev/ashmem` immediately. If the
swap had not landed yet, the fd kept the original ashmem fops and the
later pwrite returned EINVAL (no write method on real ashmem fops).

Fixed: `run_chain_ks` now waits for the write trigger's
`consume done;` line before sending SIGUSR2. Live result changed from
EINVAL to `errno=19 ENODEV` on `/dev/ashmem` open, proving the swap now
happens. The new blocker is that the reclaimed page holding the table is
reused by the mm_struct cache before the open: the SKB does not pin the
page (or the first skb is not retained). Next: pin the reclaimed page
(hold the skb/socket and verify refcount), or shrink the window between
SKB send and /dev/ashmem open.

### Status 2026-08-07 evening (after many boots)

Proven live end-to-end:

1. Discard to buddy: 476 trigger refs + tail-last free -> serve reads
   `base+0x000 == 0` (buddy page).
2. SKB payload placement: 64KB send with 0xe80 head offset -> serve reads
   exact `ASHMEM_FOPS_*_IMAGE + slide` at `base+0x100`.
3. fops swap now synchronizes: `run_chain_ks` waits for the q0 write
   trigger's `consume done` before opening `/dev/ashmem`; error moved from
   EINVAL (swap not landed) to ENODEV on open.

Remaining blocker: the reclaimed page is not retained until `/dev/ashmem`
open; by then it is re-used (serve has seen SLUB freelist and even
log-like ASCII at `base`). Also note the serve oracle itself degrades
after heavy use (control reads start returning 0xff), so treat late
readbacks as suspect; restart the chain for a fresh oracle.

Next experiment candidates:
- Fewer sends (16) with the socket held open and verify the table with a
  fresh serve immediately after SKB.
- Hold the reclaimed page: after SKB, verify `skb_shinfo(skb)->nr_frags`
  and page refcount via root, or keep the receiving socket open and read
  the queue so the first skb is never freed.
- Move the `/dev/ashmem` open into the probe right after SKB (same
  process, same hold window) instead of the bridge after the selinux
  trigger, so the table is still live.

### Audit fixes applied + page retention proven (2026-08-07)

External audit found two real bugs in the bridge chain:

1. SIGUSR1/SIGUSR2 race: `poc.c` sends SIGUSR1 (repair) BEFORE printing
   `consume done`, so the bridge's `while (!fops_repaired)` loop can exit
   before `clear_q0_lock` runs, skipping `Q0_LOCK_CLEAR_OK` and hanging the
   bridge. Fixed: q0 write trigger now honors `A53_NO_REPAIR_SIGNAL=1`
   (set by bridge for the KS path), and the bridge sends SIGUSR1 itself
   AFTER `Q0_LOCK_CLEAR_OK`.
2. Double-close of `write_fd` in `A536_ORACLE_DETACH` after `fclose`:
   fixed by setting `write_fd = -1` and guarding `close`.
3. Dead `relay_pid` removed.

Retention test (fresh boot, serve oracle, sends=64, slide=0x100000):

```
base+0x100 after SKB: 0000100000000000 dc894708c0ffffff 88745408c0ffffff ...
  = ASHMEM_FOPS_08/10_IMAGE + 0x100000, table present
same read 3s later: identical (page retained)
```

So the reclaimed page with the forged fops table is stable; the ENODEV in
the chain is NOT page reuse. The chain still fails at `/dev/ashmem` open
with `errno=19` after the q0 write trigger, and the GhostLock residue
panics the boot later (`try_to_take_rt_mutex`, RCNT dump). Next diagnostic:
after the q0 write trigger, read `ASHMEM_MISC_FOPS_ALIAS` via serve to
confirm the misc fops pointer was actually replaced before blaming open.

### Signal-order audit closed; ENODEV root cause narrowed (2026-08-07)

Audit + fix (`587be2c` + `3fca141`):

- `run_chain_ks` spawned the q0 write trigger without
  `A53_NO_REPAIR_SIGNAL=1`, so the early SIGUSR1 race stayed in the KS
  path. Now both `run_chain` and `run_chain_ks` pass the env, and the KS
  path sends SIGUSR1 itself only after `Q0_LOCK_CLEAR_OK`.
- `poc.c` (clean copy) honors the env too; committed with the bridge.
- Dead `relay_pid` removed; `write_fd` double-close fixed.

Regression caught by code reading: `run_chain` (perf path) spawns the
write trigger WITH the env but does not send SIGUSR1 itself and does not
wait for `consume done`. With the env the trigger no longer sends SIGUSR1,
so the perf fops process stays in `while (!fops_repaired) pause()` forever.
Reverted `run_chain` to plain `spawn_capture` (no env) so the perf path
keeps its proven behavior; only `run_chain_ks` uses env + bridge SIGUSR1.

Live KS run after the fix (`chain-v5`): q0 prints `repair signal skipped`
(env works), `consume done`, then `ARW_FAIL open q0 lock clear errno=19
ENODEV`. The write trigger wrote the correct misc fops pointer
(`target=ASHMEM_MISC_FOPS_ALIAS+slide`, `value=base+0x100`), and the
reclaimed page with the table is stable (serve-verified), yet
`/dev/ashmem` open returns ENODEV.

ENODEV analysis: `misc_open` walks `misc_list` by minor and calls
`fops_get(c->fops)`. If the pselect write primitive corrupted
`misc_list`/the misc entry (it writes through a stale waiter), open fails
ENODEV before looking at the table. Next: after the q0 write trigger, read
the misc entry's fops pointer via serve and compare with the perf path on
the same boot.

### Perf vs KS: table verified, ENODEV is KS-path-specific (2026-08-07)

On a fresh boot with a live serve oracle (chain-auto, perf path):

```
prefetch slide=0xc0000
ROOT_OK chain ready slide=0xc0000 fops_pid=3902
serve read 0xffffff8001ffbc20 (misc fops alias, no slide): 0xffffffc009ffbb88
serve read 0xffffff80020bbc20 (alias+slide): 0xffffffc009bc6f18
  = ASHMEM_FOPS_IMAGE + 0xc0000  (restored correctly)
serve read fops page base+0x100: table with ASHMEM_FOPS_08/10 + slide
```

So in the perf path the misc fops restore is correct and the forged table
is intact on the bridge's user page. The KS path fails with ENODEV at
`/dev/ashmem` open even though the reclaimed page with the forged table is
stable in standalone runs. The difference: perf path table lives on a
mlock'ed user page; KS path table lives on the reclaimed (SKB) page. The
KS path's later selinux/q0 GhostLock triggers fork new processes, whose
mm_struct allocations may reuse the reclaimed page if the SKB did not pin
it (refcount not held across the trigger phase). If the page is re-used,
`misc_open` sees garbage fops -> ENODEV.

Next experiment: in the KS path, keep the reclaimed page pinned (hold the
SKB socket open / take a page ref via root oracle) across the selinux+q0
trigger phase, then open /dev/ashmem. Alternatively run the selinux and q0
triggers BEFORE the SKB reclaim so their mm frees cannot touch the target
page, then do SKB -> open immediately.

### SKB_ACCEPT is a false positive; page is mm-reused, not SKB data (2026-08-07)

With a live serve oracle on one boot (slide=0xc0000), after a perf
calibration run that reported `SKB_ACCEPT alloc_confirmed=1`:

```
candidate=0xffffff8931f48000 page_order3_base=1 page_free_base=1
SKB_SENT sends=64 -> SKB_ACCEPT -> SKB_RECLAIM_DONE
serve read base+0x100   = 0 (no fops table)
serve read base+0xe80   = 0
serve read base+0x800   = 0xffffff8931f48808 (SLUB in-page freelist ptr)
```

The page is a reused SLUB mm_struct slab, not an SKB buffer. The perf
`page_order3_base=1` matched ANY order-3 allocation on that base during the
window - including the mm_struct allocation that reused the freed page -
not specifically the SKB. `perf_candidate_alloc_match` cannot distinguish
SKB from mm reuse, so `SKB_ACCEPT` was a false positive all along.

That explains the inconsistent serve reads: when the page happened to stay
as the SKB buffer the table was there (skb-s6); when mm reused it first
the table vanished (skb-pin, skb-accept). It also explains ENODEV in the
KS chain: by the time /dev/ashmem opens, the reclaimed page is usually a
new mm_struct slab.

Next: make the SKB allocation deterministic on the target page. Options:
pin the freed page in buddy right before send (buddy PCP order), or use a
socket send path that allocates order-3 from the same CPU/buddy list, or
verify the page is SKB-owned via `skb_shinfo(skb)->nr_frags`/page refcount
before trusting SKB_ACCEPT. The serve oracle can read the skb page only
after we know it is not reused; use root slab sysfs + page refcount for the
identity check.

### Serve reads image VAs directly; slide confirmed; ENODEV still open (2026-08-07)

Important correction: kernel-image symbols must be read through their
kernel VAs (`0xffffffc0... + slide`), NOT through physmap aliases. The
physmap alias formula `PAGE_OFFSET + (image_va - KIMAGE_VBASE)` is wrong for
the image (the image lives in a different mapping; `0xffffff8009b7ef18`
mapped to phys `0x89b7ef18`, i.e. high RAM, not the image).

Live reads with slide=0x78000:

```
0xffffffc009b7ef18 (ashmem_fops + slide):
  +0x00 owner = 0
  +0x08 llseek = 0xffffffc008caf788 = ashmem_llseek + 0x78000
  +0x10 read = 0 (real ashmem has read_iter, not read)
  +0x18 write = 0
  +0x20 read_iter = 0xffffffc008caf82c = ashmem_read_iter + 0x78000
  +0x50 ioctl = 0xffffffc008caf8e8 = ashmem_ioctl + 0x78000
  +0x58 compat = ...cb023c, +0x60 mmap = ...cb0294,
  +0x70 open = ...cb04c4 = ashmem_open + 0x78000
```

This matches our forged table layout (configfs read/write at 0x10/0x18,
ashmem ioctl/open/release at 0x50/0x58/0x60/0x70/0x80). The slide used by
the bridge is correct. The misc structure read (`0xffffffc00a06bc10`)
returned repeating `e2040000 0a000000` which is not a valid miscdevice
name/list - either the misc symbol address is wrong or the read hits a
different object; this needs a KS-boot read of misc->fops right after the
q0 write trigger to close the ENODEV question.

### ENODEV clue: forged table owner slot gets clobbered (2026-08-07)

After a manual `write` trigger (misc fops <- forged table base+0x100), the
forged table's owner slot changed from 0 to `0xffffff80020bbc18` (a misc
alias-ish pointer), and `/dev/ashmem` open returned ENODEV. The pselect
write primitive is writing through the target page and clobbering the
table's first qword (owner must be 0 for `fops_get`/module refcount).

Confirmed readback of `base+0x100` after the manual write:
`18bc0b0280ffffff dc894308c0ffffff ...` (owner no longer zero).

The bridge's own write trigger uses the same primitive, so in the KS path
the forged table can be corrupted before `/dev/ashmem` open -> ENODEV.
Next: keep the forged table's owner slot zero after the write trigger
(verify via serve on the same boot, or make the write primitive target a
copy of the table that does not share the page with the owner slot).

### Owner-clobber was a bad-slide artifact; manual write panics the boot (2026-08-07)

The owner-slot clobber seen earlier was caused by my manual `write`
invocation using the WRONG slide (0xc0000 from a previous boot on a boot
whose slide was 0x78000). The write landed at the wrong alias and
corrupted the table. With the correct slide, the manual write trigger
itself crashed/rebooted the device (GhostLock residue on a dirty boot) -
the panic dump was not even written (watchdog reboot).

So the ENODEV question is still open; the bridge's own write trigger uses
the correct slide and correct target, but the KS chain still gets ENODEV.
The remaining untested hypothesis: the write trigger's stale-waiter
mechanism writes through the reclaimed page and can clobber the forged
table even with a correct slide (the table lives on the same page the
primitive touches). Perf path avoids this because its table is on a
mlock'ed user page. Next clean test: KS probe -> SKB -> verify table via
serve -> write trigger -> verify table again via serve (same boot, serve
enabled in KS path) -> then open.

### Exact KS close panic: uninitialised fake-fops flush slot (2026-08-07)

Fresh no-tracefs/no-perf run on boot
`9929cf0a-87cb-4565-acaf-8e9d8a2b677f` reached all discovery and reclaim
gates:

```
prefetch slide=0x70000
PAGE_LEAK_GROUP_REJECT group=0 exact=33 expected=34
PAGE_LEAK_GROUP_ACCEPT group=1 exact=34 expected=34
PAGE_LEAK_FREE_OK base=0xffffff89342c8000
SKB_RECLAIM_DONE base=0xffffff89342c8000
FREE_OK
Q0_PAGE_CHECK ... fops=1 marker=1
Q0_PAGE_OK
```

The device then panicked. Rooting the next boot with the proven clean
perf path let us pull Samsung last-kmsg to
`artifacts/crash/ks-lock-clear-lastkmsg.log.gz` (SHA-256
`35c3717cf0660d92043fd100d6368e09aec6dba530ac0acc437fbf26b3d880f4`).
The exact fault was:

```
PID 4042 Comm rb3-owner0
PC 0x50505050505050
LR filp_close+0x40/0xa4
x8=5050505050505050
__close_fd -> filp_close -> 0x50505050505050
```

Exact `vmlinux.elf` disassembly closes the diagnosis:
`filp_close+0x2c` loads `file->f_op`, then `filp_close+0x2c` loads
`[f_op + 0x78]`, the `file_operations.flush` slot, and calls it at +0x3c.
The SKB blob starts as byte `0x50`; `fill_skb_fops` filled selected slots
but did not zero the rest of the table. Therefore fake `fops+0x78` was
`0x5050505050505050`. The perf path did not show the bug because its
anonymous mmap page started zeroed.

Required fix before another chain: zero the complete fake-fops region in
both 32-KiB chunks before filling known slots, and make both user and
kernel fops validators require the unused `flush` slot (and preferably all
unused slots in the table) to be zero. This panic is not evidence that
the KS address or SKB reclaim was wrong; those gates were green.

### Owner-zero A/B test (2026-08-07)

The next fresh no-tracefs/no-perf run on boot
`54e8d36e-62f4-4f6c-8c80-e35f99b9fb7c`, slide `0x48000`, tested removal
of the extra owner-zero q0 write while keeping the full-table zero fix.
Discovery and reclaim repeated successfully:

```
PAGE_LEAK_NO_PERF_GROUP_FULL group=1 base=0xffffff891df40000
PAGE_LEAK_NO_PERF_TRIGGER_READY pages=14 refs=476 s2=513 cpu=0
PAGE_LEAK_SKB_RECLAIM_DONE base=0xffffff891df40000
PAGE_LEAK_FREE_OK
```

After the SELinux and misc-fops q0 writes, `/dev/ashmem` failed with
`ENODEV` before ARW. The previous run with the owner-zero write reached
`Q0_PAGE_OK`, so the owner write is empirically required before
`misc_open` calls `fops_get()`. It is restored with its separate zeroed
fake lock at `base+0x3000`. The unsafe q0-lock memory clearing remains
removed; after owner-zero the bridge signals the fops holder directly and
enters the same ARW flow as the proven perf path.

### Prefetch control bug and wrong-slide proof (2026-08-07)

On boot `9eae293f-27f7-42f7-ad39-78b06057f0f4` the no-tracefs path returned
prefetch slide `0x1a00000`; same-boot tracefs debug ground truth was
`0x1d0000`. The wrong slide explains the later `EACCES`: the SELinux and
misc-fops q0 writes went to wrong addresses.

Code audit found a direct bug in the prefetch controls. The probe assigned
both `mapped_address` and `unmapped_address` to one anonymous page, unmapped
that page, and only then measured both. Thus both controls were the same
unmapped VA. Live samples confirmed it (`mapped=112 unmapped=111`,
`423/423`, `223/223`) and produced unrelated edges from `0x348000` through
`0x1a08000`.

The control is changed to use the probe's own executable function as the
mapped address and a freshly unmapped anonymous page as the unmapped
address. An attempt now fails unless unmapped timing is both at least eight
ticks and 50 percent slower. The threshold is the midpoint between the two
live controls. Edge search also requires a full high run immediately before
the low run; if a prospective edge gets two low samples and then returns
high, the attempt fails instead of accepting a later mapped-image island.
Consensus and bridge retries can retry a noisy measurement, but a dubious
attempt cannot supply an address to q0.

### Prefetch/tracefs calibration gate (2026-08-07)

Prefetch is probabilistic and must not be judged from one miss. During work on
the later KernelSnitch/SKB/q0 stages, `find_slide_auto` now always measures the
prefetch candidate first and then reads the same-boot tracefs truth. It prints
one machine-readable line:

```
SLIDE_CALIBRATION prefetch=0x... tracefs=0x... result=match|miss
```

On a miss, the dangerous stages receive the tracefs value. If tracefs cannot
provide a truth value, calibration aborts instead of using an unverified
candidate. This behavior is now enabled only by
`A536_SLIDE_CALIBRATE_TRACEFS=1`; normal execution uses a successful prefetch
consensus directly.

`cve-2026-43499-bridge slide-auto Q0` runs only this calibration and exits. It
does not execute GhostLock, KernelSnitch reclaim, or q0 writes, so repeated
same-boot measurements are safe.

Fresh boot `34fffa3a-f433-42e1-8d10-446919c4bf79` gave tracefs truth
`0x1f8000`. Six consecutive calibration runs all returned prefetch
`0x1a00000`, so this boot was `0/6` and the new gate correctly selected
`0x1f8000` every time. This is evidence of a stable false edge on this boot,
not proof that the probabilistic channel never works on other boots. Continue
recording match/miss across boots while later exploit stages use the verified
slide.

### Prefetch false edge was CPU-type dependent (2026-08-07)

The timing primitive itself was checked with two known kernel linear-map
controls. A mapped address measured 14--15 ticks, while an address in the
known direct-map hole measured 144 ticks. Both instruction and data prefetch
separated the controls. The failure was therefore not a dead prefetch channel
or a userspace/kernel-address artefact.

On boot `2a930c5d-ba80-40a9-a209-bb651100dbbf`, same-boot tracefs truth was
`0x1d8000`. The exact per-CPU matrix found the cause:

```
CPU0: 3/3 exact 0x1d8000
CPU1: 3/3 exact 0x1d8000
CPU2: 3/3 exact 0x1d8000
CPU3: 3/3 exact 0x1d8000
CPU4: 3/3 exact 0x1d8000
CPU5: 3/3 exact 0x1d8000
CPU6: stable false late edges near 0x1a00000/0x1c00000
CPU7: stable false late edges near 0x1bf8000/0x1c00000
```

The long CPU-heavy scan was free to migrate or be promoted to the two big
cores, where its timing distribution and accepted edge differ. This explains
why earlier unpinned runs sometimes found the exact slide and sometimes
returned a stable late false edge on the same boot.

The whole prefetch consensus is now pinned to CPU0 before any control or image
measurement. `A53_PREFETCH_CPU` remains only as an explicit diagnostic
override. After this cutover, six consecutive bridge calibrations on the same
boot all printed:

```
SLIDE_CALIBRATION prefetch=0x1d8000 tracefs=0x1d8000 result=match
```

No GhostLock or reclaim stage ran during these tests. The cross-boot checks
and final cutover are recorded below.

One old deployed oracle binary from boot
`9e175066-f66c-4d39-85d7-396576d509d5` predated the exact `init_mm` image
address fix. A later PTE-gate query through that stale process rebooted the
device. Do not reuse a resident oracle across a boot or binary update; check
the boot ID and deployed SHA-256 first. The current source uses
`INIT_MM_IMAGE + slide`, where the image address is the value verified from
the exact `vmlinux.elf`.

### Tracefs/perf-free full root after CPU pin (2026-08-07)

Cross-boot calibration of the CPU0-pinned prefetch path passed on three
different boots and three different slides:

```
boot 2a930c5d-ba80-40a9-a209-bb651100dbbf: 0x1d8000, 6/6 match
boot 55105897-db0e-4b3b-91cd-fa99ece8a4b2: 0x158000, 3/3 match
boot 45920d1c-7b3f-4b01-931e-5c2633343513: 0xb8000, 3/3 match
```

An explicit no-tracefs slide-only run on the third boot returned the same
`0xb8000`. The full chain was then run once on that boot with no tracefs and no
perf. Deployed SHA-256 values were checked before launch:

```
q0     4ac60d2f1a8dd3624496d4f200cc09a2c57cf4ffe323de2d615726398ba56d7a
bridge 83297cdd94ecf926a691bd340d8b3104fe19338dc4b7bf891735f3c02934e283
probe  087bcf61de62e78679b080cc581f19e96d879a9a2a147c9888709af4eead12af
root   1aa1a77d7c15e7b5de9ac77374e272b589cd2b117b8459b8c160c92bd9bea228
```

The live path completed every required gate:

```
SLIDE_ROOTLESS prefetch=0xb8000
PAGE_LEAK_NO_PERF_GROUP_FULL group=1 base=0xffffff89279e8000
PAGE_LEAK_NO_PERF_TRIGGER_READY pages=14 refs=476 s2=513 cpu=0
PAGE_LEAK_SKB_RECLAIM_DONE base=0xffffff89279e8000
PAGE_LEAK_FREE_OK
ARW_OK
PATCH_OK usersize=0x279e8a00
ROOT_OK
```

`/data/local/tmp/rmg-root -c id` returned
`uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0` on the same boot.
This proves the clean chain can start with no external slide, find its page
without perf, reclaim it, build ARW, and start the root service. Normal
`find_slide_auto` now uses this rootless path by default. Tracefs comparison
remains an explicit calibration mode only.

The default cutover was then rebuilt and tested on fresh boot
`f036be60-2613-4f1f-a3e0-9c6f9d7252e0`. No slide-related environment variable
was supplied. The bridge found `0xf8000`, passed the same no-perf reclaim gates,
and reached `ARW_OK`, `PATCH_OK`, and `ROOT_OK`. The deployed bridge SHA-256 was
`58cf8b7a72f3756cf0f49b3b2ef55cf3e5ca690dfac28af8168d7577cf689ec4`.
`rmg-root -c id` again returned uid/gid 0 in `u:r:kernel:s0`.

### Windows PowerShell quoting fix (2026-08-07)

`collect-target.ps1` and `read-kernel-log.ps1` no longer put nested quoted root
commands inside one `adb shell` string. Each script writes one LF-only Android
shell script, pushes it, and invokes the root helper as `rmg-root script-path`;
this becomes `sh script-path` inside the helper. Using `-c script-path` was also
wrong on this Samsung build: it tried to execute the shell-data file directly
and was killed with status 137.

Both scripts were run end to end with Windows PowerShell 5.1 on the live clean
root. `collect-target.ps1` finished in 2.5 seconds and pulled a 14,315,200-byte
`kallsyms.txt`, the 50,721-byte config, and event IDs 260/253.
`read-kernel-log.ps1` finished in 1.2 seconds and wrote all five expected
sections. Both removed their remote helper files after success.

### APK parity audit and live reclaim recheck (2026-08-07)

The first normal-app run used the right A536 sources and runtime flags, but its
build was not byte-for-byte equivalent to the proven clean build. The payload
used API 35, `-Oz`, shared/PIC linkage, and a separately built root helper. The
A536 payload build now uses API 31 and `-O2`; its root helper is byte-identical
to clean. Shared-library dispatch remains the one intentional APK-only
difference.

The app run found the exact prefetch slide and a full 34-object KS group, then
panicked in the first q0 operation with a userspace-looking rt_mutex owner at
the predicted fake-lock page. This is consistent with an old `mm_struct` page,
not a proven SKB payload. The no-perf probe printed `SKB_RECLAIM_DONE` without a
pre-q0 identity gate, so that marker alone was never proof of reclaim.

Live standalone calibration on an already rooted boot now gives these exact
facts without running q0:

- 24 blind trigger batches produced 17 pages with all 34 controlled
  allocations and all 34 matching `__mmdrop` frees.
- The chosen KS target produced 34 unique object frees and an exact order-3
  `mm_page_free` event. KS selection and SLUB-to-buddy drain are therefore
  proven on this path.
- A failed KS helper returned integer `0`; the collector confused that status
  with fd 0 and later double-closed it. Soft misses now use `-2`, invalid direct
  map addresses are rejected, and only real fds enter groups.
- Blind trigger frees now use the proven order: one head from every batch,
  then all remaining objects. A 14-batch run still freed the target exactly.
- One socket accepted only 32 complete 64-KiB sends with the old 1-MiB
  `SO_SNDBUF`. Perf saw 39 order-3 allocations but none at the target PFN.
  Thus the current blocker is after buddy free: make SKB take the exact page,
  likely by handling buddy merge/order and increasing controlled SKB pressure.

Calibration logs are under
`artifacts/android/20260807-app-reclaim-audit/`. Perf and the live root service
are ground truth only; the final APK path still must use neither.

### KS reclaim succeeded; cross-page fake locks caused q0 panic (2026-08-07)

The final APK and a direct clean `chain-ks` run both completed rootless slide
discovery, the 34-object group, the 14-page/476-reference SLUB drain, and 256
SKB sends. Both then panicked in the first SELinux q0 write. The second run used
a same-boot tracefs-verified slide, so this excluded a bad prefetch result.

The Samsung last-kmsg gives the exact failure:

```
Unable to handle kernel paging request at 0x00000064bce89820
PC: rt_mutex_adjust_prio_chain+0x168/0x8c8
process: rmg-write
x3/x24/x27: 0xffffff8004ac2000
stack: rt_mutex_adjust_pi -> __sched_setscheduler -> sched_setattr
```

`0xffffff8004ac2000` is the selected KS base plus the old
`KS_SELINUX_LOCK_OFF=0x2000`. The dump of that page contains userspace
pointers and auxv-like data, including `0x00000064bce897e8`, rather than the
zeroed fake rt_mutex. The crash dereferenced that value at `+0x38`.

This proves the bad assumption: after the empty order-3 `mm_struct` slab is
discarded, buddy may split it. An SKB allocation can reclaim the first 4-KiB
page containing the fake fops table without owning `base+0x2000` or
`base+0x3000`. `PAGE_LEAK_SKB_RECLAIM_DONE` therefore proves the target base,
not ownership of every page in the old 32-KiB compound block.

All data needed by q0 now stays in the controlled first 4-KiB page:

```
fops table     base+0x100
marker         base+0x800
usercopy lock  base+0x900
usercopy value base+0xa00
SELinux lock   base+0xb00
owner lock     base+0xc00
```

The clean and payload copies were changed together. New build hashes:

```
clean bridge d8c1e192de8babaf8b9da02f3249d01f9cf3c8227fd19a8f11047237ee2c0282
clean probe  732afde057a3b5da8a79fb79f1ed78a19127e07578c4270f57676eaea7875764
app payload  e1ee51aa910e1ff609441b7824040b7123a6b977245829a2a98b4eab5db4d488
```

One more operational fact was confirmed: a panic can roll back recent,
unsynced F2FS writes in `/data/local/tmp`, making old binaries reappear after
boot. Use unique remote names, run `sync`, and verify SHA-256 immediately
before every dangerous launch.

### APK root and KernelSU pass with same-page locks (2026-08-07)

The rebuilt local APK was installed on a fresh boot after roughly one minute.
The installed `base.apk` and host APK had the same SHA-256:

```
d6627ddd68e3728a845ecdfc1bf287469b012a59d8229e2be24b68f2638edcc1
```

The payload ran from the normal app domain:

```
uid=10313
u:r:untrusted_app:s0:c57,c257,c512,c768
SLIDE_ROOTLESS prefetch=0x1c8000
PAGE_LEAK_NO_PERF_GROUP_FULL group=1 base=0xffffff88f3488000
PAGE_LEAK_NO_PERF_TRIGGER_READY pages=14 refs=476 s2=513 cpu=0
PAGE_LEAK_SKB_RECLAIM_DONE base=0xffffff88f3488000
PAGE_LEAK_FREE_OK
```

The relocated same-page locks then passed every dangerous stage:

```
selinux lock=0xffffff88f3488b00
fops owner lock=0xffffff88f3488c00
kernel_fops=1
ARW_OK
PATCH_OK
ROOT_OK
A536_APP_ROOT_PROOF uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

The embedded KernelSU module loaded on the same boot. The rebuilt `ksud`
force-stopped and restarted the Manager after late load, so the first visible
Manager state was `Working <LKM> [Jailbreak mode]`, version `32525-2`; no stale
`Not installed` screen remained. The final APK contained these exact assets:

```
payload e1ee51aa910e1ff609441b7824040b7123a6b977245829a2a98b4eab5db4d488
ksud    918105e103dcc3072d8fc64de61834255d76efd26e564187b786f4f366b2a942
helper  1aa1a77d7c15e7b5de9ac77374e272b589cd2b117b8459b8c160c92bd9bea228
```

The full exploit log and Manager UI dump are saved in the local app test
artifacts. The final runtime path uses neither tracefs nor perf.

### App force-stop exposed a stale forged fd (2026-08-07)

The first successful APK boot later panicked exactly when the app was
force-stopped for a screenshot. This was not a timer or an idle-system crash.
Samsung last-kmsg records the force-stop killing the exploit process, followed
immediately by:

```text
process: cve43499-run
PC: 0xfff4edeefff4edee
LR: filp_close+0x40/0xa4
put_files_struct -> exit_files -> do_exit
```

The process still owned the forged `/dev/ashmem` fd after `ROOT_OK`. The SKB
page backing its fake `file_operations` table was later released and reused;
closing the stale fd during process exit called the overwritten `release`
slot and panicked.

The fops child now closes its ARW fd immediately after root installation when
no `A536_SHADOW_DIR` serve oracle was requested, prints `ARW_FD_CLOSED`, and
exits. Both chain drivers require that marker after `ROOT_OK` before printing
`chain ready`. Oracle serve mode deliberately keeps the fd and preserves the
old `ROOT_OK` gate. A normal APK run therefore has no forged fd left for a
later app force-stop to close.

The first cleanup test exposed a second stale-state bug before `PATCH_OK`.
Last-kmsg showed the fops child jumping through a corrupted
`file_operations.unlocked_ioctl` slot while issuing `ASHMEM_SET_NAME`:

```text
process: cve43499-run
PC: 0x28783861e868f8
LR: __arm64_sys_ioctl+0x90/0xcc
```

The probe hold loop always watched the global file
`/data/local/tmp/clean-oracle/page-release`. A previous accepted calibration
left that file behind. The app could not see it while SELinux was enforcing,
but the access started succeeding as soon as q0 cleared SELinux; the probe
then released the SKB page while the ARW fd still used its fake fops table.

Normal runs no longer consult a global release file. The hold exits early only
when an explicit `PAGE_LEAK_RELEASE_PATH` is supplied; the calibration script
passes its own path. After a normal non-serve chain closes the forged ARW fd,
the fops child terminates and reaps the SKB page-holder process before printing
`ARW_FD_CLOSED`.

### Final APK confirmation and upstream payload PR (2026-08-07)

The cleanup fixes were synced into the app payload and retested after a clean
reboot. The exploit ran from `u:r:untrusted_app:s0`, used rootless prefetch and
KernelSnitch discovery (`no_perf=1`), reclaimed the page through SKB, reached
`ARW_OK`, `PATCH_OK`, and `ROOT_OK`, then printed `ARW_FD_CLOSED` and
`chain ready ... detached=1`. No exploit or page-holder process remained.
KernelSU loaded on the same boot and the root proof returned uid 0.

The tested payload has SHA-256:

```
27e792c5576261a265fc4477f06fa87ae6d83093ed2c5f1a7bec5536ba06f8ba
```

The model-specific payload is proposed upstream in
[Root-My-Galaxy-Payloads PR #168](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/pull/168).
# rt_sigreturn FPSIMD writer branch (2026-08-08)

- Worktree: `root-my-galaxy-clean-fpsimd`, branch
  `agent/rt-sigreturn-fpsimd-poc`.
- Exact GZG3 disassembly was rechecked. The stale `rt_mutex_waiter` is at
  syscall-entry SP `- 0x1e0`; `restore_fpsimd_context` copies `0x200` bytes
  into a local buffer at syscall-entry SP `- 0x2e0`. The waiter therefore
  starts at FPSIMD `vregs + 0x100` and its full `0x50` bytes are covered.
- Added a separate `fpsimd-writer-poc`; production `poc.c` and clean chain are
  unchanged. `frame` is the safe writer/oracle control. `ghostlock` creates
  the stale waiter, writes through `rt_sigreturn`, stops before
  `sched_setattr`, and stays alive.
- A kprobe at `restore_fpsimd_context+0x338` is rejected because that point is
  the function return instruction. The accepted live oracle is a kretprobe on
  `__arch_copy_from_user`, filtered to `fpsimd-poc`, reading kernel
  `SP+0x100..SP+0x148` after the copy.
- Root must invoke pushed scripts as `/system/bin/sh SCRIPT`. Directly
  executing a root-owned command from `/data/local/tmp` is killed by Samsung
  DEFEX and logs `Safeplace violation`; this is unrelated to kprobe or FPSIMD.
- Safe `frame` live test passed: `restore_fpsimd_context+0x338` returned from
  `__arch_copy_from_user` with `ret=0`, and kernel `SP+0x100..+0x148` contained
  the exact ten-qword marker.
- Full `ghostlock` live test passed on boot
  `22f64510-d8c8-4a96-b7ca-bae695310f8c`. Probe facts:
  `rt_mutex_waiter=0xffffffc03047bc60`, restore SP
  `0xffffffc03047bb60`, so `SP+0x100` equals the waiter exactly. The same
  event contained markers `0x465053494d440000..009`.
- The full PoC never called `sched_setattr`; it stayed alive after the copy.
  The host then deliberately used `adb reboot` to remove the stale waiter.
  There was no spontaneous reboot during capture.
- After replacing cross-thread signal flags with lock-free C11 atomics, the
  rebuilt binary (`d795ccdb4ae3c74a67d7832c0411ebbf87a279730f422eb7e0d88bfd2e53f684`)
  passed safe `frame` mode again on the next boot.
- `scripts/build-exploit.sh` now applies the root-helper patch with `patch`
  after a dry run. WSL otherwise follows the Windows worktree `.git` pointer
  and fails before compilation; the patch does not need repository discovery.
- Probe capture now uses a dedicated tracefs instance `rmg_fpsimd`; it no
  longer clears or stops global tracing. Cleanup disables and removes both
  dynamic events and then removes the instance, so the check leaves no trace
  controls behind.
- `scripts/run-fpsimd-frame.ps1` passed end to end on the next boot with the
  stable tracefs/perf root already active: exact target gate, build, push,
  host/device SHA-256, isolated probe capture, marker gate, and cleanup. After
  the run, no `rmg_fpsimd` instance or dynamic probe remained; root stayed
  active.
