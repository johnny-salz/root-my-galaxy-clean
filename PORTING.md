# Porting this kit

This file is for a new phone or firmware. It is not needed to run the checked
A536E profile.

## Port to another build

Do not change only the model string. Make a new profile from these inputs.

1. **Identify the live target.** Save model, build fingerprint/incremental,
   `uname -r`, ABI, page size, SELinux state, and the live trace event IDs.
   Run `collect-target.ps1` **after bootstrap root**. Its `kernel.config` is the
   source of CFI, SCS, module, KDP/RKP, and `CONFIG_MODVERSIONS` flags. Its
   `kallsyms.txt` is the fresh symbol-name set for module audit. Do not reuse
   another phone's file.

2. **Get the exact stock firmware.** This is separate from Samsung Open Source.
   The Open Source `SM-A536B.zip` wrapper contains source zips; it is not the
   phone firmware. Read the model, CSC/region, and four-part build version from
   the live phone. Query Samsung FUS, then download that exact version:

   ```powershell
   samloader.exe check-update --model SM-A536E --region THL --all --verbose
   samloader.exe download `
     --model SM-A536E `
     --region THL `
     --version "A536EXXSNGZG3/A536EOLMNGZG3/A536EXXSNGZG3/A536EXXSNGZG3" `
     --threads 16 `
     --out-dir firmware `
     --verbose
   ```

   A previous firmware can help find the kernel family and start analysis, but
   its addresses, event IDs, offsets, and slide constants are hypotheses only.
   **Final values must come from the exact live build or its exact stock image.**

3. **Get the matching Samsung source.** Use the source release that covers the
   target kernel branch. Extract its `Kernel.tar.gz`, then apply only the small
   source fixes that the build proves necessary. The live config still wins;
   source model or region names do not prove ABI equality.

4. **Recover the exact kernel image.** Decompress Samsung LZ4, extract the raw
   ARM64 `Image` from `boot.img`. Recover a
   symbolized ELF with `vmlinux-to-elf` when possible. Generate `vmlinux.nm`
   with `llvm-nm --numeric-sort` and use `llvm-objdump` for the few functions
   whose call sites define exploit constants. Use `pahole`/`bpftool` only when
   the image has usable BTF. Ghidra is useful for hard cases and review, but
   its project database is not a build dependency.

5. **Derive, do not copy, target facts.** A new `target.h` must contain the
   trace event IDs, trace caller offsets, physical/direct-map bases, object
   aliases, structure offsets, waiter/fd-set geometry, and all other addresses
   used by `poc.c` and `bridge.c`.

6. **Build and audit.** Build the module with the exact release string and live
   config. Keep `.symtab` and `.strtab`, leave `__versions` empty, and run the
   target-symbol audit. Do not copy `Module.symvers` from another build:
   `ksud` performs live `/proc/kallsyms` relocation. Then test one controlled
   reboot on the exact phone before calling the profile supported.

## What is required

| Item | Ready-made profile | New port |
| --- | --- | --- |
| Samsung Open Source tree | Yes | Yes, as close branch as possible      |
| Live config and `kallsyms.txt` | Yes, regenerate if phone changes | Yes, exact phone |
| KernelSU v3.2.5 full history | Yes | Keep pin unless protocol/signature is re-audited |
| Android clang `r416183b` | Checked build pin | Match vendor family; retest if changed |
| NDK `29.0.14206865` and Rust nightly pin | Checked userspace build pins | Replaceable only with a new build check |
| Stock AP/BL firmware images | No | Yes, unless exact raw kernel/boot evidence is already retained |
| `vmlinux.elf`/`vmlinux.nm` | No, constants are checked in | Yes, for deriving constants |
| LLVM `nm`/`objdump` | Build tool | Analysis tool; version can vary if results are checked |
| Ghidra | No | Optional analysis aid |
| Exact target profile | Already present | Must be new and re-audited |
