# Agent run book

1. Read `PROVENANCE.md`, `TUTORIAL.md`, and the chosen `target.env`.
2. Check the phone model, build, kernel release, and all three trace IDs.
3. Stop if any exact-profile fact does not match. Do not try nearby addresses.
4. Use native WSL for the large KernelSU/kernel build. The small exploit C build
   can run from the normal project path.
5. In native WSL, fetch KernelSU with `scripts/fetch.sh`.
6. Build the exploit. Run shell root once.
7. Get the live config and kallsyms with `collect-target.ps1`.
8. Have the operator manually download the exact Samsung source from the Open
   Source Release Center. Extract it, get clang, and check hashes. The kit does
   not fetch the Samsung source. Get stock firmware only for porting; see
   `PORTING.md` for the FUS download flow.
9. Build KernelSU. The symbol audit must say zero missing.
10. Reboot, unlock the phone, wait for full boot and
    `sys.user.0.ce_available=true`, run one root chain, then one `ksud late-load`.
11. Do not run the exploit again while `kernelsu` is live. Use `/system/bin/su`,
    or reboot first. A second exploit pass can reset the phone.
12. Prove both `/proc/modules` and `/system/bin/su -c id`.

If two runs reboot at the same exploit point before module staging, stop too.
Keep the last log. Do not call it a module crash.

For a new build, make a new profile. Find all addresses and struct offsets from
that exact kernel. A same kernel version is not proof.
