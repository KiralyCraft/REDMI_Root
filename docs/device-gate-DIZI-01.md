# DIZI-01 device gate: dizi 5.10.236 select_stack full path — PASS

Baseline commit `67d519b` (upstream main) plus the uncommitted changes in this workspace
(batches 1/2/2c/2d/2e/3a; the list and validation are in
`docs/development/dizi-5.10-select-adaptation-plan.md`). Candidate binary
`build/native/ghostlock` SHA-256
`cde2c59828586fbbecddf0f21a6c9f518028f9d26027fc0ef366f37a996648dc` (md5
`2311977db70f5f2d2266a7e351983cb9`, matching the device copy). Device-side profile bin
md5 `49ff261c8bd37236ff54db9edac1efb6`.

## Device and entry point

- Model 2405CRPFDC (Redmi Pad Pro / POCO Pad, dizi, parrot/SM7435); `uname -r` =
  `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`; HyperOS 3 OS3.0.307.0.WNSCNXM,
  Android 16, patch level 2026-08-01; bootloader state vbstate=green, no preinstalled
  KernelSU/su.
- Entry point: CLI over USB adb,
  `./ghostlock --load-prebuilt-profile /data/local/tmp/profile.bin`; cold boot, single
  route (select_stack), CPU pair 0/1 (the value recommended by the profile).
- Two-stage gate (batch 2d): stage 1 exits cleanly after `--stop-after-w1`, then stage 2
  runs W2/W3 in a new process.

## Result

Each of two independent cold boots completed a full PASS (evidence:
`build/dizi/9p-c5-p2-1.log`, `build/dizi/9p-c4-p2-1.log` plus driver logs
`gate-2phase-driver10.log` / `gate-2phase-driver11.log`):

```
[+] child uid = 2000            # baseline probe before the W2 write: child answers
[*] pselect route done calls=1 success=1 status=0 clean=1/1 step=0 errno=0
[*] W2b: firing prebuilt init_cred+8 repair
[*] pselect route done calls=1 success=1 status=0 clean=1/1 step=0 errno=0
[+] child uid = 0
[+] child is root!
[+] no app seccomp filter (adb/shell flow); skipping W3
[*] [T+13558ms] exploit complete
[+] KernelSU ready
```

Post-run checks (the device did not panic): `su -c id` reports `uid=0(root) gid=0(root)
groups=0(root) context=u:r:ksu:s0`; SELinux is back to Enforcing; the KernelSU manager
shows "working [jailbreak mode]"; `.ghostlock_ksu.log` records `late-load
kmi=android12-5.10`, `late-load exit=0` and `KernelSU module loaded`.

## Logs

- Host side: `build/dizi/` (gate-loop driver logs `gate-2phase-driver*.log`, per-run logs
  `9p-c*-p*-*.log`, A/B control `ab-driver.log`, A/B run logs `ab-*.log`).
- Device side: `/data/local/tmp/.ghostlock_ksu.log` (late-load record) and
  `.ghostlock_iomem` (a 11227-byte copy of /proc/iomem cached after rooting).

## Change summary

- This record covers the joint device validation of batch 1 (leaf arm / ghost disarm),
  batch 2 (mm_struct_sz=960), batch 2c (w2_fast_repair for the 5.x select route), batch
  2d (two-stage run), batch 2e (raising the victim pipe fds — fixing an upstream latent
  bug where the select route's dup2 could seize the pipe fd and cause a false verify
  failure) and batch 3a (moving skb_reclaim_sends/skb_frag_bias down into profile fields,
  plus the shared-mutable fix in ProfileMerger).
- Known device behavior: the payload page reclaim hit rate is roughly 1/3–1/2, and a miss
  panics and reboots (KASAN_HW_TAGS + PANIC_ON_OOPS environment). The two-stage flow and
  the in-boot retry loop turn this into a self-recovering cycle.
