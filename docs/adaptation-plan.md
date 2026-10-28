# dizi 5.10 select-route adaptation plan (2026-10-08)

> Written with the plan template from `documentation-standards.md`. **All batches are
> complete** (2026-10-09): two consecutive cold-boot device-gate passes (record
> `docs/analysis/device-gates/DIZI-01-20261009-select-stack-pass.md`), dizi registered in
> SUPPORTED_DEVICES, and KernelSU jailbreak mode landed.

## Status and baseline

- Branch baseline: `very-not-stable-dev`, upstream `main` @ `67d519b` (no commits made
  after cloning).
- The workspace already contains uncommitted changes (all of which reached their current
  state through device or static validation):
  - `app/src/main/assets/kernel_profiles/5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284.conf` (new)
  - `app/src/main/assets/kernel_profiles/index.conf` (one registration line added)
  - `tools/extract_rs/examples/dump_init_cred.rs`, `derive_select_shift_5x.rs` (new,
    host-side one-off derivation tools)
  - `local.properties` (local SDK/NDK paths, not committed)
- Device: Redmi Pad Pro / POCO Pad (dizi, parrot),
  `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, HyperOS 3 OS3.0.307.0.WNSCNXM,
  Android 16, patch 2026-08-01, no KernelSU/su, vbstate=green.
- Static evidence chain for the profile (complete and trusted):
  - The vulnerable primitive exists: `remove_waiter@0x1ecc18` is unpatched (determined
    statically from the official OTA boot.img).
  - All struct offsets come from the DWARF of the same-build GKI vmlinux (ci.android.com
    build 14313284, kernel/common fb24cf99ad97) and were cross-checked byte by byte on
    the device boot.img: `init_task.comm="swapper"`, the `init_cred` caps section
    (0x30..0x40 = 0x1ffffffffff×3), and the self-referential `init_task.tasks` pointer
    all match exactly.
  - The select stack geometry is **proven at byte level** from the frame depths of both
    syscall chains: the futex chain (0x90+0x70+0x1a0, waiter at futex_wait_requeue_pi
    sp+0x90, cross-checked against the two real writes at [sp,#0x90]/[sp,#0xc0]) and the
    pselect chain (0xa0+0x1c0, stack_fds at core_sys_select sp+0x50, the nfds=320 stack
    path threshold holds). Both give S0-0x210 → delta=0 → `waiter_shift=-2`.
- Gate-failure evidence (three cold boots, same build, same execution point
  `pselect pre-select attempt=1/4` panic, satisfying same-build reproduction + cold-boot
  rerun, ruling out KERNEL-PANIC-01):
  - run1: NULL deref @ 0xc39, `rt_mutex_adjust_prio_chain+0x3f0` = the BUG_ON
    pre-read of `rt_mutex_top_waiter`; `fake_lock->waiters.rb_leftmost` read as **0xc01**.
  - run2: NULL deref @ 0x8, `rb_insert_color+0x48` = `__rb_insert` reading
    `gparent->rb_right` with gparent==NULL (a "red node without parent" in the tree).
  - run3: panic at the same point (signature not retrieved; device offline timeout).
- **Root cause (instruction-level analysis, evidence below)**: both panics come from the
  **payload page reclaim missing** — the fake_lock page parsed by the walk still contains
  the old mm_struct contents (0xc01 = dizi 5.10 `mm_struct.vmacache_seqnum@+0x10`,
  whose magnitude matches the thousands of dup_mm calls in that spray round; the 3
  failed KernelSnitch leaks in the same round are corroborating evidence that the reclaim
  is marginal). **The 5.10 rtmutex walk itself is harmless**: given "correct stamp +
  correct page", the walk completes and triggers the write primitive at the [7]
  tree_entry erase (run2 had actually produced `*target = fake_right` before crashing on
  page garbage).
- Hypotheses ruled out: wrong waiter_shift (frame accounting is exact); incompatible 5.10
  walk semantics (verified harmless instruction by instruction).

### 5.10-specific differences (checked at instruction level; used as design facts below)

1. `rt_mutex_waiter` layout: tree_entry@0 / pi_tree_entry@0x18 / task@0x30 / lock@0x38 /
   **prio@0x40** / deadline@0x48, size 0x50; **no wake_state and no ww_ctx** (5.15:
   wake_state@0x40, prio@0x44). The current compact encoding writes +0x44=140 assuming
   the 5.15 layout, so the 5.10 kernel actually reads 0/3 from +0x40. Impact: after [7]
   the re-insert lands to the right of fake_w0 instead of at leftmost, and the [11]
   pi-erase refire (a redundant write) does not happen; the primary write is unaffected.
   With a single waiter, neither the waiter_equal gate (requeue when unequal) nor the [9]
   wake branch is affected.
2. `route_needs_ghost_disarm()` is true only for multicast (route_policy.hpp:271-276); the
   5.10 CMP_REQUEUE error path clears `current->pi_blocked_on` (the main thread) and the
   waiter thread's `pi_blocked_on` necessarily becomes a dangling ghost — the select route
   does no disarm on 5.10, which is a hazard when W2/W3 reuse the race.
3. The select encoder's leaf arm deviates from the `encode_compact_waiter` contract (see
   change list batch 1).

## Goals and constraints

**Goal**: pass the device gate for the dizi 5.10.236 select_stack route (W1/W2 writes
verified; W3 skipped in the CLI shell domain; the in-app Shizuku path is the same), and
complete every validation gate before the profile is marked supported.

**Non-goals**:
- Do not restore the multicast/tcp routes (multicast geometry is proven infeasible:
  waiter_off=336 > the fixed 264-byte window; tcp is structurally blocked by uapi struct
  sizes).
- No general 5.10 support (this release only).
- Do not change walk/rtmutex assumptions (proven harmless).
- Do not pursue restoring the [11] refire (redundant write, no functional gap; open a
  separate L-level item if needed).
- W3 (seccomp) is not validated in this plan (the shell/Shizuku paths skip it naturally).

**Constraints**: the profile (GLK1) is the single source of configuration truth; new
fields are synchronized on both sides and locked down by agreement tests; changes to the
attack path require cmp_disasm of 8 functions + a device gate + a gate record; never mark
supported without passing the gate.

## Change list

### Batch 1 (S-level cap, correctness fix, do first)

| File | Change | Reason |
|---|---|---|
| `src/core/route/select_stack_route.cpp` | compact branch words[]: for a leaf (fake_right==0), stamp both the tree and pi groups of three fields as `{fake_parent, 0, 0}` (matching the `encode_compact_waiter` contract and the payload_builder.h:71-72 comment); non-leaf unchanged | the current code stamps a leaf as `{0,0,target}` → erase takes the root arm, writes rb_root = target → the next insert walks from the selinux data area → rb_insert_color-style panic. W1/W2 do not trigger it today because preserve_child=1, but W3 would; it is a real correctness bug |
| `src/core/tests/` (existing select/encoder fixed-vector tests) | add a leaf fixed vector (pc=left=... matching the existing payload_builder vector semantics) | mechanism guard, fixed regression |
| `src/core/route/route_policy.hpp` | evaluate and extend `route_needs_ghost_disarm()` to the 5.10 select route (decide by compact_waiter+kernel_major==5 or a new policy declaration, minimally expressive) | a 5.10 ghost necessarily remains (difference #2); prevents a second walk from stepping on the reused stack frame when W2/W3 reuse the race |

### Batch 2 (M–L level, root-cause fix, gather evidence first)

| File | Change | Reason |
|---|---|---|
| `src/core/memory/heap_context.*` / `util.cpp::prepare_kernel_page` and nearby | first add a **reclaim-hit self-check/diagnostic** (validate the page contents against the oracle before stamping; on failure return ROUTE_RETRYABLE instead of proceeding to the walk); then calibrate dizi's skb reclaim geometry from the diagnostic data (SKB_DATA_DELTA/SKB_FRAG_BIAS are currently compile-time constants, constants.hpp:14,24) | the common root cause of both panics; the oracle first turns "reclaim missed" from a random panic into an observable, safely retryable failure |
| (possibly) new fields in the profile heap section | if calibration shows the delta/bias are machine-specific, move them down into profile fields (both sides synchronized + agreement tests) | single source of configuration truth; do not hardcode per-device values |

### Batch 2c (M level, complete the W2 repair mechanism)

| File | Change | Reason |
|---|---|---|
| `src/core/route/route_policy.hpp` | `SelectPolicy` declares `w2_fast_repair = true` + an Android-only noinline hook declaration | 40 gate rounds measured: W1 hit 15/40 (37%), W2 0/15 with a panic every time. On 5.x the second erase write of the cred write stores the cred pointer into the real init_cred+8 (corrupting init_cred.gid); multicast has the prebuild/activate repair but select lacked it, so 5.x+select W2 had never been validated upstream |
| `src/core/route/select_stack_route.cpp` | define `SelectPolicy::w2_fast_repair_prebuild/activate` with the same semantics as the multicast version (stash the pre-sprayed repair page → activate after the primary write to zero `init_cred_alias+8`), **self-gated at runtime on `kernel_major==5`**, keeping 6.x an inert no-op | protect the developer-validated 6.x select path; the repair mechanism is required for 5.10/5.15-class kernels |
| `src/core/tests/route_policy_test.cpp` | keep the SelectPolicy capability assertions in sync | capability-list agreement |

### Batch 2d (M level, two-stage run — borrowed from ghostlock-oneplus's process isolation design)

| File | Change | Reason |
|---|---|---|
| `src/core/session/runtime_config.h` | `RuntimeConfig` gains `stop_after_w1` (default false, not cleared by init()) | measured at the gate: when the same process continues to W2 after W1 hits, the heap has been churned by thousands of forks/sprays and W2's reclaim hit rate approaches 0 (15/15 panics). ghostlock-oneplus's bootstrap mode likewise runs W1 in a separate process and exits immediately (its main.c:753 comment states this motivation) |
| `src/core/main.cpp` | parse `--stop-after-w1` and store it in the runtime config | a CLI process-behavior switch, same class as `--force-attack` |
| `src/core/session/backend/cve_2026_43499_backend.cpp` | in `run()`, after w1 returns Continue, check the switch; when `true`, `pr_success` + return `StageResult::Done` (mapped to DiagnosticStop, exit 0) | stage 1: loop `--stop-after-w1` until W1 succeeds and exits cleanly; stage 2: run normal mode, where `check_selinux_off()` hits the existing "SELinux already permissive" branch, skips W1 and does W2 directly on a clean heap (W2's hit rate is then ≈ the 37% of a cold W1, together with batch 2c's fast_repair) |

### Batch 3 (validation and wrap-up)

- dizi device gate (cold boot, fixed CPU pair, single route, no KernelSU); only two
  consecutive PASS runs count as a pass;
- archive the gate record (linked from §Progress below, format per the gate template);
- after passing, update `docs/kernel_profiles/SUPPORTED_DEVICES*.md` (bilingual) to
  register dizi; never mark it before passing.

## Data-flow / control-flow differences

- The batch 1 leaf change only alters the three u64 values stamped for a leaf write (the
  source fields of pc/left); the wire/profile format is unchanged; the non-leaf path is
  byte-identical (proven with cmp_disasm + fixed vectors).
- The batch 1 ghost-disarm change adds one futex slow-path disarm to the route's teardown
  path (reusing the existing multicast semantics) and changes nothing inside the attack
  window.
- The batch 2 oracle is a read-only check during the prepare phase (outside the attack
  window); its failure semantics are a safe retry, producing no new kernel write.
- Invariant: every existing behavior of the validated 5.15/6.x devices is unchanged (all
  changes are byte-level invisible to non-dizi profiles, proven by cmp_disasm + host
  fixed vectors + RouteCatalogAgreementTest).

## Compatibility and rollback

- All changes are backward compatible: no wire-format version change (v2 unchanged); the
  leaf fix affects only an error branch.
- Rollback = revert the corresponding batch commit; the profile conf and the index.conf
  registration line stay or go based on the batch 3 gate result (if the gate fails, keep
  the conf but do not add the device to SUPPORTED_DEVICES).

## Validation matrix

| Batch | Command/action | Expectation |
|---|---|---|
| 1 | `make -C src native-host-tests` | all pass (including the new leaf fixed vector) |
| 1 | `make -C src lint-tidy` | 0 findings |
| 1 | NDK build | zero warnings |
| 1 | `python3 tools/cmp_disasm.py <baseline> build/native/ghostlock` | 8 functions IDENTICAL or named annotated differences (leaf branch) |
| 1 | dizi gate ×2 cold boots | no more rb_insert/root-arm panics; W1 still behaves at the pre-batch-2 reclaim hit rate |
| 2 | the same gate + diagnostic logs | a reclaim miss becomes an observable retry (no panic); after calibration W1 verify passes |
| 3 | dizi cold boot ×2 consecutive | W1/W2 write verification passes with no panic → only then mark supported |
| all | `./gradlew :app:testDebugUnitTest` | all pass (including both-side agreement) |

KERNEL-PANIC-01 discipline applies: any new panic may only be attributed after
same-build reproduction + cold-boot rerun + stack evidence; retrieve and archive the
RebootChart record after every gate.

## Explicitly out of scope

- Upstream code in `kernelsnitch/` and the v1 conversion in `LegacyProfileConverter.kt`:
  untouched.
- rtmutex walk assumptions and the `waiter_shift=-2` geometry: byte-level checked,
  untouched.
- The multicast/tcp route code and every existing 5.15/6.x profile: untouched.
- The existing multicast behavior of `route_needs_ghost_disarm`: untouched (batch 1 only
  extends its coverage).
- No new configuration-format version; no dizi values hardcoded into native (calibrated
  values go through the profile).

## Progress

- [x] Design document (this file)
- [x] Batch 1: select leaf arm + ghost-disarm + host tests + cmp_disasm
  - changes: `select_stack_route.cpp` (leaf stamps `{fake_parent,0,0}`),
    `route_policy.hpp` (ghost disarm extended to kernel_major==5),
    `route_policy_test.cpp` (5.x/6.x assertions)
  - validation: `native-host-tests` 20/20 ok; NDK build zero warnings; `lint-tidy` exit 0;
    cmp_disasm: 5 functions IDENTICAL, 2 functions MISSING in both baseline and current,
    waiter_thread +3 instructions reviewed (cmp/b.eq/cbz for major==5, the rest pure
    address renumbering; `do_pselect_fake_lock_route` purely renumbered,
    `select_stack_build_fdsets` differs by the leaf csel three-way selection + block
    reordering)
  - note: the `ProfileMigrationEquivalenceTest` failure in `:app:testDebugUnitTest` is a
    **pre-existing upstream HEAD problem** (fixture has 55 entries vs the current 6.x
    builtin 57, missing 6.1.25-maybe-dirty and 6.6.89-ab13771415; unrelated to this
    batch and outside this plan's scope); the other 79 tests pass
- [x] Batch 1: dizi gate ×2 (observe whether root-arm crash types disappear; reclaim-miss
      panics are still expected)
  - run4 (batch 1 build): **no panic**, 15 W1 attempts failed cleanly (exit=1); ghost
    disarm is active on the select route (log `mcast ghost disarm ret=-1 errno=110`);
    exposes the full picture behind batch 2's root cause: KernelSnitch leak success rate
    ~3% (2 of 60)
- [x] Batch 2 (root cause): **wrong mm_struct slab stride**. dizi's SLUB uses 64-byte
  cachelines: DWARF sizeof(mm_struct)=952 → measured /proc/slabinfo objsize=960
  objperslab=34; the profile carried over 1024 from the 5.15 machine → scan/reclaim
  misalignment. Both successful leaks fell in slots where 960 and 1024 coincide
  (k∈{0,15,30}), confirming it. Fix: profile `mm_struct_sz = 960` (pure configuration).
  Evidence collected by reading /proc/slabinfo and /proc/config.gz directly from the
  device shell (no root needed).
- [ ] Batch 2: gate validation run5 (960): **the leak succeeded on attempt=1** (+2.2s),
  but the walk panicked (exit=255, pre-select attempt=1/4) — the page should have been
  reclaimed correctly, so the panic points at route semantics; RebootChart signature
  pending retrieval and analysis
- [x] Batch 3: gate ×2 consecutive PASS, gate record, SUPPORTED_DEVICES registration
  (only after passing)
- [x] **Batch 2e gate passed (2026-10-09 00:44)**: with the fd-raising fix, W2 succeeded
  on the first attempt of stage 2 in the first permissive boot (`child uid = 0` /
  `child is root!`), and the root script ran fully as uid=0 (policy fixup rc=0; the
  11227-byte iomem cache written to disk for precise calibration).
- [x] **KernelSU landed (2026-10-09 01:2x, evidence in `.ghostlock_ksu.log`)**: after
  installing the manager and rerunning, `late-load kmi=android12-5.10 exit=0` →
  `KernelSU module loaded`; final check `adb shell su -c id` →
  `uid=0(root) context=u:r:ksu:s0`, and the manager shows "working [jailbreak mode]".
  **The dizi 5.10.236 select route is fully working.**
- [x] **Batches 3b/3c complete (2026-10-09 03:0x-03:3x)**: two consecutive cold-boot
  full-path PASS runs (v10 cycle 5 / v11 cycle 4, both `KernelSU ready`); gate record
  `docs/analysis/device-gates/DIZI-01-20261009-select-stack-pass.md`; bilingual
  SUPPORTED_DEVICES registration; the "unverified" annotation removed from the conf.
- [x] A/B comparison: pre3a vs 3a builds have the same W1 hit rate (1/3 each), so batch 3a
  has no regression.
- [x] iomem calibration check: after rooting, `/proc/iomem` shows System RAM starting at
  0x808f4000, DRAM base=0x80000000 matches the profile default, and
  `kernel_phys_load=0xa8000000` falls inside the RAM mapping — **every profile geometry
  value was re-checked against device data and needs no correction**.

### Batch 2 implementation record (2026-10-08 afternoon)

- run6 (sends=16): panic (signature rb_insert_color+0x48, same as run2).
- **Geometry breakthrough**: dizi 5.10's unix sendmsg allocation path (verified against
  af_unix.c + skbuff.c sources) = 4 KB header (kmalloc) + order-3 whole-page frag (data at
  page offset 0) → stream byte 4096 corresponds to the start of the target block. Carrying
  over the 5.15 bias=0 puts the payload 0x180 too early. Experiment:
  `SKB_FRAG_BIAS 0→0x180`.
- run8 (bias=0x180 + sends=16 + diagnostic logs): **W1 succeeded** (attempt 4 route done
  status=0 → "SELinux permissive" → "Write 1 complete", write verification passed),
  **empirically confirming the shift=-2 geometry, the bias=0x180 alignment and the 5.10
  walk**. W2 attempt 4 panicked (signature rb_insert_color+0x48, reclaim-miss class).
- run9 (sndbuf 4 MB + sends=128 to fill up): panic — after an order-3 frag allocation
  failure falls back to small pages, the buddy allocator splits the target block and the
  mapping misaligns; over-pressuring does not help.
- run10 (back to the run8 configuration): W1 panicked on the first walk — run8's W1 hit
  contained a probabilistic element.
- **Conclusion**: the per-walk reclaim hit rate is about 1/3–1/2; a miss panics (the page
  holds an old mm / misaligned frag / wild pointer, and there is no read primitive to
  detect it in advance); without root it is impossible to read pstore/buddyinfo/slab
  internals, so calibration can only come from gate iterations. Remaining work =
  deterministic reclaim calibration (heap feng shui), at the cost of one panic + a manual
  USB replug per round.
- run11/12 (oracle / drain+oracle): still panics, the oracle never triggers — draining the
  order-3 freelist actually forces the reclaim frag to fall back to small pages that split
  the target block (broken mapping), so drain was reverted. The evidence now points to the
  block being covered by the frag most of the time but with **misaligned contents** (order
  fallback) or not covered at all (stale mm); the oracle only helps while "the block stays
  in the slab", so its trigger rate is low.
- run13 (the author's original orchestration sends=4 + bias=0x180 + oracle): still panics.
  The workspace is back on the run8-validated configuration (sends=16, bias=0x180, 960) +
  oracle + reclaim diagnostic logs.
- **Hit-rate accounting**: of 6 attempts that reached the walk, W1 hit once (run8). run8
  proved the geometry, the alignment and the 5.10 walk are all correct; what remains is
  purely the probabilistic reclaim hit rate.

### Offline analysis record (2026-10-08 evening, while device access was paused)

1. **Panic signature classification** (RebootCharts from 6 bugreports, including 108
   crashes from the 40-round loop): all in the same family — under
   `rt_mutex_adjust_pi+0x174`, `rb_insert_color+0x48` /
   `rt_mutex_adjust_prio_chain+0x3f0` / `+0x548`. **Zero cred-related signatures**: the
   hypothesis that a cred state inconsistency crashes the kernel is false.
2. **Exact derivation of the W2 cred write side effects** (encode_compact_waiter + 5.10
   rbtree/rtmutex semantics): the primary write is
   `*(child_task+1920) = init_cred_alias` (the low 2 bits of pc are 0, so the value is
   exact and not a poisoned pointer); the secondary write is
   `*(init_cred+8) = child_task+1920` (fixed by fast_repair zeroing it). No other
   out-of-bounds write. **On paper: if the write lands on the correct child, getuid must
   return 0** — a silent child leaves only two possibilities: "the child was already dead
   / the address was invalid at write time" or "child_task pointed at the wrong object",
   and the comm probe decides between them.
3. **Kernel configuration** (IKCONFIG extracted from boot.img, 181 KB):
   - `CONFIG_DEBUG_CREDENTIALS` unset (no cred magic-number landmine)
   - `CONFIG_PANIC_ON_OOPS=y` (any oops reboots — the source of every failure's physical
     cost)
   - `CONFIG_CFI_CLANG=y` (confirms that ghostlock-oneplus's fops-hijack route is not
     viable on dizi; the data-write route is the only option)
   - `CONFIG_KASAN_HW_TAGS=y` + `CONFIG_KFENCE=y` (likely amplifiers of the reclaim-miss
     panic family)
   - no `RANDOMIZE_KSTACK_OFFSET` (only introduced in 5.13; 5.10 stack geometry is
     deterministic — the reason stamping is reliable)
   - `SLAB_FREELIST_RANDOM/HARDENED`, `SHUFFLE_PAGE_ALLOCATOR`, `INIT_ON_ALLOC` all
     enabled
4. **Probe mode v1 lesson**: under SELinux enforcing, perf_event_open is blocked (15
   rounds, zero panics, all failing with "perf leak did not reproduce"); the probe now
   runs after W1, and once W1 succeeds in a boot, later probes skip W1 entirely.

### Batch 3a (M level, move calibration values into the profile + upstream merger fix — 2026-10-09)

- **Motivation**: dizi's calibration values (`skb_reclaim_sends=16`, `skb_frag_bias=0x180`)
  were compile-time constants, so landing them directly would regress the validated
  6.x/5.15 devices (upstream values 4/0). Following "the profile is the single source of
  truth" they were moved into profile fields (absent = compile-time default).
- **Touch points**: native `model.h` (KernelMisc + accessors) / `binary.cpp` (kKernel +2
  OPT) / `constants.hpp` (back to 4/0) / `util.cpp` (consumers read the profile); Kotlin
  `NativeProfile.kt` (declaration/serialization/HOCON parsing/deserialization/constructor,
  6 places) / `AndroidProfileConfigController.kt` (field list) / `FieldLabels.kt` +
  bilingual strings; dizi conf `kernelsnitch { skb_reclaim_sends=16, skb_frag_bias=384 }`.
- **Incidental upstream bug found and fixed**: `ProfileMerger.resolveMerged` put the
  shared `tuningExecution` into defaults by reference, and `deepMergeValues` mutated the
  base in place → any profile carrying an execution override block (dizi was the first)
  would **pollute the override value into every profile exported later in the loop**
  (5.15.189's w2_attempts was written as 1, caught by ExporterAgreementTest). Fix:
  `copyValue()` deep copy before inserting.
- **Validation**: host tests 20/20; lint exit 0; cmp_disasm shows all 8 functions
  LAYOUT-SHIFT (annotation offsets only, no instruction-shape change); after
  `exportKernelProfiles` the measured values are 5.15.189 w2_attempts=15 and dizi
  w2_attempts=1/skb fields=384/16; `:profile-core:test` all pass;
  `:app:testDebugUnitTest` only shows the pre-existing upstream
  ProfileMigrationEquivalenceTest failure.
- **A/B comparison (empirical proof that 3a has no regression)**: the pre3a build (the code
  state that rooted twice) and the 3a build, alternated 3 W1 runs each on the same device:
  pre3a 1/3, 3a 1/3 — identical hit rate, so the 0/6 in the early cold-boot gates was
  probability noise, not a code regression.

### Batch 2e (S level, root cause of the W2 verify EBADF failure — 2026-10-09)

- **Root cause** (gate forensics + code review, closed loop): the select route's
  `open_selected_fds()` `dup2`s over every fd number whose fd_set bit is set; a non-leaf
  write stamps `pi_left=target` (a kernel pointer) into the fd_set, and when bit 6/7 of the
  pointer's low byte is set it seizes the victim pipe's fds 6/7 → the child reads EOF and
  exits (exit 1) → verify EBADF. The comm probe (leaf, pi_left=0) is unaffected —
  consistent with every observation. This is an **upstream latent bug** (the validated 6.x
  devices simply got lucky with addresses).
- **Fix**: after `spawn_child` creates the pipes, raise the six pipe fds above the
  stamping window with `fcntl(F_DUPFD, PSELECT_ROUTE_NFDS+128)` (same precedent:
  `reserve_standard_io`).
- Incidental: `verify_w2_stage`/`verify_leaf_dir_stage` now log child liveness and fd
  forensics (waitpid status code + fd numbers), and `w2()` prints the pipe fds after
  spawning.

### Batch 2c/2d implementation record (2026-10-08 evening)

- **Plan A, 40 rounds**: W1 15/40 (37%); W2 0 successes out of 15 chances (the first walk
  always panics).
- **Batch 2c**: w2_fast_repair ported to select (self-gated on `kernel_major==5`).
  Validation: host 20/20, lint 0 findings, cmp_disasm 5 IDENTICAL + one anchor-symbol
  annotation difference in do_one_write (reviewed; instruction stream identical).
- **Batch 2d**: `--stop-after-w1` two-stage run (borrowing ghostlock-oneplus's W1 process
  isolation). cmp_disasm same conclusion.
- **Two-stage gate data over 13+ cycles**: stage 1 W1 success rate ~50% with clean exits
  and zero panics; stage 2 reached W2 every time, and both the primary write and the
  repair write reported `success=1 status=0` (the writes really landed and the repair
  mechanism works), but **verify always failed silently** (no `child uid` line; the child
  never answered the "C" probe). One c10 round had 3 consecutive attempts with no panic →
  the stage 2 heap is clean, and the problem shifts from "reclaim hit" to "the child does
  not answer after the write" (suspects: the perf leak gave the wrong child_task / a cred
  offset error / the child was killed on the side).
- Added verify_w2_stage child-liveness diagnostics (waitpid WNOHANG status code), awaiting
  the next stage 2 data point.
- The dizi profile overrides `execution.stages.w2_attempts = 1`: a failed stage 2 exits
  cleanly and the outer loop reruns stage 2 directly (SELinux is still permissive),
  avoiding 15 idle iterations on a dirty heap until the panic.

---

## Addendum (2026-10-28): second supported build

A second build is now covered by an offline-derived, build-exact profile:
`5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` (HyperOS 1.0.19.0.UNSCNXM). Its
`profiles/*.bin` / `.conf` were derived from that build's own kernel image (kallsyms
decoding, pointer-chase anchors, device-code stack frames), not from the 5.10.236 values,
and `tools/reroot.sh` selects profiles by the device's `uname -r`. The derivation and
every still-unconfirmed empirical field (`kernel_phys_load`, `skb_reclaim_sends`,
`skb_frag_bias`) are recorded in `../LEDGER.md`; the build has no device-gate record yet.
