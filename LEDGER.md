# LEDGER.md — investigation ledger

Append dated entries. Summaries at the top reflect the latest state; the journal below is the
authoritative history. Convention per AGENTS.md: read this before working in the repo.

## State summary (2026-10-28)

- Target device confirmed; second device quarantined.
- Target kernel is **vulnerable** to CVE-2026-43499 (verified at the exact build commit, source level,
  and in the device Image: `remove_waiter` at `0x1ea7a0` keeps the unpatched form).
- Build-exact profile for the target build **derived offline and written**
  (`profiles/5.10.209-…-ab12292661.{bin,conf}`): every symbol value comes from the device's own Image
  (kallsyms decode + three pointer-chase anchors), route geometry from the device's own bytes.
- Exploit binary now **built** on the remote machine, copied to `build/native/ghostlock`, and
  cross-checked against the source tree.
- Run prepared but **not executed**: `tools/reroot.sh --check` passes read-only preflight on the
  tablet; no push and no exploit execution has happened.
- Remaining gaps: device gate run (needs explicit authorization) to confirm the empirical fields
  (`kernel_phys_load`, `skb_reclaim_sends`, `skb_frag_bias`) and end-to-end success.

## Journal

### 2026-10-28 — Device inventory

- `adb devices -l`: two devices.
  - `a37b82` — `msm8916_32_512` — **DO NOT TOUCH** (user directive, recorded in AGENTS.md).
  - `e5778c5b` — `dizi` / `2405CRPFDC` (Redmi Pad Pro) — the target tablet.
- Target kernel (`uname -r`, read-only): `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661`.
- Boot state: `verifiedbootstate=green`, shell domain uid 2000, `sys.boot_completed=1`.
- **Mismatch:** bundled profile `profiles/…ab14313284.bin` targets `5.10.236-…-ab14313284`, a
  different build. Per project rules (exact-match required), it must not be used against this device.

### 2026-10-28 — Vulnerability verification at the exact build

Source-level verification against `kernel/common @ 4ea09a298bb4` (the commit embedded in the device's
uname) via googlesource `?format=TEXT`:

1. `kernel/locking/rtmutex.c` — `remove_waiter()` uses `current->pi_lock` / `current->pi_blocked_on = NULL`,
   i.e. the unpatched `8161239a8bcc` form. Fix `3bfdc63936dd` (2026-04-08) landed in v7.1 and was
   backported to 6.1.175 / 6.6.140 / 6.12.86 / 6.18.27, **never to 5.10**. → vulnerable.
2. `kernel/futex/core.c` at the same commit contains `futex_requeue` / `FUTEX_CMP_REQUEUE_PI`,
   calls `rt_mutex_start_proxy_lock(..., this->rt_waiter, this->task)` with the rollback
   `remove_waiter()` in the requeuer's context, and the `-EDEADLK` path that leaves `waiter->task`
   unarmed. → trigger path intact.
3. Device config (`/proc/config.gz`, saved to `/tmp/opencode/tab_config.gz`): `CONFIG_FUTEX_PI=y`,
   `CONFIG_RT_MUTEXES=y`, `CONFIG_SECURITY_SELINUX=y`, `CONFIG_DEBUG_INFO=y` + `DWARF4=y`,
   **no BTF** (`CONFIG_DEBUG_INFO_BTF` unset) — matches the profile comment that boot.img carries no
   embedded BTF.
- Note: source-level check proves the primitive is present; byte-level cross-validation against the
  actual device image (boot.img) is still open, per project gate methodology.

### 2026-10-28 — CI artifact availability

- ci.android.com for build **12292661**: "Artifacts not found for build 12292661" (rendered via
  Chromium MCP). The original profile used public CI build 14313284; that shortcut is unavailable
  for this build.
- Toolchain identity recovered from source: `build.config.common` at the commit pins
  **clang-r416183b** (`prebuilts-master/clang/host/linux-x86/clang-r416183b`); `Makefile` confirms
  `5.10.209`. → path forward is a hermetic rebuild from source, not CI artifacts.

### 2026-10-28 — Build machine (ResearchVM, root@192.168.104.201)

- SSH key auth works. Arch Linux, `Linux ResearchVM 7.1.8-arch1-3` (ironically patched; it is only
  a build host).
- **NDK present:** `/bigdata/android-sdk/ndk/29.0.14206865` (r29, clang 21, android21–35 targets).
- `pahole 1.31`, `git`, `ninja`, `bazel`, `python3` present. No `repo`, no `adb` on the VM.
- Disk: `/bigdata` 378 G total, **78 G free**.
- **Build performed:** repo synced to `/bigdata/redmi-root-build/`, `ANDROID_NDK_HOME=… ./build.sh`
  → `build/native/ghostlock` ✅ valid aarch64 PIE ELF, not stripped.
  - Run side stays on the workstation (adb here); pull the binary back or push it to the device.

### 2026-10-28 — OTA identified for the exact running build

- Device build identity (`getprop`, read-only): `V816.0.19.0.UNSCNXM`, `missi_pad_cn-user`,
  Android 14 (sdk 34), HyperOS 1 — i.e. **China HyperOS 1.0.19.0.UNSCNXM**.
- The 236 profile (`ab14313284`) belongs to a later HyperOS 3 build (3.0.307.0.WNSCNXM); the
  tablet's 209 kernel (`ab12292661`) shipped with 1.0.19.0. Confirms profile mismatch from the OTA
  side too.
- Official Recovery ROM for that exact version (via miuirom.org, mirrors = Xiaomi servers):
  `miui_DIZI_OS1.0.19.0.UNSCNXM_ec70c6dda2_14.0.zip`, 4.59 GB (content-length 4588769485),
  MD5 prefix `ec70c6dda2` — full MD5 verified at download completion.
  Mirror 1: `https://bn.d.miui.com/OS1.0.19.0.UNSCNXM/miui_DIZI_OS1.0.19.0.UNSCNXM_ec70c6dda2_14.0.zip`
- Download running on the VM → `/bigdata/dizi_root/firmware/`; browser cookies saved to
  `/bigdata/dizi_root/miuirom_cookies.txt`.
- After landing: extract `boot.img` (Xiaomi recovery zips ship the partition images directly; if
  VAB/super, use `lpunpack`), then unpack the Android boot header and get the kernel Image for
  byte-level cross-validation (`init_task.comm="swapper"`, `init_cred` caps, `remove_waiter`
  prologue, select/futex frame depths) — that is the authoritative source for the `offset` block.

### 2026-10-28 — DWARF build started (and one pitfall)

- First `make olddefconfig` failed: Kconfig evaluates `$(shell,$(LD) --version | scripts/ld-version.sh)`,
  and r416183b's generic `lld` driver prints "lld is a generic driver…" (exit nonzero) which
  surfaced as bogus "init/Kconfig:39: syntax error". Fix: use `LD=ld.lld` explicitly. Second run
  wrote `.config` cleanly.
- Build running on the VM: `ARCH=arm64 CC=clang LD=ld.lld LLVM=1` with clang-r416183b + device config,
  target `vmlinux`, log at `/bigdata/dizi_root/build-kernel.log`. Purpose: pahole field offsets;
  symbol addresses only as corroboration (link layout ≠ device Image).
- Second pitfall: device config has `CONFIG_TRIM_UNUSED_KSYMS=y`, and `scripts/gen_autoksyms.sh`
  demands the CI-only `abi_symbollist.raw` whitelist. Workaround for the offline DWARF rebuild:
  disabled `CONFIG_TRIM_UNUSED_KSYMS` in the working `.config`. Field layouts are unaffected by the
  autoksyms mechanism. Note: `CONFIG_LTO_CLANG` is NOT set in the device config (plain -O2 builds).
- Third pitfall: `CC=clang` without `CROSS_COMPILE` made clang default to the **host x86_64 target**
  (sp global-register error, 'I' constraint error on asm-offsets). Fixed by `CC="clang
  --target=aarch64-linux-gnu"` — GKI `build.config.common` uses `CLANG_TRIPLE=aarch64-linux-gnu-`,
  so this matches CI's effective target.
- Fourth pitfall: `CC="clang --target=..."` (space-joined flags) breaks Kbuild/Kconfig `--version`
  probes ("unknown assembler invoked", broken `.inst` → host binutils `as`). Working form: driver
  aliases via argv0 — symlink `binlink/aarch64-linux-gnu-clang -> clang` and use
  `CROSS_COMPILE=binlink/aarch64-linux-gnu-`; also alias `ar/nm/objcopy/objdump/...` from
  `llvm-*`, and LD points at `ld.lld` (generic `lld` alone is rejected). One misstep recorded:
  an attempted `-j defconfig` would have overwritten the device `.config` — it aborted before
  writing anything (Kconfig `$(CC)` probe wanted `aarch64-linux-gnu-gcc`); `.config` re-restored
  from `dizi_root/device.config` before the build.
- Build running with these aliases (log `build-kernel.log`); pahole runs on `vmlinux` when it exists.
- Fifth pitfall (resolved): a full-path clang driver alias passes `command -v` but fails Kconfig's
  `expr "$(CC)" : "clang"` string match, so `as-version.sh` treats it as binutils `as` →
  "Sorry, this assembler is not supported". The string `$(CC)` itself must read `clang`. Working
  recipe: `CC=clang` + `LD=ld.lld` on PATH, with target supplied as a separate command-line
  variable `CLANG_FLAGS="--target=aarch64-linux-gnu"` (preserved by the Makefile's `+=`), and
  `CROSS_COMPILE=binlink/aarch64-linux-gnu-` for the binutils-name tools. `LD` must keep the name
  `ld.lld` for lld's flavor detection. `.config` re-restored from `device.config` (autoksyms off).
- Sixth pitfall (resolved): `scripts/as-version.sh` in this tree probes the assembler via
  `-Wa,--version`; clang's integrated assembler only answers it when `-fintegrated-as` is explicitly
  among `$(CC) $(CLANG_FLAGS)` args (otherwise empty output → "this assembler is not supported").
  Run 1 passed Kconfig only because bare host-target `clang` answered GNU-style. Verified on this
  tree: `CLANG_FLAGS="--target=aarch64-linux-gnu -fintegrated-as"` → as-info `LLVM 0`, `.inst`
  as-instr probes pass. Full working recipe launched:
  `make ARCH=arm64 CROSS_COMPILE=binlink/aarch64-linux-gnu- CC=clang LD=ld.lld
   CLANG_FLAGS="--target=aarch64-linux-gnu -fintegrated-as"` with tool aliases in binlink.

### 2026-10-28 — Live calibration data already matching the profile

- `/proc/slabinfo` on the target: `mm_struct` `objsize=960 objperslab=34 pagesperslab=8` —
  **identical** to the `kernelsnitch` fields calibrated on the 5.10.236 profile. Confirmed, no gate
  work needed for `mm_struct_sz` on this build.

## What still must be derived for the new profile

Per `profiles/…ab14313284.conf`, the build-specific fields to re-derive for `ab12292661`:

- `task_struct` + `cred` field offsets → pahole on rebuilt vmlinux (clang r416183b + device config).
- `offset` block absolute symbols (`init_task`, `init_cred`, `selinux_enforcing`, …) → nm/System.map
  from the same rebuild.
- `route.select_stack.waiter_shift` → frame-depth proof from the real device Image (prologue
  disassembly is authoritative) and/or DWARF call graph. Stable .209→.236 backports could shift it;
  the old value (-2) does not transfer automatically.
- `kernel_phys_load` → assumed same (same device model) but **unconfirmed** for this build.
- `skb_reclaim_sends` / `skb_frag_bias` → empirical, gate-calibrated only; carried as presumed,
  must be confirmed by a gate run.
- `compact_waiter`, 5.10 layout notes (prio@0x40, no wake_state, size 0x50) → apply, but verify
  against this build's DWARF.

### 2026-10-28 — Device gate paused (user directive)

- Device `e5778c5b` is **actively in use by another agent** debugging graphics issues. Per explicit
  user directive: prepare everything but **do not execute the exploit**, and do no device work at all
  (read-only probes excluded too, to avoid interfering) until the user re-authorizes. Gate runs can
  panic the kernel — the risk is live right now. Standing state: no device interaction planned until
  explicit authorization.

### 2026-10-28 — OTA download complete and verified

- `miui_DIZI_OS1.0.19.0.UNSCNXM.zip` downloaded on the VM →
  `/bigdata/dizi_root/firmware/miui_DIZI_OS1.0.19.0.UNSCNXM.zip` (4588769485 bytes).
- MD5 = `ec70c6dda28ff46dfdb84d03cb5cef87` — filename hash prefix `ec70c6dda2` **confirmed**.
- Package is a VAB recovery OTA: only `payload.bin` (+metadata), no standalone partition images.
  `payload.bin` is stored uncompressed in the zip, but contains no `ANDROID!` magic → the `boot_a`
  content is not a raw contiguous block run (compressed blocks and/or patch ops against a base);
  needs a VAB payload reader per update_engine `Cr` header format.

### 2026-10-28 — waiter_shift encoding convention (code-level, settled)

- `select_stack_route.cpp`: `global_word = waiter_shift + waiter_word`, words counted from the
  `stack_fds` base in `core_sys_select`, `set_idx = global_word / words_per_set` (nfds=320 →
  5 words/set). Default `kernel::PSELECT_WAITER_WORD_SHIFT = -2` (`src/core/kernel/target.h:73`)
  applies only when no profile is loaded.
- Convention reproduces the 236 value: geometric `delta = waiter_slot − stack_fds_base` bytes,
  stored `waiter_shift = delta/8 − 2` (delta 0 → −2). For `ab12292661`, recompute delta from the
  real device Image prologues (`sub sp, sp, #imm` + sp-relative slots for the futex waiter and
  `stack_fds`), then encode with the same rule.

### 2026-10-28 — Derivation helper status (corrected)

- Upstream `tools/extract_rs/examples/` contains: `disasm_func.rs`, `extract_parts.rs`,
  `list_partitions.rs`, `make_test_payload.rs`, `symbols_near.rs` — the earlier assumed filenames
  (`dump_init_cred.rs`, `derive_select_shift_5x.rs`) do **not** exist upstream. All examples depend
  on the `ghostlock_extract` crate, which is not in this repo. Re-derive directly on the VM with
  `llvm-objdump` + `nm` on the rebuild `vmlinux`, and byte-match prologues against the device
  Image once extracted from the payload.

### 2026-10-28 — Payload format correction (it is `CrAU`, not VAB `Cr`)

- `payload.bin` hexdump shows magic **`CrAU`** — a classic major-version-2 payload, not a VAB `Cr`
  file (the earlier "Cr + u32" reading was misparsed; the first 4 bytes are `CrAU`). Layout per
  `update_metadata.proto` header comment: `CrAU` + u64 BE major + u64 BE manifest_size + u32 BE
  metadata_signature_size + manifest + metadata signature + data blobs + payload signature.
  Actual values (corrected by the hash-verified `payload_walk.py` run below, 2026-10-28): major 2,
  manifest_size **172493 (0x2a1cd)**, metadata_signature_size 267 → blobs start at payload offset
  **172784**. Boot partition ops: 24 `REPLACE_BZ` + 24 `REPLACE_XZ` (the earlier `BZh`×347 count
  was a scan-window artifact, not the op set).
- Field numbers used for the wire walk: `DeltaArchiveManifest` block_size=3, signatures_offset=4,
  signatures_size=5, minor_version=12, partitions=13; `PartitionUpdate` partition_name=1,
  new_partition_info=7, operations=8; `InstallOperation` type=1, data_offset=2, data_length=3,
  src_extents=4, dst_extents=6, data_sha256_hash=8; `Extent` start_block=1, num_blocks=2;
  `PartitionInfo` size=1. `REPLACE_BZ` = type 1, `REPLACE` = 0, `ZERO` = 6.
- Reader on VM: `/bigdata/dizi_root/payload_walk.py` (stdlib-only: struct/bz2/lzma/hashlib/mmap —
  no pip), verifies each op blob against `data_sha256_hash` to prove the data_offset base, then
  assembles `boot` partition ops → `/bigdata/dizi_root/firmware/boot_a.img`.
- Run result: all 48 boot-op hashes verified against blob_start base (`data_offset` is blob-section
  relative); boot ops = 24×REPLACE_XZ + 24×REPLACE_BZ, assembled 96 MB `boot_a.img`, `ANDROID!`
  header v4, kernel section 46,848,116 B at file offset 0x10000 — **uncompressed** kernel Image
  (`d503201f` head.S NOP padding; `swapper` present). `swapper` occurrences at seg offsets
  34059596, 34201284, 41473616; occurrences 1–2 are `.rodata` log strings ("parse stats\n\0swapper",
  "active_mm is swapper\n"); occurrence 3 is the embedded `init_task.comm` (pid/tgid 0,
  prio@132 = normal_prio@140 = 120, flags@0 = 8 = init_task static init ✓).
- **Data-section mapping proof:** static pointers inside `init_task` encode link-time vaddrs
  (DWARF domain), and the data region's file position sits 0xF000 below its DWARF addresses.
  `tasks@1224` value `0x279c388` = `D + 1224` where `D` = DWARF `init_task` = `0x279bec0`;
  `parent@1504`/`real_parent@1496` = `BASE + D` ✓. So the profile `offset` block must be recorded
  in DWARF domain (`data_alias` = `KIMAGE_TEXT_BASE + offset`), not raw file offsets, and pointer
  chase from `t` yields those directly. Confirmed device values (DWARF domain):
  **init_task = 0x279bec0 (41,533,120)**, **init_cred = 0x27b0ae0 (41,672,672)**,
  **root_task_group = 0x2992040 (43,602,240)** (via `sched_task_group@784`). Pending: `ref0/1/2`
  from cred content at `D − 0xF000`, and the remaining `offset` symbols
  (`empty_zero_page`, `selinux_enforcing`, `selinux_blob_sizes`, `security_hook_heads`,
  `slide_nfulnl_logger`, `slide_loggers_0_1`, `slide_boot_id`) — obtainable from the embedded
  kallsyms blob (the device data link layout differs from my rebuild: rebuild init_task
  DWARF = 0x1afcec0 vs device 0x279bec0, so rebuild values cannot be transferred).

### 2026-10-28 — Derivation work started (ResearchVM)

- `git fetch --depth 1` of an arbitrary SHA on googlesource fails ("couldn't find remote ref") —
  use the `+archive/<sha>.tar.gz` endpoint instead. Confirmed it also works for clang prebuilts
  (`+archive/refs/heads/master-kernel-build-2021/clang-r416183b.tar.gz`, the pattern community
  kernel builders use).
- Downloads running on the VM: kernel tree → `/bigdata/kcom-4ea09a298bb4/`, toolchain →
  `/bigdata/clang-r416183b/`.
- Note: clang 12.0.1 (r416183b) vs the VM's system clang 22 must not be mixed — DWARF layouts
  come from the r416183b build only.
- Caveat for the rebuild: struct field offsets are reproducible from the exact compiler + source +
  config, but absolute symbol addresses (the `offset` block) are link-layout artifacts; the CI link
  cannot be byte-for-byte reproduced, so symbol positions must come from the device's actual Image
  (pattern search / KernelSnitch anchors), with the rebuild only as corroboration. Cross-validation
  against boot.img remains mandatory.

### 2026-10-28 — waiter_shift frame-depth proof (rebuild corroboration; device byte-check pending)

- pahole on the rebuild `vmlinux` confirms **every** `task_struct`/`cred` offset in the 236 profile for
  this build (android12-9 5.10 struct layout unchanged .209→.236): prio@132, normal_prio@140,
  sched_task_group@784, tasks@1224, atomic_flags@1424, pid@1480, tgid@1484, real_cred@1912,
  cred@1920, comm@1936, seccomp@2120, pi_lock@2156, pi_waiters@2176, pi_top_task@2192,
  pi_blocked_on@2200; cred cap_permitted@48 (= `caps_offset`), user@128 / user_ns@136 /
  group_info@144 (= ref0/1/2), size 168; `mm_struct` DWARF size 952 → slab stride 960 ✓.
- `rt_mutex_waiter` (80 B): `tree_entry` rb_node {parent_color, rb_right, rb_left} @0,
  `pi_tree_entry` @24, task @48, lock @56, prio @64, deadline @72. `waiter_word 2` = tree word 0
  (parent_color) → confirms the `stored = delta/8 − 2` convention.
- Disassembly pitfall 7: `llvm-objdump` `--start-address/--stop-address` are parsed base-0, so the
  `0x` prefix is required (unprefixed → empty output); `--section=.text` required; LLVM 12 rejects
  `--disassemble=<sym>`.
- Rebuild call sites:
  - `core_sys_select`: frame `#448` (0x1c0 ✓); `stack_fds` base = `sp+0x50` (`add x20, sp, #80` on the
    no-kmalloc path, zero-fill `sp+0x50..0x140`, fd_set pointer array at `sp+0x20` pointing at
    `x20 + k·size`) — **same as 236**.
  - `futex_wait_requeue_pi`: frame `#416` (0x1a0 ✓); waiter base = `sp+0x90` (passed to
    `rt_mutex_init_waiter`, `rt_mutex_wait_proxy_lock`, `rt_mutex_cleanup_proxy_lock`) — **same as 236**.
  - `__arm64_sys_pselect6` `#160` (0xa0 ✓), `__arm64_sys_futex` `#112` (0x70 ✓).
  - `do_futex` here is `#96` (0x60), **not** the 0x90 in the 236 proof. If the device Image agrees:
    delta = waiter − stack_fds = (−0x70−0x60−0x1a0+0x90) − (−0xa0−0x1c0+0x50) = +48 → stored
    `waiter_shift = 48/8 − 2 = 4` (candidate). The 15-word fd window covers waiter field-words 0..7 at
    window words 6..13 ✓. **Resolve against the real device Image prologues before trusting either value.**

### 2026-10-28 — Profile derived for ab12292661 (device Image kallsyms; gate run still pending)

**Source of truth = the device's own Image.** CI build 12292661 has no artifacts, and the hermetic
rebuild turned out *not* to be byte-identical to the CI build (see below), so every absolute value in
the new profile comes from the Image extracted from the OTA payload (`boot_a.img` kernel section,
46,848,116 B at partition offset 0x10000). File offset = DWARF address − `0xF000` for **both** text
and data (verified against `remove_waiter`'s full prologue: `hint #25; str x30,[x18],#8;
stp x29,x30,[sp,#-64]!; …` appears exactly at 0x1db7a0 = 0x1ea7a0 − 0xF000).

**kallsyms decode (5.10 layout).** `kallsyms_relative_base` (u64 == `0xffffffc008000000`) at
`0x1e29ee8`; `num_syms = 142102` at +8; offsets array start `S = 0x1d9f290` (u32, monotonic,
`[0] = 0`); names blob `B = 0x1e29ef8`; markers `0x201d120` (556 entries, all consistent); token table
`0x201d9d0`; token index `0x201dd88` (the u16[256] equals the cumulative string starts exactly).
Entry = length byte + token bytes; **the expansion's first character is the symbol type char and must
be stripped**. Two wrong turns worth remembering: tokens are *not* limited to 2 chars (`__kmod_`,
`android_`), and comparing `bytes` names against a `str` target list silently matched nothing.

Cross-check: index 124597 → `init_task` = `0x279bec0` (equals the pointer-chase value), 125823 →
`init_cred` = `0x27b0ae0`, 139987 → `root_task_group` = `0x2992040` → decode proven correct.

**Device build ≠ my rebuild for code.** `remove_waiter` is byte-identical (10 instructions), but
`__arm64_sys_futex` / `do_futex` are not: device `sub sp, sp, #0x90` / `#0x70` vs rebuild `#0x70` /
`#0x60`. Frame sizes were therefore re-derived **from the device bytes** at the kallsyms offsets
(file = DWARF − 0xF000):

| function | device frame | landmark |
| --- | --- | --- |
| `__arm64_sys_pselect6` | `#0xa0` | `add x29, sp, #0x40` |
| `core_sys_select` | `#0x1c0` | `stack_fds = add x21, sp, #0x50` |
| `__arm64_sys_futex` | `#0x90` | — |
| `do_futex` | `#0x70` | `add x29, sp, #0x40` |
| `futex_wait_requeue_pi` | `#0x1a0` | `waiter = add x27, sp, #0x90` |
| `remove_waiter` | `#0x40` | unpatched prologue |

Absolute stack positions: pselect `−(0xa0+0x1c0)+0x50 = −0x210`; futex
`−(0x90+0x70+0x1a0)+0x90 = −0x210` → **delta 0** → `waiter_shift = 0/8 − 2 = −2`, identical to the
236 profile. The earlier candidate `4` is **withdrawn**: it relied on the rebuild's `0x60/0x70`
wrapper frames, which the device does not have.

**offset block (device Image, DWARF domain = vaddr − `0xffffffc008000000`):**

| field | value | symbol |
| --- | --- | --- |
| `init_task` | 41533120 (`0x279bec0`) | `init_task` |
| `init_cred` | 41618144 (`0x27b0ae0`) | `init_cred` |
| `empty_zero_page` | 43569152 (`0x298d000`) | `empty_zero_page` |
| `root_task_group` | 43589696 (`0x2992040`) | `root_task_group` |
| `selinux_enforcing` | 44309400 (`0x2a41b98`) | `selinux_state` +0 (`bool enforcing` is field 0; `CONFIG_SECURITY_SELINUX_DISABLE` unset, no RANDSTRUCT per pahole) |
| `selinux_blob_sizes` | 36632184 (`0x22ef678`) | `selinux_blob_sizes` |
| `security_hook_heads` | 36630504 (`0x22eefe8`) | `security_hook_heads` |
| `slide_nfulnl_logger` | 41489312 (`0x27913a0`) | `nfulnl_logger` |
| `slide_loggers_0_1` | 41489096 (`0x27912c8`) | `loggers` (`nf_logger *loggers[NFPROTO_NUMPROTO][NF_LOG_TYPE_MAX]`) |
| `slide_boot_id` | 44436405 (`0x2a60bb5`) | `sysctl_bootid` (not `random_boot_id_data`; 236's value is likewise odd and .bss-adjacent) |

Cross-check vs 236: every value is within ±`0x6A08` of the 236 value; the cred refs below are exactly
`+0x80` shifted from 236's with `group_info` still pinned at `init_cred+0xA8` — consistent geometry.

**Cred template.** Device `init_cred` content (file `0x27a1ae0` = DWARF − 0xF000): `usage@0 = 4`
(matches `kernel/cred.c: .usage = ATOMIC_INIT(4)`), `uid@4 = 0`, caps at 48/56/64 =
`0x1ffffffffff` (permitted/effective/bset), refs at 128/136/144 =
`0xffffffc00a7af660` / `…a7af6f8` / `…a7b0b88` → profile `ref0/1/2_image` =
−274702076320 / −274702076168 / −274702070904.

**Profile written and verified.** `profiles/5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661.bin`
(1993 B) was generated in the 236 layout (only build-specific values replaced) and validated by
compiling `src/core/profile/binary.cpp` into a host harness: `parse()` returns every expected value
and `serialize()` reproduces the file **byte-identically** (SHA-256
`c343b7e1157617c48c776ea0413d905c9d9558999bee3d270d8e781989213953`). The matching `.conf` documents
provenance, geometry and the unconfirmed fields.

**Reroot script.** `tools/reroot.sh` no longer hardcodes the 236 profile: it resolves
`profiles/$(adb shell uname -r).bin` per device and refuses to run when that file is absent
(build-exact, no fallback to another build). `build/native/ghostlock` has to be copied back from the
VM before a run.

**Still unconfirmed (gate-only):** `kernel_phys_load = 0xa8000000` (bootloader-owned, same device
model) and `skb_reclaim_sends = 16` / `skb_frag_bias = 384` (same 5.10 unix-sendmsg code path). No
gate run has been authorized or performed; nothing has been pushed to the tablet.

Correction to the entry below: the rebuild is a struct-layout oracle only — it must not be used for
absolute values *or* for code bytes/frames.

### 2026-10-28 — Repository handoff: English documentation, branch, no device work

Translated the repository's user-facing documentation and messages to English on a new branch
(`feat/dizi-5.10.209-profile-en`): `README.md`, `DISCLAIMER.md`, `docs/tutorial.md`,
`docs/adaptation-plan.md`, `docs/device-gate-DIZI-01.md`, the comments/echo text in `build.sh` and
`tools/reroot.sh`, and the one Chinese string in `src/Makefile`'s `product` target. No code paths,
profile bytes or script logic changed; `bash -n` passes for both scripts and no CJK remains in the
tree.

Deliberate content updates made while translating (not merely wording):

- README now lists **both** supported builds and states explicitly that the 5.10.209 profile has no
  device-gate record yet; it also documents that `reroot.sh` selects the profile from `uname -r`
  and refuses other builds.
- `docs/tutorial.md` embeds the current `reroot.sh` (including `resolve_profile`) instead of the old
  hardcoded-236 version, and shows the new English console output.
- `docs/adaptation-plan.md` gained a short addendum pointing at this ledger for the 5.10.209
  derivation.
- `reroot.sh` output strings are now English (`== ROOTED + KernelSU active ...`), so any external
  notes matching the old Chinese strings no longer apply.

No adb command was run against either device during this work.

### 2026-10-28 — Gate run staged (binary + script), preflight only, nothing executed

**Binary staged.** Copied `/bigdata/dizi_root/redmi-root-build/build/native/ghostlock` to
`build/native/ghostlock` (2,602,168 B, SHA-256
`14cb155faafee0e48d9b3e75b07a6daa5e8217515778ebd127f0b45fe5c0ba4f`, aarch64 PIE built with NDK
r29, targets Android 35). The VM build tree's `src/` is byte-identical to this repo's `src/`
(125 files compared by SHA-256) except `src/Makefile`, which differed only in the `product`
target's echo string translated today; the VM copy was updated to match. So the binary corresponds
to the source that produced the 5.10.236 gate build, and `build/` stays git-ignored.

**Script hardened for this bench.** `tools/reroot.sh` now (a) targets one device via
`SERIAL`/`ANDROID_SERIAL`, aborting when several devices are attached and none was named — every
adb call goes through `-s <serial>`; (b) refuses to proceed unless `ro.product.device` is `dizi`
(`ALLOW_ANY_DEVICE=1` overrides); (c) gained `--check`, a read-only preflight that prints device
identity, kernel release, SELinux state, profile selection and both SHA-256s without pushing or
executing anything. `bash -n` passes.

**Bench state.** Both devices remain attached: `a37b82` (msm8916, untouched — no command was ever
sent to it) and `e5778c5b` (target). `SERIAL=e5778c5b tools/reroot.sh --check` output:

- model `dizi` / `2405CRPFDC`, OS1.0.19.0.UNSCNXM, Android 14, patch 2024-12-01
- `uname -r` = `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` → resolves to the new profile
- SELinux `enforcing=1` (not rooted, no KernelSU)
- profile 1993 B SHA-256 `c343b7e1157617c48c776ea0413d905c9d9558999bee3d270d8e781989213953`

**Deliberately not done:** no push to `/data/local/tmp`, no execution of `ghostlock`, no state
change on the tablet. Waiting for explicit authorization for the gate run (expect reboots; a miss
panics the kernel).

## Open items / next actions

1. ✅ On ResearchVM: `kernel/common` @ `4ea09a298bb4` fetched, clang-r416183b downloaded, vmlinux
   rebuilt with the device `.config` (struct-layout oracle only — not byte-identical to the CI build).
2. ✅ OTA obtained and `boot_a.img` / raw Image extracted; kallsyms decoded from the Image and
   cross-checked against three pointer-chase anchors; offset block, cred refs and select/futex frame
   geometry verified against the device bytes.
3. Derivation helpers were not reimplemented as Rust tools; values were derived directly from the
   Image with stdlib Python and cross-checked three ways (kallsyms anchors, relative geometry vs the
   236 profile, pointer-chase content). A future re-derivation must assert the same anchors.
4. ⏳ Confirm the empirical fields via a device gate run (`kernel_phys_load`, `skb_reclaim_sends`,
   `skb_frag_bias`); panics/reboots expected; requires explicit user authorization.
5. The new profile is derived and build-exact but **not gate-verified** — record a cold-boot PASS here
   before treating it as production-ready.

## Constraints reminder

- Never touch `a37b82`.
- Device interactions read-only until gate authorization.
- No profile use across builds.
- **VM workspace convention:** everything fetched, downloaded, or built on ResearchVM goes under
  `/bigdata/dizi_root/` (the NDK may be reused from `/bigdata/android-sdk/ndk/29.0.14206865` in
  place). Exception for the two already-running downloads: their paths were baked in before the
  convention was set, so their outputs (`kcom-4ea09a298bb4`, `clang-r416183b`, plus the tarballs)
  must be moved into `dizi_root` after completion.
