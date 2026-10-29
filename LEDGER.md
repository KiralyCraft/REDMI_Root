# LEDGER.md — investigation ledger

Append dated entries. Summaries at the top reflect the latest state; the journal below is the
authoritative history. Convention per AGENTS.md: read this before working in the repo.

## State summary (2026-10-29)

- Target device confirmed; second device quarantined.
- Target kernel is **vulnerable** to CVE-2026-43499 (verified at the exact build commit, source level,
  and in the device Image: `remove_waiter` at `0x1ea7a0` keeps the unpatched form).
- Build-exact profile for the target build **derived offline and written**
  (`profiles/5.10.209-…-ab12292661.{bin,conf}`): every symbol value comes from the device's own Image
  (kallsyms decode + three pointer-chase anchors), route geometry from the device's own bytes.
- Exploit binary **built** (`build/native/ghostlock`) and **gate run 6 PASS** (2026-10-29): temporary
  uid-0 root on `dizi` via the userspace `ghostsu` agent (no KernelSU), SELinux permissive until
  reboot. Empirical fields (`kernel_phys_load`, `skb_reclaim_sends`, `skb_frag_bias`) remain
  unconfirmed; a second cold-boot pass is still open.
- **Unlock attempt FAILED (2026-10-29, 09:48 EET):** an authorized ordinary-only edit of
  `devinfo[13]` from 0 to 1 (critical byte 14 kept 0) passed full 4096-byte readback before reboot.
  After reboot, the correct tablet's bootloader still reports `Device unlocked: false` and
  `unlocked: no`. **Stopped before wiping.** Earlier claims that this writable blob alone is a
  concrete unlock path are superseded; the VB protocol's authoritative backing/storage behavior
  is not a direct raw-partition mapping. A diagnostic return to stock Android has since passed:
  boot complete, slot `_a`, green/locked. The raw post-reboot `devinfo` bytes still await root
  readback. No firmware/GPT flashing, userdata/metadata wipe, EDL entry or custom RAM boot was
  performed.
- **VB provider recovered offline:** exact OTA `VerifiedBootDxe` implements the GUID/callback
  ABL uses. It chooses Keymaster/RPMB storage on the secure path (`0x202` read, `0x203` write),
  with raw GPT `devinfo` as the non-secure/permitted fallback path. This explains why a writable
  layout-matching partition alone cannot establish an unlock. Runtime readback/active UEFI
  cross-check is pending; no secure-storage or additional unlock write has been attempted.
- **Fallback is not forceable (2026-10-29):** the store selector is
  `(scm_fuse_state & 0x8703) == 0` and the `devinfo` fallback additionally requires bit `0x20`
  set (`0x8723` mask). Both inputs come from the read-only SCM SIP call `0x2000604`; no partition,
  EFI variable or property feeds them. Corrupting the blob magic merely re-derives a locked state
  from TZ. The only supported path is Xiaomi's MiToken-verified `oem unlock`, which sets ordinary
  **and** critical unlock and wipes. Bit `0x20` semantics are unconfirmed.
  `docs/bootloader-unlock-DIZI.md` §4.5.
- **Latest gate run did not root:** the 2026-10-29 diagnostic `reroot.sh` run timed out (12
  attempts, W1 ok, W2 never landed), so the tablet is booted stock, green/locked, unrooted, and the
  post-reboot `devinfo` readback remains outstanding.
- **Unlock side effects analysed (2026-10-29, read-only):** the `devinfo` write itself is low-risk
  (a corrupt magic re-inits from the TZ secure-state default, expected locked; a read/write failure
  is a boot-entry error). The skipped
  official `misc` wipe is the main open question: `/data` is metadata-encrypted with a
  Keymaster-wrapped key, and if the lock-state change invalidates it the device cannot mount
  `/data` (soft brick until a factory reset). Code evidence favours key survival but is
  **unconfirmed**. A clean reset was authorized but **not executed**, because the ordinary unlock
  attempt failed its post-reboot verification. Do not wipe or retry on the assumption that the
  tablet is unlocked. Details in the 2026-10-29 execution entry and
  `docs/bootloader-unlock-DIZI.md`.

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

### 2026-10-28 — Gate run 1 (5.10.209): W1 + W2 pass, KernelSU was missing, harness hang

Authorized gate run of the new profile on `e5778c5b`. Results, in order:

1. **W1 passed on the first attempt** (21:35:34). `/sys/fs/selinux/enforce` went to 0 and stayed 0
   for the rest of the session (no panic, no reboot at any point).
2. **W2 passed too**: the root script ran as `uid=0 euid=0` with `Seccomp: 0`, the SELinux policy
   fixup worked (`policyload before=0 after=2`, `policy fixup rc=0`), and `/proc/iomem` was cached
   (11258 B). The victim child was parked (`ghostleaf_01234` in `rt_sigsuspend`, i.e. the deliberate
   `pause()` parking after a successful cred overwrite).
3. **Root still failed** because **no KernelSU manager was installed**: the root script reported
   `ksud=/data/adb/ksu/bin/ksud`, `ksud_file=` (empty) and `[!] ksud missing; cannot late-load`,
   then exited 1. With the handoff aborted, the parked child was never signalled (`root_child_frontend`
   tears it down only at the late-load teardown), so it kept the adb shell's stdout open and
   `reroot.sh` blocked forever on that iteration. That is the "stuck on attempt 1, no reboot"
   symptom: it was not a stalled exploit, the exploit had already succeeded through W2.
4. **`kernel_phys_load` is now confirmed**, not inferred: the cached `/proc/iomem` shows
   `a8000000-aa47ffff : Kernel code` (and `808f4000-808fffff : System RAM` first), so
   `kernel_phys_load = 0xa8000000` with `kernel_phys_offset = null` (default 0x80000000) is correct
   for this build. `skb_reclaim_sends` / `skb_frag_bias` remain unconfirmed until a full pass.

Remediation before the next attempt (no profile change):

- Installed KernelSU v3.3.1 (`KernelSU_v3.3.1_32680-release.apk`, package `me.weishu.kernelsu`) and
  pushed its `lib/arm64-v8a/libksud.so` to `/data/local/tmp/ksud` (mode 755) as the root script's
  fallback ksud. v3.3.1 embeds the `android12-5.10_kernelsu.ko` LKM, which is the KMI this kernel
  reports (`android12-5.10`).
- Hardened `tools/reroot.sh`: per-try progress lines, a 240 s bound on every exploit invocation, and
  stray-process reaping (`ghostlock`, `ghostleaf`) before/after each attempt. The child parking is by
  design, so the harness — not the exploit — has to cope with a failed handoff.

### 2026-10-28 — Gate runs 3–5 (authorized, instrumented driver; in progress)

Post-remediation runs after installing KernelSU + pushing ksud (all on `e5778c5b` only):

- **Run 3** (22:39–22:46, `tools/reroot.sh`, log `/tmp/opencode/gate-209-run3-223947.log`): 6 attempts,
  W1 hit 1/6, one W2 try, panics.
- **Run 4** (22:48–22:52, instrumented driver): 4 attempts, 0/4 W1 hits — panics during the race.
- **Run 5** (22:53–00:55, instrumented driver with full stdout capture, log `/tmp/opencode/gate-209-run5.log`):
  87 attempts. **W2 does land** — see the correction below — so the geometry is not the blocking part.
  Collision screens report 9/7–14/7 (passing, but unstable relative to the expected 7-slot geometry);
  `skb_reclaim_sends=16`/`skb_frag_bias=384` remain **unconfirmed** and **not falsified** (Run 1 landed
  once with the same profile). `kernel_phys_load=0xa8000000` self-confirms on every attempt.

#### 2026-10-29 — correction: W2 lands, root is still not reached, and the blocker is the LKM load

Read-only re-reading of the run-5 log and the device contradicts the earlier "zero landings" reading:

- `grep -c "root script start uid=0" gate-209-run5.log` = **7**. The landed child's root script executed
  as `uid=0 euid=0` with `Seccomp: 0`, completed the policy fixup (`policyload before=0 after=2`,
  `policy fixup rc=0`) and cached `/proc/iomem` (11258 B). So the write lands; `verify_w2_stage`
  reporting `child uid = 2000` is a **false negative** — it reads the child before the cred overwrite is
  observable, so runs were misclassified as misses.
- Every landing ran `ksud late-load --kmi android12-5.10 --allow-shell`, which **exited 0 with no
  output** and the module never appeared in `/proc/modules` during the 5 s watch →
  `[!] KernelSU module not loaded`. Root is therefore not established. Device state at 07:40:
  `su` not found, `grep -c kernelsu /proc/modules` = 0, `/sys/fs/selinux/enforce` = 1.
- **Why late-load cannot work on this build** (from the pushed `lib/arm64-v8a/libksud.so`, KernelSU
  v3.3.1, PIE aarch64): `late-load` (`ksud::late_load`) is implemented through the **KernelSU driver**
  (`anon_inode:[ksu_driver]`, `ksu_driver_su`, string `KernelSU driver install syscall was blocked by
  seccomp`) — it has no `finit_module`. On a stock kernel with no KernelSU driver there is nothing for
  it to trigger, which matches the observed silent exit 0. This binary also has no `--kmi` string, so the
  flag the handoff passes is probably not recognized by this build either.
- Two ways forward, neither yet attempted: (1) extract the embedded `android12-5.10_kernelsu.ko` from the
  manager APK assets and load it from the uid-0 context with `finit_module`/`init_module` directly;
  (2) `ksud boot-patch` the boot image and write `boot_a` — which requires the lock state to be flipped,
  i.e. it depends on the unauthenticated ABL device-info blob recorded above.


### 2026-10-28 — Bootloader (XBL/ABL) hunt: the ABL volume *does* decode, and the unlock path is enumerated

Offline work only, from the OTA payload (`/bigdata/dizi_root/firmware/`, local working copies in
`/tmp/opencode/ghidra/`). Nothing was read from the device for this.

**Correction to the earlier "ABL payload is undecodable" note.** That was a framing error, not an
encryption obstacle. The compressed FV data at LOAD-segment offset `0x78` is a plain
LZMA-alone stream — props `0x5D` (lc=3, lp=0, pb=2), dict size `0x1000000`, declared unpacked size
`0xE00C8` — and Python's `lzma` decodes it cleanly with `FORMAT_ALONE`. The result is a
917,704-byte firmware volume (`/tmp/opencode/ghidra/abl_09fa00000_fv.bin`). `imagefv` also reports
an LZMA-alone header but its output is almost all zeros with no modules in it, so it is not usable.

What the decoded ABL volume contains:

- One PE32 module, machine `0xAA64` (AArch64), entry RVA `0x1000`, name `LinuxLoader` in its entry
  header (DataLength `0x9AA78`), followed by a large trailing data region (~290 KB) that holds the
  string tables.
- **Fastboot server command table**: `getvar:`, `flashing get_unlock_ability`, `oem unlock`,
  `oem lock`, `oem device-info`, `oem allow-wipe-userdata`, `oem edl`, `oem erase-vb-index`,
  `oem fbreason`, `oem uart-enable`, `oem getguid`.
- **Token path**: `Error Locate MiToken Protocol: %r`, `Error Get Token Length: %r`,
  `Token Length: %d`, `Error Get Token: %r`, `token`, `Token Verify Failed, Reboot the device`,
  `Edl Token Verify Failed`.
- **Unlock state writes**: `IsAllowUnlock is %d`, `Error Set Device Unlock: %r`,
  `Failed to update the unlock status`, `Error Set Device UnlockCritical: %r`,
  `Unable set the unlock value: %r`, `Unable set the unlock critical value: %r`,
  `Device unlocked: %a`, `Device critical unlocked: %a`, `get_unlock_ability: %d`,
  `the Unlock status is : %d`, `After Unlock user write, the stored_rollback_index is : %d`,
  `VB Reset Device State error: %r`, `RwDeviceState Re…turned error: %r`.
- **AVB / boot state**: `State: Unlocked, AvbSlotVerify returned %a, continue boot`,
  `assert fail: ops->read_is_device_unlocked != NULL`,
  `KeyMasterSetRotAndBootState: SetFuse (TZ_HLOS_IMG_TAMPER_FUSE)`,
  `… (TZ_HLOS_TAMPER_NOTIFY_FUSE)`.

Reading of this evidence (inferences, not device-verified):

1. **The lock state is a value that ABL writes at runtime** (`Unable set the unlock value`,
   `… the unlock critical value`, `Error Set Device Unlock`), and the fuses are a *separate*
   mechanism (`SetFuse (TZ_HLOS_IMG_TAMPER_FUSE)` is the root-of-truth / tamper-notify fuse, not the
   unlock flag). This matches the GBL observation that `is_unlocked` / `is_unlocked_critical` are
   variables rather than fuses.
2. **The unlock decision itself is still server-signed.** Token verification is delegated to
   TrustZone (`SecFuseLib.c`, `computeAndVerifyECDSA failed`, `verifyECDSACertificate failed`); the
   earlier `FUN_a702ad24` / `FUN_a702ae48` wrappers are thin SMC trampolines. So there is no
   offline-forgery route visible in ABL — the RSA-2048 server signature remains the gate. What
   ABL controls locally is only *where* the answer is stored and whether `IsAllowUnlock` permits it.
3. **There is no EDK2 variable store on this build.** The EDK2 variable-store signature
   (`0x5A5B6176`) is absent from `abl.img`, `imagefv.img`, `tz.img`, `xbl.img`, `xbl_config.img`,
   and the payload partition list has no `efisp`/variable-store partition. So the GBL-style
   "drop a UEFI app that sets the variable" trick has no variable store to write to on dizi; the
   state must live in some QCOM-side store (RPMB / `RwDeviceState` blob / `featenabler` /
   `qweslicstore`) — **which one is unconfirmed**.

**The handler is now read.** The earlier blocker was a parsing mistake, not a missing module: the
entry-header `DataLength` (`0x9AA78`) is not the module size. The PE section table shows `.text` at
raw pointer `0x1000` with raw size `0xBA000`, `.data` `0x24000`, `.reloc `0x1000` — so the whole
decoded volume is one module, and the "string pool" is inside `.text`. Re-imported whole
(`/tmp/opencode/ghidra/abl_full.efi`, 917,504 bytes), Ghidra resolves cross-references. Handler map
(program `abl_full.efi`, 1,344 functions):

- `FUN_0005ad20` — fastboot init. Looks up partition `frp` and takes **the last byte of the FRP
  partition & 1 as `IsAllowUnlock`** (`Error Reading FRP partition: %r`, `IsAllowUnlock is %d`).
- `FUN_0005db28` — the unlock command path: locate MiToken protocol → get token length → get token →
  verify; failure prints `Token Verify Failed, Reboot the device`; success calls `FUN_00048908(0,1)`
  then `FUN_00048908(1,1)`.
- `FUN_00048908(index, value)` — index 0 → `FUN_00048e10` (unlock), index 1 → `FUN_00048ee8`
  (unlock-critical). Each sets one byte inside a **0x998-byte device-info blob** whose magic is
  `ANDROID-BOOT!` (flags at blob offsets 13, 14, 15 = unlock, unlock-critical, charging-screen), then
  persists the blob with `FUN_00030ad8(1, blob, 0x998)` (`VBRwDevice`). Failure prints
  `Unable set the unlock value: %r`. It also writes 0x440 bytes to the **misc** partition
  (GPT type GUID `82ACC91F-357C-4A68-9C8F-689E1B1A23A1`) with the `--wipe_data` recovery command.
- `FUN_000493a0` — state init. VB read of the blob; **if the magic matches, the stored bytes are used
  as the authoritative state with no integrity or signature check**. Only when the magic mismatches is
  the state re-derived from the TrustZone secure state (`FUN_00031870`, the SMC wrapper that returns
  `(state>>2 ^ 0xff)&1`) and then written back.
- `FUN_000486d8` / `FUN_000486e8` / `FUN_00048708` — the three flag getters. The AVB path
  (`FUN_0000b3e8`) uses the unlock flag to add `AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR` and to
  set `androidboot.verifiedbootstate` (orange when unlocked, `State: Unlocked, AvbSlotVerify returned
  %a, continue boot`).
- The fastboot flash/erase handlers refuse in locked state (`Flashing is not allowed in Lock State`,
  `Flashing is not allowed for protected Partitions`), so fastboot alone cannot write the blob.

Reading: **the server signature gates the *command*, not the *storage*.** Nothing in ABL authenticates
the persisted blob — the unlock flag is a writable byte in an unauthenticated structure, and the TZ
state is only a fallback default when the blob's magic is absent. That is the concrete offline
candidate: write `ANDROID-BOOT!` + byte 13 = 1 into the blob directly (from Android root through the
block device), reboot, and ABL reports unlocked with AVB verification errors tolerated. The fastboot
`IsAllowUnlock` flag is likewise just the last byte of the FRP partition.

Still unconfirmed: **which partition the VB protocol's blob actually lives in** (the protocol producer is
a DXE driver not present in the decodable volume; `frp` is the strong candidate because the fastboot
path reads it, but the code path uses a GUID, not a name). Read-only device check that settles it: dump
the FRP/persist/misc partitions, look for `ANDROID-BOOT!` at offset 0 and read byte 13.

Independent confirmation from `dev-zetta/xiaomi_redmi_pad_unlocker` (Redmi Pad SE, `xun`): the
Qualcomm ABL argument-injection flaw (`fastboot oem set-gpu-preemption`, accepts
`androidboot.selinux=permissive`) is confirmed working there, chained with the HyperOS
`miui.mqsas.IMQSNative` binder service to run a command as UID 0 during that one permissive boot.
That project explicitly does **not** bypass Mi Unlock's server authentication — it only bypasses the
Community quota. For dizi the permissive-boot half is already covered by the kernel route, so the
remaining barrier is the server signature plus the location of the lock flag.

### 2026-10-29 — Temporary adb root without KernelSU (userspace `ghostsu` agent)

Run 5 proved the race lands (7 uid-0 executions, "child is root!"), and that the only
failing step is the module handoff: `ksud late-load` exits 0 with no output and never
loads anything on this kernel. Pivot: do not depend on KernelSU for the temporary root.

**Verified on `dizi` (read-only), module-loading configuration** (`zcat /proc/config.gz`):

| option | value | consequence |
| --- | --- | --- |
| `CONFIG_MODULES` | `y` | modules can be loaded at all |
| `CONFIG_MODULE_SIG` | **not set** | unsigned modules are *not* rejected by signature |
| `CONFIG_MODULE_FORCE_LOAD` | not set | `finit_module` honouring the force flag |
| `CONFIG_MODVERSIONS` | `y` | CRC check; bypassable with `MODULE_INIT_IGNORE_MODVERSIONS` |
| `CONFIG_CFI_CLANG` / `CONFIG_LTO_CLANG_FULL` | `y` / `y` | the kernel calls module code through CFI-instrumented indirect calls |
| `CONFIG_CFI_PERMISSIVE` | not set | a CFI mismatch panics instead of warning |
| `CONFIG_KPROBES`, `CONFIG_KALLSYMS_ALL` | `y`, `y` | KernelSU-style LKMs have their prerequisites |

So the earlier "signature will block a custom .ko" concern is wrong — signatures are off.
The real constraint is CFI: the VM oracle tree was built `CONFIG_LTO_NONE` and *without*
`CONFIG_CFI_CLANG` (device vs VM `.config` differ only in the CFI/LTO block), so a module
built from that tree has no CFI preamble and the loader's indirect call into
`mod->init` would trap. A custom `.ko` therefore needs a CFI+LTO build, not attempted
here; recorded as **unconfirmed** and left as an option.

**Also verified:** `security_load_policy()` in the exact build tree
(`security/selinux/ss/services.c`) never assigns `selinux_state.enforcing`, so the
exploit's W1 permissive state survives the handoff script's policy reload. A userspace
agent started at handoff therefore runs with SELinux permissive until reboot.

**Implementation (this repo):**

- `src/tools/ghostsu.cpp` — one small binary with two roles. `--agent` keeps the rooted
  handoff's uid-0 authority alive and serves commands over the abstract unix socket
  `ghostsu.v1`; the client runs `-c <cmd>` (framed stdout/stderr + exit status) or an
  interactive pty shell; `--ping` probes liveness. The agent re-asserts `enforce=0` on
  start and per request, sets `oom_score_adj=-1000`, and lives in its own session so it
  outlives the exploit. Built as `build/native/ghostsu` (`make -C src ghostsu`).
- `tools/ksud-agent-shim.sh` — pushed to `/data/local/tmp/ksud`. The rooted script
  already executes that path as uid 0 (`ksud late-load --kmi ... --allow-shell`); the
  shim starts the agent there and then chains to the real ksud saved as `ksud.real`.
  No rebuild of the proven exploit binary was needed: `build/native/ghostlock` was
  restored from the device and is byte-identical (sha256 `14cb155f…`).
- `tools/reroot.sh` — pushes the agent, installs the shim (preserving a real ksud), and
  treats `/data/local/tmp/su -c id` as the success criterion (`root_id`), falling back to
  KernelSU's `su` if present.

**Dry test on the device (unprivileged, no exploit):** the shim starts the agent,
`ghostsu --ping` returns 0, and `/data/local/tmp/su -c id` returns the caller's identity
through the socket (`uid=2000` in the unprivileged test, as expected). The interactive
pty path was exercised on the host build (echo, command output, exit status).

**Build note:** the local NDK 27 defines `PAGE_SIZE` as a macro and broke the exploit
build; `src/core/kernel/constants.hpp` now `#undef`s it. The known-good binary was built
with **NDK 29.0.14206865 on ResearchVM** (`/bigdata/android-sdk/ndk/29.0.14206865`, clang
21.0.0) — use that toolchain for any exploit rebuild, to keep codegen comparable.

**Gate run 6** (`/tmp/opencode/gate-209-agent-run6.log`) — **PASS**, temporary root
reached on attempt 9 / W2 try 1 (08:06, cold boot, `e5778c5b` only):

```
== ROOTED (attempt 9, try 1)
uid=0(root) gid=1514833792(u15148_a3792_ext) groups=1514833792(...) context=u:r:kernel:s0
Uid: 0 0 0 0
Gid: 1514833792 1514833792 1514833792 1514833792
CapEff: 000001ffffffffff
```

- The rooted handoff script ran as uid 0, the `ksud` shim logged
  `[*] ghostsu agent running: /data/local/tmp/su -c id`, and `.ghostsu.log` records
  `[*] agent start uid=0 label=u:r:kernel:s0`.
- `/data/local/tmp/su -c id` → `uid=0(root)`, `CapEff=000001ffffffffff`; `ls /data/misc/keystore`
  and `dmesg` (as root) work; the device stays permissive (`enforce=0`, AVC denials show
  `permissive=1`) until reboot.
- Interactive path verified on the device: `adb shell /data/local/tmp/su` gives a `dizi:/ #`
  shell; `id -u` → 0; `exit` closes it. Commands from later adb sessions also reach the agent
  (it is independent of the exploit process).
- **Observed artifact (unexplained, not blocking):** the rooted cred has uid 0 but
  gid/groups `1514833792` instead of 0, so the exploit does not install pristine `init_cred`
  (the uid fields are the crafted part). With full capabilities and SELinux permissive every
  root operation tested so far succeeds; recorded rather than assumed normal.
- This is a temporary root: reboot clears the agent and restores enforcing. The abstract socket
  is reachable by any process on the device while permissive — acceptable only inside a
  controlled test window.

**Status: the stated goal (a temporary root shell from adb, no bootloader unlock) is met.**

### 2026-10-29 — Bootloader unlock storage found: `devinfo` is magic-only trusted

Using the live run-6 root, partitions were dumped read-only and the ABL image re-read. The unlock
gate is **not** `frp`; it is two unauthenticated bytes in the `devinfo` partition.

**Location and layout.** `devinfo` = `/dev/block/by-name/devinfo` → `/dev/block/sde58`
(GPT #58 on LUN 4, one 4096-byte logical block, first/last LBA 478862, type GUID
`65addcf4-0c5c-4d9a-ac2d-d90b5cbfcd03`). The partition is the persisted 0x998-byte
`ANDROID-BOOT!` device-info blob used by ABL:

| offset | field |
| --- | --- |
| 0x000 | `"ANDROID-BOOT!"` (13 bytes, the only integrity check) |
| 0x00d (13) | `is_unlocked` (currently `0x00`) |
| 0x00e (14) | `is_unlock_critical` (currently `0x00`) |
| 0x00f (15) | charger-screen flag (currently `0x00`) |
| 0x090 (144) | init marker, currently `0x01` |
| 0x8a0 | init marker, currently `0x01` |

**Read-only dumps and checksums** (host copies under `/tmp/opencode/dizi-dumps/`, not committed;
each stream was cross-checked with an on-device `sha256sum` of the same block device):

| partition | node | size | sha256 (prefix) | note |
| --- | --- | --- | --- | --- |
| `devinfo` | sde58 | 4096 | `a799fba7…` | magic at 0x0; [13]=[14]=0 |
| `frp` | sda5 | 512 KiB | `1a462029…` | last byte `0x01` = OEM unlock allowed |
| `misc` | sda3 | 1 MiB | `ca6dc3b6…` | only `0x8000..0x8004` = `02 b0 0a 74 56` |
| `persist` | sda2 | 32 MiB | `f5c37693…` | no magic |
| `uefivarstore` | sde67 | 512 KiB | `224fbd06…` | `PTBL` store; only standard EFI vars, no unlock var |
| `vbmeta_a` | sde16 | 64 KiB | `d29eaaf9…` | `avbtool 1.2.0` |
| `vbmeta_system_a` | sda7 | 64 KiB | `03f22ddd…` | — |

**ABL code (Ghidra project `A3xxOpenCLLab`, program `/dizi-bootloader/abl_full.efi`, from the OTA):**

- `FUN_000493a0` is the load/init routine. It is called from the boot entry `FUN_0000135c` at
  `0x1454`, **before** the AVB call at `0x1c64`. It reads 0x998 B through the VB protocol; if the
  13-byte magic matches, the struct is trusted as-is. On mismatch it zeroes the struct, writes the
  magic, sets `is_unlocked = (secure_state == 0)` (the TZ-derived secure-state bit; on this
  production secure device the re-init is expected locked, though the raw TZ state was not read),
  `is_unlock_critical = is_unlocked`, byte 0x90 = 1, and writes it back. **No CRC, signature or TZ
  check is applied to the magically-valid blob.**
- `FUN_00048e10(v)` writes offset 13; `FUN_00048ee8(v)` writes offset 14; both persist the full
  0x998 B blob through `FUN_00030ad8(1, …)` (VB protocol `VBRwDevice`).
- `FUN_0005db28` (`fastboot oem unlock`, command table entry at `0xb7fd0`) verifies a MiToken
  through a MiToken protocol (TZ) and, on success, calls `FUN_00048908(0,1)` then `(1,1)` → sets
  offsets 13 and 14 to 1. `FUN_00048908` also writes a `boot-recovery` message to `misc`
  (`--wipe_data` or `--just_exit`, depending on `allow-wipe-userdata`); that wipe request is a side
  effect, not part of the lock state.
- `FUN_0005dd78` (`fastboot oem lock`) requires `is_unlocked`, then calls `FUN_00048908(0,0)` and
  `(1,0)` → clears offsets 13/14. This is the mirror image of the unlock path and proves those bytes
  are the state.
- The same bytes gate the rest of the bootloader: AVB (`FUN_0000b3e8`; at `0xc3f0` a failed
  `LoadImageAndAuth` only continues when `is_unlocked`; boot state string `orange`), flash
  (`FUN_0005c27c`: "Flashing is not allowed in Lock State", critical partitions need byte 14),
  erase (`FUN_0005d680`: "Erase is not allowed in Lock State"), EDL (`FUN_0005e9f4`), rollback
  index (`FUN_0000ef34` writes it instead of failing when unlocked). `FUN_000486d8`/`FUN_000486e8`
  are the getters for bytes 13/14.
- The complete fastboot command table (`0xb7f80`) was enumerated: `flash:`, `erase:`, `set_active`,
  `flashing get_unlock_ability`, `oem unlock`, `oem lock`, charger-screen, display-panel,
  `oem device-info`, `oem poweroff`, `oem fbreason`, `oem uart-enable`, `oem getguid`, `continue`,
  `reboot`, `oem edl`, `oem erase-vb-index`, `oem lkmsg/lpmsg/uefilog`, recovery/fastboot/bootloader
  reboots, `snapshot-update`, `getvar:`, `download:`, `oem allow-wipe-userdata`. No locked-state
  command writes `devinfo` or bypasses the MiToken; the flash/erase handlers all check 13/14.

**Device state:** `ro.boot.flash.locked=1`, `ro.boot.verifiedbootstate=green`,
`ro.boot.vbmeta.device_state=locked`, `sys.oem_unlock_allowed=1`, `ro.oem_unlock_supported=1`.
`frp`'s last byte is `0x01`, so the "OEM unlocking" developer-option gate is already open.

**Writability (non-destructive proof):** `/sys/block/sde/sde58/ro` = 0 and the node is
`brw------- root root`. A 4-byte **nonzero** pattern (`de ad be ef`) written into the unused
padding at 0xF00 (the blob ends at 0x998) read back byte-identical, and was then restored to
zeros; the partition hash returned to `a799fba7…`. A later 4-byte no-op zeros write also returned
`rc=0`. The partition is neither block-layer read-only nor XPU-protected on this build.

**Concrete unlock (identified; deliberately not executed).** From the live root:

```sh
dd if=/dev/block/by-name/devinfo of=/data/local/tmp/devinfo.bin bs=4096 count=1
printf '\001' | dd of=/data/local/tmp/devinfo.bin bs=1 seek=13 conv=notrunc
printf '\001' | dd of=/data/local/tmp/devinfo.bin bs=1 seek=14 conv=notrunc
dd if=/data/local/tmp/devinfo.bin of=/dev/block/by-name/devinfo bs=4096 count=1 conv=notrunc
sync
# verify: dd if=/dev/block/by-name/devinfo bs=1 skip=13 count=2 | od -An -tx1   → 01 01
adb reboot bootloader
```

Then `fastboot oem device-info` should report "Device unlocked: true" and "Device critical
unlocked: true", `fastboot flashing get_unlock_ability` → 1, `fastboot getvar unlocked` → yes.
Re-lock with `fastboot oem lock` (only with stock images; it clears 13/14 and writes the `misc`
message), or write the bytes back to 0 from root.

**Why this is the real unlock, not a guess:** the official token path and the official lock command
use exactly these setters; the boot/AVB/flash/erase/EDL/rollback paths read exactly these bytes;
the load path checks only the magic; the partition is writable from root; no other partition holds
the magic; `frp` carries only the already-open allow flag; `uefivarstore` has no unlock variable.
This is also the bootloader weakness itself: the persistent unlock state is unauthenticated, so any
uid-0 (including the temporary kernel-exploit root) can flip it without the Xiaomi server token.

**Caveats:** not executed (user directive). A corrupted blob re-initializes from the TZ
secure-state default (expected locked); either way, the failure mode is not a brick. The direct write skips the `--wipe_data`/`--just_exit` request of the official
flow, so userdata is retained unless wiped manually. XBL still verifies ABL (secure boot), so a bad
bootloader image can still brick; use stock images for critical partitions. OTA/rollback behavior
after unlocking is untested.

### 2026-10-29 — Unlock side-effect analysis: the skipped wipe is the main risk

Read-only follow-up to the `devinfo` entry: what a direct write changes beyond bytes 13/14.
**Nothing was unlocked or rebooted.**

**Confirmed (read-only):**

- The direct write is exactly the official state change minus the `misc` `boot-recovery` /
  `--wipe_data` request that `FUN_00048908` writes. `frp`, `persist`, `uefivarstore` and the current
  benign `misc` bytes are unchanged.
- `/data` is FBE (`ro.crypto.type=file`) with metadata encryption; the metadata key is
  `/metadata/vold/metadata_encryption/key/` (210-byte `keymaster_key_blob` + 278-byte
  `encrypted_key`), with a `key_back` copy. `/metadata` is ext4 on `sda9` (64 MiB) with
  `formattable,first_stage_mount` in both fstabs.
- `vold` `retrieveOrGenerateKey`: when the key directory exists it calls `retrieveKey`; a Keystore
  decrypt failure returns false. It does not generate or delete the key in that path.
  `deleteAllKeys` runs only when the key directory is **missing** and
  `ro.crypto.metadata_init_delete_all_keys.enabled=true`.
- `fs_mgr`: a metadata `vdc cryptfs encryptFstab` failure returns `FS_MGR_MNTALL_FAIL`; the
  auto-format branch requires `partition_wiped` **and** `formattable`, so a key failure does not
  auto-format. `/data` cannot mount; the device goes to recovery / "Can't load Android system" and
  needs a factory reset (data loss). This is a **soft brick**, not a hard brick.
- The Keymaster TA on this build is `KeymasterLite` in `tz_a` (`SET_BOOT_STATE`,
  `READ/WRITE_KM_DEVICE_STATE`, `KeymasterLite_verifyKeyBlob`, `encryptDecryptKeyBlob`,
  `KM_TAG_NO_AUTH_REQUIRED`, `KM_TAG_ROLLBACK_RESISTANT`, `KM_TAG_ROOT_OF_TRUST`); userspace
  `libqtikeymaster4.so` sends `set_boot_state_req`, `set_device_locked`, `set_early_boot_ended`.
  `vold` creates the metadata key with `NO_AUTH_REQUIRED` (+ optional `ROLLBACK_RESISTANT`), not
  `UNLOCKED_DEVICE_REQUIRED`. Ghidra: `generate_key_context` mixes the key-blob fields, a 0x50-byte
  device field and a hardware-derived cipher key; it does not visibly consume a current boot-state
  value, and the `SET_BOOT_STATE`/`WRITE_KM_DEVICE_STATE` commands are separate. The blob is CBOR
  with hardware-enforced tags (the TA exposes `KM_TAG_ROOT_OF_TRUST`), but its exact
  root-of-trust handling was not decoded. Suggestive, not proof.
- ABL: a corrupt magic re-initializes the blob from the TZ secure-state default (expected locked;
  the raw TZ state was not read); a read/write failure returns a boot-entry
  error (`Initialize the device info failed`) and can halt / enter fastboot / EDL. The 0xF00
  write-and-restore test shows the UFS partition is healthy.

**Unconfirmed:** whether the closed `KeymasterLite` rejects the existing metadata blob after
green/locked -> orange/unlocked. The code evidence favours survival, but there is no device test.
OTA behavior and whether the official `--wipe_data` formats `/metadata` are also unconfirmed.

**Recommendation:** do not execute yet. If data loss is acceptable, the safe path is the direct
write **plus** wiping `/data` and `/metadata` before the first Android boot (`fastboot -w`,
`fastboot erase metadata`, or the official token / `--wipe_data` path), so a fresh metadata key is
created under the unlocked state. If data must be kept, back up, keep stock firmware/EDL ready, and
treat the first boot as an experiment. The write itself is low-risk; the skipped wipe is the open
question. Details and risk table: `docs/bootloader-unlock-DIZI.md` §9.1.

### 2026-10-29 — Clean-start order clarified; `fastboot boot` confirmed in ABL

Offline follow-up only; no adb/fastboot command, unlock, wipe, reboot or RAM boot was executed.

- **Correction to the earlier command-table summary:** `boot` is present. Entry `0xb7ff0` is
  `{name=0xb7b69, handler=0x5de1c}`; its name points into the `boot` suffix of `has-slot:boot`.
  This string reuse hid it from the earlier enumeration summary, not from the bootloader.
- `FUN_0005ad20` registers the entry via `FUN_0005bf98`. Dispatcher `FUN_0005a7ac` supplies the
  downloaded buffer/length; `FUN_0005de1c` checks ordinary `is_unlocked` (`FUN_000486d8`), with
  error `Fastboot boot command is not available in locked device`. No separate critical-unlock
  check is present in this handler.
- The unlocked handler loads/authenticates the downloaded image using `FUN_0000b3e8`, then calls
  `FUN_0001bf38` (`BootLinux`), rather than flashing it. Invalid/incomplete images are rejected.
  A/B handling may clear the active slot's unbootable flag (`FUN_00044b70`), so RAM boot is not
  strictly a no-persistent-write operation. The booted image can also modify storage itself.
- Thus `fastboot -s e5778c5b boot boot-test.img` is **statically supported after unlocking**; no
  runtime success is claimed. A compatible Android boot image and matching on-device companion
  images are still required. An ordinary reboot normally returns to the installed boot image.
- Clean-start order: back up off-device and retain account credentials; unlock and verify the
  stored state; reboot directly to bootloader fastboot; verify unlocked; wipe userdata and erase
  metadata; reboot to stock Android only after both operations succeed. This is a lower-risk,
  **untested** fresh-start plan, not a guarantee. Never erase metadata alone while retaining data.

Updated `docs/bootloader-unlock-DIZI.md` §§7.1–7.2 and qualified the earlier first-boot guarantee.

### 2026-10-29 — Unlock authorized; preflight and off-device backups complete

The user authorized the unlock, bootloader reboot, userdata/metadata wipe and stock reboot, accepting
data loss. After being told that the direct path remains experimental and recovery cannot be
guaranteed, the user explicitly selected **"Proceed; accept residual risk"**. Scope is **ordinary
unlock only** (byte 13 -> 1; byte 14 remains 0), no critical unlock, no firmware/GPT changes, and no
custom RAM boot. Stop on unexpected state or write/wipe failure.

At 09:45 EET, serial `e5778c5b` was verified as `dizi`, firmware `V816.0.19.0.UNSCNXM`, exact
`5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` kernel, slot `_a`, Android boot complete,
green/locked, 100% battery (`Full`), live uid-0 `u:r:kernel:s0` root. Host fastboot is
`35.0.2-android-tools`. `devinfo` resolves to `sde58`, size 4096, valid magic and flags `00 00`.

Verified off-device backups are in ignored, mode-0700 directory
`.dizi-dumps/unlock-preflight-20261029-094508/`; each stream matched an independent on-device hash:

| file | bytes | SHA-256 |
| --- | --- | --- |
| `devinfo.before.img` | 4096 | `a799fba76a204f67eabd37ab48fa61d1ca459be9afe160eb14b0a876030ce0c2` |
| `misc.before.img` | 1048576 | `ca6dc3b64ed590f8af9b78fa3177243f6ad22a1f8ada93de77a0e4c9a61e2fd0` |
| `frp.before.img` | 524288 | `1a462029354328d59cd182c4ba549a3165beaf667efc7bc96637ab76c248488f` |

All three match the earlier recorded hash prefixes. At this entry's creation no unlock write, wipe
or reboot has occurred; execution results will be appended separately. `a37b82` remains untouched.

### 2026-10-29 — Ordinary-only `devinfo` write verified, but bootloader STILL LOCKED; stopped

Authorized execution after the preflight above, approximately 09:48 EET:

1. Created an off-device copy differing from `devinfo.before.img` at **offset 13 only** (`00 -> 01`).
   Byte 14 stayed `00`. Staged it at `/data/local/tmp/devinfo.normal-unlock-20261029.img`.
2. A guarded root command rechecked device/build, root, battery >=80%, node `sde58`, 4096-byte
   partition length, original hash and staged-image hash, then issued one full-sector `dd`, `sync`
   and `cmp`. Write returned 4096 bytes, `cmp` passed, and an independent host read of the whole
   partition was byte-identical to the staged image. Post-write SHA-256:
   `51f11e795f59e53cf2b0edafe89c0426757e654325ae023daeb4f5dd9aec0a3f` (flags `01 00`).
3. Ran `adb -s e5778c5b reboot bootloader`. Fastboot responded normally. Targeted queries returned:

   ```text
   serialno: e5778c5b
   product: dizi
   is-userspace: no
   (bootloader) Verity mode: true
   (bootloader) Device unlocked: false
   (bootloader) Device critical unlocked: false
   (bootloader) Charger screen enabled: true
   unlocked: no
   current-slot: a
   snapshot-update-status: none
   ```

4. The unlocked-state assertion failed. **No `fastboot -w`, metadata erase, firmware/GPT flash,
   EDL entry, custom RAM boot or further reboot was attempted.** The tablet was left responsive
   in bootloader fastboot. `a37b82` was never targeted.

Logs, before/staged/readback images and the backup manifest remain in ignored directory
`.dizi-dumps/unlock-preflight-20261029-094508/` (`stage.log`, `write.log`,
`fastboot-verification.log`). No device-specific binary dumps are committed.

**Correction:** the previous identification of the writable `devinfo` blob as the authoritative
VB-protocol store was too strong. The ordinary-only edit did **not** unlock this device. Whether
the byte persisted across reboot, the partition is a mirror/unused store, another boot stage
restored state, or some additional condition applies is **unconfirmed**. There is no evidence
justifying a critical-unlock retry, a wipe, or a claim that Android has been freshly reset.

Next safe investigation is to check post-reboot bytes and resolve VB-protocol backing/build
identity; this requires a separately considered return to stock Android/root or offline analysis.
Earlier journal entries are retained as history and superseded where they claim a proven unlock.

### 2026-10-29 — Diagnostic stock boot succeeds; VB provider recovered offline

The user authorized diagnosis of whether reboot restored the byte or ABL uses another store.
Rebooted `e5778c5b` from fastboot to stock Android; `sys.boot_completed=1`, same firmware/kernel,
slot `_a`, `ro.boot.flash.locked=1`, verified boot `green`. Thus Android boot after the failed
attempt is now verified. The `ghostsu` client reports its temporary agent is absent, as expected
after reboot. Started the previously authorized temporary-root gate to regain read access; no
new unlock/partition write or wipe is part of this diagnostic. Gate result/readback pending at
this entry's creation. The protected second device is not targeted.

**The missing provider was found offline.** Copied the already-downloaded exact OTA `uefi.img`
from ResearchVM (`/bigdata/dizi_root/firmware/`) to ignored `.dizi-dumps/uefi.ota.img`. The UEFI
container is not opaque: its GUID-defined sections at `0x52e80` / `0x1a6108` are **gzip**, not
LZMA (GUID `1d301fe9-be79-4353-91c2-d23bc959ae0c`, data offset `0x18`). The first decoded volume
contains FFS `a25f5839-4d55-428f-8f0b-5ce1d565f53e`, UI `VerifiedBootDxe`, PE payload 61,440 bytes.
Exact extraction coordinates and SHA-256s are in `docs/bootloader-unlock-DIZI.md` §4.4.

Ghidra `/dizi-bootloader/VerifiedBootDxe.efi`:

- `FUN_000027d8` installs GUID **`8e5eff91-21b6-47d3-af2b-c15a01e020ec`**, exactly the GUID ABL
  locates in `FUN_00030ad8`. Protocol table `0xd180`, offset `+8`, points to **`FUN_000015ac`**.
- `FUN_000015ac` reads security state through `FUN_0000390c` (mask `0x8703`). The secure branch
  calls QSEECom app **`keymaster`**, reading 4096 bytes via request **`0x202`**; its write path
  read/modifies the secure buffer and sends **`0x203`**. Success logs **`Succeed using rpmb!`**.
- The raw GPT **`devinfo`** partition is the alternative store (`FUN_00002878` /
  `FUN_00002a24`). Non-secure state selects it directly. If a secure-app request fails, fallback
  is gated by `FUN_000038a0` (mask `0x8723`); a fully secure state refuses fallback. Raw-store
  success logs **`Succeed using devinfo!`**.

This supplies the previously missing mechanism for the failed edit: the layout-matching raw
partition need not be the authoritative secure-store blob. Runtime partition persistence and the
active UEFI payload still need cross-checking. Do not infer a new authorized write path from the
private Keymaster command IDs; no `0x203`, raw RPMB/provisioning operation, critical unlock or wipe
has been attempted in this diagnostic.

**Offline cross-check:** the pre-attempt on-device `abl_a` dump is 1,048,576 bytes; its first
204,800 bytes hash to `7b54a8fcc41428328487de5848fcc512dd8bd4f4a38f765c8ebedccae9f50c65`,
exactly matching the OTA `abl.img`. All remaining bytes are zero. Thus an ABL payload mismatch is
not supported by the available dump. A static assertion check also passed for the OTA UEFI hash,
gzip/FFS extraction, module identity, matching protocol GUID and `+8` callback pointer. Saved
Ghidra plate comments at provider addresses `0x15ac`, `0x390c`, `0x38a0` documenting the store
selection and the unconfirmed mask-bit semantics.

### 2026-10-29 — Fallback predicate resolved offline; unlock is not forceable

Read-only analysis + one authorized diagnostic gate run. No partition write, wipe, unlock write,
critical unlock, EDL entry or RAM boot was performed. The protected second device was not touched.

**Gate/diagnostic run:** a `tools/reroot.sh` run against `e5778c5b` (12 attempts, ~15 min) ended at
the 900 s timeout with `exit 124` and **no root**: W1 (SELinux permissive) succeeded on most
attempts, but W2 (cred overwrite) never landed. The tablet was left booted in stock Android,
`sys.boot_completed=1`, `ro.boot.flash.locked=1`, `verifiedbootstate=green`, shell uid 2000. So the
post-reboot `devinfo` readback is **still not obtained**; it needs a successful gate run, not a new
write. A cached-rederivation question is open on why run 6 passed and this run did not.

**The full chain from fuse state to the fastboot answer is now reconstructed**
(`docs/bootloader-unlock-DIZI.md` §4.5):

- Store selector `VerifiedBootDxe: FUN_0000390c` → Keymaster/RPMB store iff
  `(scm_state & 0x8703) == 0`; otherwise the raw `devinfo` GPT partition. The
  `VB: Non-secure device` log line belongs to the *raw* branch, i.e. to unfused/dev units.
- Fallback gate `FUN_000038a0` → a failed Keymaster read may use `devinfo` only if
  `(scm_state & 0x8723) != 0`. Since `0x8723 = 0x8703 | 0x20`, an RPMB-store device can reach the
  fallback **only when bit `0x20` is set**. Bit semantics remain **unconfirmed**.
- `scm_state` is read once via SCM SIP call **`0x2000604`** in `FUN_000037e4` and is fuse-derived.
  No partition, EFI variable, `misc` byte or Android property participates. There is therefore no
  writable input that can flip the branch.

**Why the 2026-10-29 write was ignored (now explained without a device read):** the observed outcome
requires that the raw branch was not taken, so this tablet reads its device info from the RPMB store
and treats the byte-identical `devinfo` partition as a legacy mirror. Consistent with
`secure`/`green`/fused retail configuration.

**Caching and writers:** `LinuxLoaderEntry` → `FUN_000493a0` performs the single
`RWDeviceState(0, …)` read of 0x998 bytes into `0xd1538`; `DAT_000c04e0` is statically `1` in the
image and is the lazy-load guard. `FUN_000486d8`/`FUN_000486e8` only return cached bytes 13/14. The
sole post-load writers are the magic-mismatch re-init and `FUN_00048e10`/`FUN_00048ee8`. The
magic-mismatch path is a **re-lock**: it clears the blob, re-derives
`is_unlocked = is_unlock_critical = (FUN_00031870() == 0)` from TZ, and writes back — so zeroing the
store can never produce an unlock.

**Only supported unlock path on this build:** `oem unlock` = `FUN_0005db28`, which resolves the
**MiToken protocol**, reads and verifies the token, reboots on
`Token Verify Failed`, and on success calls `FUN_00048908(0,1)` + `FUN_00048908(1,1)` (both ordinary
**and** critical) then stages the `misc` master clear. `oem lock` = `FUN_0005dd78` requires unlocked.

**Also established:** the VB protocol table `0xd180` is `{version, RWDeviceState(+8)=0x15ac,
…, Reset_State(+0x30)=0x1c44, …}`; `FUN_000319a0` calls `Reset_State` after a successful state change
and at boot, guarded by `FUN_0000b3e0`/`FUN_0000b3d8`. The exact UEFI image's own BDS menu text
confirms RPMB is provisioned with a TZ-derived key, that the key changes once fuses are blown, and
that re-provisioning a provisioned RPMB **bricks the device**.

Conclusion recorded: there is **no tokenless unlock** to pursue on this unit short of a secure-world
compromise, which is out of scope and carries EDL-only recovery risk.

### 2026-10-29 — Token path is plain RSA-2048; brute force is not applicable

Offline only: no adb/fastboot command, no device write, no token submitted. The protected second
device was not touched.

Extracted `MiTokenDxe` from the exact OTA's `uefi.img` (nested FV → FFS
`068aae46-bdc6-4073-85d5-31c5eef19a15`, 45,056-byte PE32+; `.dizi-dumps/MiTokenDxe.efi`). This is the
provider of the protocol ABL's `oem unlock` locates.

- `FUN_0000160c` builds the request: base64 of `55 01 01 02` + tag `0x10` (16 bytes from
  `EFI_RNG_PROTOCOL`, a **per-boot nonce**) + tag `0x03` (device name from SMEM) + tag `0x02`
  (`ChipId << 32 | Serial`). Cached in BSS `0x9390`, filled only when that byte is 0, so once per boot.
- `FUN_0000199c` → `FUN_00001a50` → **`FUN_00001dc8`** is textbook **RSA-2048 / PKCS#1 v1.5 type-1**
  verification with its own bignum (`FUN_000020d0` Montgomery multiply, `FUN_000021fc` subtract).
  It requires `EM = 00 01 FF..FF 00 || M` and compares `M` byte-for-byte with the regenerated base64.
- Key struct at `0x9108`: `[0]=0x40` words, `[1]=n0=0x5d57403f`, `N` at `0x9110` (little-endian
  words, LSW first), `R² mod N` at `0x9210`, `e=65537` at `0x9310`.
- **Confirmed, not assumed:** `n0·N[0] ≡ -1 mod 2³²` holds and the bytes at `0x9210` equal
  `pow(2,4096,N)` exactly. `N` is 2048-bit, odd, no factor < 100,000.
  SHA-256 of `N` (big-endian) = `c21c6c4f9b5365facac2287fc27a22e0279b828fbcfb574ac852600c62b5ca44`.
  Public key saved as `.dizi-dumps/mitoken-unlock-pubkey.der` (SHA-256 `04f02dfd…23fae5`) with a
  sibling `.json` recording offsets and the `R²` check. This is a public key, identical per build.

**Brute force assessment: not applicable.** Forgery requires the private key, i.e. factoring a
2048-bit modulus; the signature space is `2²⁰⁴⁸`; there is no oracle (one verification per boot, and
`Token Verify Failed, Reboot the device` reboots on failure); and each token is bound to this unit's
ChipId/serial/dev_name plus the current per-boot nonce, so captured tokens do not replay. The real
gate is Xiaomi's server-side authorisation policy, not the crypto.

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
5. The 5.10.209 profile passed its first cold-boot gate run on 2026-10-29 (run 6: W1 + W2,
   temporary root via `ghostsu`; entry above and `docs/device-gate-DIZI-02.md`). A **second**
   consecutive cold-boot pass is still open before calling it production-ready.
6. ❌/⏳ The authorized ordinary-only `devinfo` edit **failed to unlock after reboot** despite
   complete pre-reboot write/readback verification. Tablet remains responsive in bootloader
   fastboot initially; diagnostic stock Android boot now also passes, green/locked. No wipe or
   firmware/GPT flash performed. Root cause now established offline: the selector/fallback
   predicates read fuse-derived SCM state, this unit uses the Keymaster/RPMB store, and no writable
   input can force the raw `devinfo` branch. **Do not repeat the byte write.** The earlier
   "concrete unlock path" conclusion is superseded, not confirmed. If unlock is still wanted, the
   only supported route is Xiaomi's MiToken `oem unlock` with its mandatory wipe. Details in the
   execution/diagnostic entries and `docs/bootloader-unlock-DIZI.md` §§1.1, 4.4, 4.5.
7. ⏳ Optional kernel-module root. Signatures are off (`CONFIG_MODULE_SIG` not set) but the device
   kernel is `CONFIG_CFI_CLANG=y` + `CONFIG_LTO_CLANG_FULL=y`, while the VM oracle tree is
   `LTO_NONE`/no CFI. A compatible `.ko` needs a CFI+LTO rebuild of that tree (or a loader for an
   existing CFI-built LKM such as the extracted `android12-5.10_kernelsu.ko`) plus
   `finit_module(fd, "", IGNORE_VERMAGIC|IGNORE_MODVERSIONS)`. Not attempted; the userspace
   `ghostsu` agent covers the temporary-root goal first.

## Constraints reminder

- Never touch `a37b82`.
- Device interactions read-only until gate authorization.
- No profile use across builds.
- **VM workspace convention:** everything fetched, downloaded, or built on ResearchVM goes under
  `/bigdata/dizi_root/` (the NDK may be reused from `/bigdata/android-sdk/ndk/29.0.14206865` in
  place). Exception for the two already-running downloads: their paths were baked in before the
  convention was set, so their outputs (`kcom-4ea09a298bb4`, `clang-r416183b`, plus the tarballs)
  must be moved into `dizi_root` after completion.
