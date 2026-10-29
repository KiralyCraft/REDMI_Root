# DIZI bootloader unlock investigation: direct `devinfo` edit did not unlock

Status: **authorized ordinary-only attempt failed on 2026-10-29**. The edit passed full partition
readback before reboot, but bootloader fastboot still reports locked. **Stopped before wiping.**
The earlier inference that the writable `devinfo` partition is the authoritative unlock store is
not established. Historical candidate commands below are **not a validated unlock procedure**.

Target: `dizi` / 2405CRPFDC (Redmi Pad Pro, SM7435), firmware `V816.0.19.0.UNSCNXM`,
kernel `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661`. Device serial `e5778c5b` only;
`a37b82` must never be touched.

## 1. Result in one paragraph

The **`devinfo`** partition (`/dev/block/by-name/devinfo` → `/dev/block/sde58`, 4096 bytes,
GPT #58 on LUN 4) contains an `ANDROID-BOOT!` blob matching ABL's device-info layout. ABL's getters
use offsets 13/14 of its in-memory blob, loaded through the VB protocol. Root can write the block
partition, but this alone does **not** prove that the VB protocol uses those partition bytes as
its authoritative state: an authorized `devinfo[13]=1`, `[14]=0` write was fully verified before
reboot, yet fastboot reported locked. The subsequently recovered `VerifiedBootDxe` provider (§4.4)
has a secure Keymaster/RPMB backend distinct from the raw-partition fallback; runtime persistence
and active UEFI cross-checks remain pending. There is currently **no device-verified tokenless
unlock**.

### 1.1 Actual execution result (2026-10-29)

With explicit user authorization and acceptance of residual risk:

- Verified target `e5778c5b`, exact firmware/kernel, uid-0 root, battery 100%, slot `_a`.
- Backed up `devinfo`, `misc` and `frp` off-device with independent on-device hash verification.
- Changed **only byte 13**, leaving critical unlock disabled and all other 4095 bytes unchanged.
  One 4096-byte write, `sync`, device-side `cmp` and independent full host readback all passed.
  Flags before reboot were `01 00`, SHA-256
  `51f11e795f59e53cf2b0edafe89c0426757e654325ae023daeb4f5dd9aec0a3f`.
- Rebooted directly to bootloader fastboot. It returned `serialno: e5778c5b`, `product: dizi`,
  `is-userspace: no`, `Device unlocked: false`, `Device critical unlocked: false`, `unlocked: no`,
  `current-slot: a`, and `snapshot-update-status: none`.
- **Stopped:** no userdata wipe, metadata erase, firmware/GPT flash, EDL entry, custom RAM boot or
  further reboot during that attempt. A later authorized diagnostic return to stock Android
  succeeded (`sys.boot_completed=1`, green/locked, slot `_a`); the tablet is no longer in fastboot.

Backups/logs are in ignored directory `.dizi-dumps/unlock-preflight-20261029-094508/`. Raw `devinfo`
bytes after reboot have not been read, so persistence versus overwrite/mirror behavior remains
**unconfirmed**. Do not enable critical unlock or erase data to compensate for this failed check.

## 2. Device state observed before the attempt (read-only)

```
ro.boot.flash.locked        = 1
ro.boot.verifiedbootstate   = green
ro.boot.vbmeta.device_state = locked
sys.oem_unlock_allowed      = 1
ro.oem_unlock_supported     = 1
```

`frp`'s last byte was `0x01` (the "OEM unlocking" developer-option gate was already open). These
Android properties and raw flags were recorded before the write. Post-reboot fastboot still
reports locked; the current raw `devinfo` bytes are unknown.

## 3. Partition dumps

Dumps were streamed through the live `ghostsu` root and each device stream was checked against an
on-device `sha256sum` of the same block device. The original `/tmp/opencode/dizi-dumps/` location
was temporary; persistent investigation copies and current execution backups are under ignored
`.dizi-dumps/` and are not committed.

| partition | node | size | sha256 (prefix) | relevant content |
| --- | --- | --- | --- | --- |
| `devinfo` | `sde58` | 4096 B | `a799fba7…` | `"ANDROID-BOOT!"` at 0x0; `[13]=0`, `[14]=0` |
| `frp` | `sda5` | 512 KiB | `1a462029…` | last byte `0x01` |
| `misc` | `sda3` | 1 MiB | `ca6dc3b6…` | only `0x8000..0x8004` = `02 b0 0a 74 56` |
| `persist` | `sda2` | 32 MiB | `f5c37693…` | no magic |
| `uefivarstore` | `sde67` | 512 KiB | `224fbd06…` | `PTBL` store; only standard EFI variables |
| `vbmeta_a` | `sde16` | 64 KiB | `d29eaaf9…` | `avbtool 1.2.0` |
| `vbmeta_system_a` | `sda7` | 64 KiB | `03f22ddd…` | — |

A scan of all of the above for `ANDROID-BOOT!` found exactly one occurrence: `devinfo` offset 0.
`frp` has no blob; `uefivarstore` has no unlock variable (only `BSPowerCycles`, `RTCInfo`,
`RunCycles`, `ConIn`, `ConOut`, `ErrOut`, `HwErrRecSupport`).

GPT entry for `devinfo` (parsed from a 4096-byte-sector GPT dump):

```
partition #58  name=devinfo
type GUID   65addcf4-0c5c-4d9a-ac2d-d90b5cbfcd03
unique GUID 774b15d7-3b66-4a14-a7aa-95006a71b7de
first LBA   478862   last LBA 478862   (4096 bytes)
```

## 4. ABL evidence (`abl_full.efi`, Ghidra project `A3xxOpenCLLab`)

The ABL image comes from the exact-build OTA. Addresses are Ghidra addresses in
`/dizi-bootloader/abl_full.efi`.

### 4.1 Load and trust

`FUN_000493a0` is the device-info load/init routine, called by the boot entry `FUN_0000135c` at
`0x1454`, **before** AVB (`FUN_0000b3e8`) at `0x1c64`:

- Reads 0x998 bytes through the VB protocol (`FUN_00030ad8(0, buf, 0x998)`).
- Compares the first 13 bytes with `"ANDROID-BOOT!"`.
- On match: uses the stored struct as-is (no further checks).
- On mismatch: zeroes it, writes the magic, sets `is_unlocked = (secure_state == 0)` (the
  TZ-derived secure-state bit; on a production secure device this re-initializes locked, though the
  raw TZ state was not read), `is_unlock_critical = is_unlocked`, byte `0x90 = 1`, then writes it
  back. This provides a secure-state-default fallback if the protocol read/re-init write succeeds;
  it does not establish a guaranteed recovery path when those operations fail.

### 4.2 Setters and the official paths

| function | effect |
| --- | --- |
| `FUN_00048e10(v)` | sets device-info blob byte 13, persists through VB protocol |
| `FUN_00048ee8(v)` | sets device-info blob byte 14, persists through VB protocol |
| `FUN_000486d8()` | returns in-memory device-info byte 13 |
| `FUN_000486e8()` | returns in-memory device-info byte 14 |
| `FUN_0005db28` (`oem unlock`) | verifies MiToken via the MiToken protocol (TZ), then `FUN_00048908(0,1)` + `(1,1)` → sets 13/14 to 1 |
| `FUN_0005dd78` (`oem lock`) | requires `is_unlocked`, then `FUN_00048908(0,0)` + `(1,0)` → clears 13/14 |

`FUN_00048908` additionally writes a `boot-recovery` message to `misc` (`--wipe_data` or
`--just_exit`, depending on the `allow-wipe-userdata` property). That wipe request is a side effect
of the official flow, **not** part of the lock state; a direct `devinfo` write skips it (see risks).

### 4.3 Consumers

- **AVB** `FUN_0000b3e8`: at `0xc3f0`, if `LoadImageAndAuth` failed and `is_unlocked` is true, boot
  continues; the boot state becomes `orange` (`androidboot.verifiedbootstate=` at `0xa7a8e`, with
  `green`/`orange`/`yellow` at `0xa7aae`/`0xa7ab4`/`0xa7abb`).
- **Flash** `FUN_0005c27c`: `is_unlocked == 0` → "Flashing is not allowed in Lock State";
  critical partitions additionally require `is_unlock_critical`.
- **Erase** `FUN_0005d680`: same two checks ("Erase is not allowed in Lock State" / "…Critical
  Partitions").
- **EDL** `FUN_0005e9f4`: unlocked bypasses the EDL token and reboots into EDL.
- **Rollback index** `FUN_0000ef34`: when unlocked, updates the stored index instead of failing.

The full fastboot command table at `0xb7f80` was enumerated (`flash:`, `erase:`, `boot`, `set_active`,
`flashing get_unlock_ability`, `oem unlock`, `oem lock`, charger/display/device-info/poweroff/
fbreason/uart/getguid/edl/erase-vb-index/log commands, `getvar:`, `download:`, …). No locked-state
command writes `devinfo` or bypasses the token; `oem unlock` is the only token path.

### 4.4 Missing layer found: `VerifiedBootDxe` chooses RPMB or the partition

Offline follow-up on 2026-10-29 recovered the actual VB-protocol provider from the exact OTA's
`uefi.img`, rather than assuming its implementation from ABL's wrapper.

**Extraction/provenance:** the outer firmware volume begins at file offset `0x1000`. Its FFS
GUID-defined sections at `0x52e80` and `0x1a6108` use gzip GUID
`1d301fe9-be79-4353-91c2-d23bc959ae0c`, data offset `0x18`. Decoding the first yields 4,005,896
bytes with a nested FV at offset 8. In that volume, FFS file
`a25f5839-4d55-428f-8f0b-5ce1d565f53e` at `0x777f8` has UI name `VerifiedBootDxe`; its PE32 section
at `0x77818` contains a 61,440-byte image. Local/Ghidra paths are
`.dizi-dumps/VerifiedBootDxe.efi` and `/dizi-bootloader/VerifiedBootDxe.efi`.

| image | SHA-256 |
| --- | --- |
| exact OTA `uefi.img` (4,202,496 bytes) | `6cd080f94cf26fb635b41e45d279cc31539b663c4d7eb8112d5a388056c96e55` |
| extracted `VerifiedBootDxe.efi` | `89adb17817c374a94af54cb3557b624bf5129944fe8cc277836a63769c951567` |

The pre-attempt `abl_a` device dump's first 204,800 bytes also match the OTA `abl.img` exactly
(SHA-256 `7b54a8fcc41428328487de5848fcc512dd8bd4f4a38f765c8ebedccae9f50c65`); the remainder of
that 1 MiB partition dump is zero. This rules out an ABL payload mismatch in the available dump.

**Protocol linkage is exact:** ABL's `FUN_00030ad8` locates GUID
`8e5eff91-21b6-47d3-af2b-c15a01e020ec` and calls protocol offset `+8`. The extracted driver's
`FUN_000027d8` installs that same GUID with table `0xd180`, whose `+8` callback is
`FUN_000015ac` (`RWDeviceState`).

That callback implements two stores:

1. Read secure state using `FUN_0000390c` (SCM security-state mask `0x8703`). In the secure
   branch, locate QSEECom and obtain/start the **`keymaster`** app. The read request is command
   **`0x202`**, with a 4096-byte buffer. Successful reads copy this buffer into ABL's device-info
   object. Writes first read with `0x202`, update the supplied bytes, then send **`0x203`**.
   This path explicitly logs **`VB: RWDeviceState: Succeed using rpmb!`**.
2. In the non-secure branch, access the GPT partition labelled **`devinfo`** using
   `FUN_00002878` (`read_partition`) / `FUN_00002a24` (`write_partition`). A failed secure-app
   request can fall back to this store only if another security-state check (`FUN_000038a0`,
   mask `0x8723`) permits it; otherwise the callback returns an error. This path logs
   **`VB: RWDeviceState: Succeed using devinfo!`**.

Therefore the matching raw-partition layout and its writability do **not** establish that it is
authoritative on a secure, RPMB-provisioned tablet. The secure-store branch provides a concrete
explanation for an ignored partition edit. The live post-reboot partition contents and the active
UEFI image still need to be cross-checked before claiming which branch this tablet used. No
Keymaster `0x203`, raw RPMB operation, provisioning change or additional unlock write is authorized
by this diagnostic finding.

### 4.5 Exact fallback predicate, unlock read path, and why it cannot be forced

Follow-up offline analysis (2026-10-29, no device writes) reconstructed the complete decision chain
from SCM fuse state to the fastboot answer, and established that the fallback is **not a
configuration choice**.

**The selector and the fallback are two different checks on the same SCM value.**

| Check | Function | Predicate | Effect |
| --- | --- | --- | --- |
| Store selector | `FUN_0000390c` | `(state & 0x8703) == 0` → `local_b0 = 1` | `1` = Keymaster/RPMB store; `0` = raw `devinfo` |
| Fallback gate | `FUN_000038a0` | `(state & 0x8723) != 0` | only then may a failed Keymaster read use `devinfo` |

`state` comes from `FUN_000037e4`, which issues SCM SIP call **`0x2000604`** through the SCM
protocol and requires `ret==0 && status==1`. It is a read-only secure-world value derived from
fuses and boot configuration. Nothing in `devinfo`, `misc`, `frp`, the GPT, or Android userspace
feeds into it.

Because `0x8723 = 0x8703 | 0x20`, the two predicates together mean: a device that selects the RPMB
store (`0x8703` clear) can reach the `devinfo` fallback **only if bit `0x20` is set**. The exact
meaning of bit `0x20` is **not established** from the available images and is recorded as
unconfirmed; the mask semantics above come from the decompiled comparisons, not from a QTI header.

**Read path and caching.** `LinuxLoaderEntry` (`FUN_0000135c`, `0x1984`) calls `FUN_000493a0`
before anything else. That function issues one `RWDeviceState` read (`FUN_00030ad8(0, buf, 0x998)`)
into the BSS blob at `0xd1538`. The 0x998 bytes are then never re-read: `DAT_000c04e0` is
statically initialised to `1` in the image, and `FUN_000493a0` is the only writer that clears it.
`FUN_000486d8`/`FUN_000486e8` simply return cached bytes `+13`/`+14`.

**Only two writers can change the cached flags after load**, besides the load itself:

- the magic-mismatch re-initialisation inside `FUN_000493a0`; and
- `FUN_00048e10` / `FUN_00048ee8`, the ordinary/critical setters behind `oem unlock` / `oem lock`.

The magic-mismatch path is a **re-lock**, not a bypass: it zeroes the 0x998 bytes, restores the
13-byte magic, reads SCM device state through `FUN_00031870`, sets
`is_unlocked = is_unlock_critical = (state == 0)`, and writes the blob back through
`FUN_00030ad8(1, …)`. Corrupting the magic therefore regenerates a *locked* blob on a locked
device and never yields an unlock.

**Why the 2026-10-29 write was ignored.** For the observed outcome (a verified, byte-identical
partition write that fastboot nevertheless reported as locked) the raw-store branch must not have
been taken, so `(state & 0x8703) != 0` does not hold: this tablet read its state from the
Keymaster/RPMB store and treated `devinfo` as a legacy mirror. This is consistent with the device
reporting `secure`, `verifiedbootstate=green` and a fused retail configuration. The
`Non-secure device` log line belongs to the raw-`devinfo` branch, i.e. to unfused/dev units.

**Can the fallback be forced?** Not from any writable surface:

1. The predicate inputs are SCM fuse state. No partition, EFI variable, `misc` byte or Android
   property is consulted, so there is nothing to edit.
2. Making the Keymaster read fail on purpose is likewise not controllable: the alternative branch
   exists for secure-app failure, and the fallback is still gated by bit `0x20`. Inducing a TA
   failure would first break the secure store the device needs.
3. Patching `VerifiedBootDxe` (or any UEFI/ABL module) to skip the check breaks the signed chain
   rooted in XBL/PBL fuses; the device then does not boot normally.
4. RPMB cannot be rewritten out of band. The BDS menu text in the exact UEFI image states the store
   is provisioned with a TZ-derived key, that the key changes once fuses are blown, and that
   re-provisioning an already provisioned RPMB **bricks the device**.

**The only supported unlock path on this build** is Xiaomi's token flow, confirmed in ABL:
`oem unlock` (`FUN_0005db28`) locates the **MiToken protocol**, reads the token, verifies it, and on
failure prints `Token Verify Failed, Reboot the device` and reboots. On success it calls
`FUN_00048908(0,1)` then `FUN_00048908(1,1)` — setting **both** ordinary and critical unlock — and
stages a `misc` master clear (`recovery --wipe_data --reason=MasterClearConfirm`). `oem lock`
(`FUN_0005dd78`) requires the device to be unlocked already.

Consequently there is no tokenless unlock to pursue on this unit without a secure-world
compromise, which is out of scope for this investigation and carries an EDL-only recovery risk.

### 4.6 The normal unlock path is standard RSA-2048, not a custom scheme

Offline analysis of the exact OTA (`uefi.img`) recovered the token verifier, so the question "can the
token be brute-forced" has a concrete answer rather than a guess.

**Module:** the nested UEFI volume contains FFS file
`068aae46-bdc6-4073-85d5-31c5eef19a15`, UI name `MiTokenDxe`, holding a 45,056-byte PE32+ image.
Its protocol is the one `oem unlock` locates in ABL (`FUN_0005db28`). Relevant functions:

| Function | Role |
| --- | --- |
| `FUN_0000160c` | builds the token **request**: base64 of a TLV blob |
| `FUN_0000199c` | `VerifyTokenInternal` — thin wrapper, logs `Mi_Token: VerifyTokenInternal Failed!` |
| `FUN_00001a50` | argument shuffle into the crypto routine |
| `FUN_00001dc8` | **RSA verification** |
| `FUN_000020d0` / `FUN_000021fc` | Montgomery multiply / modular subtract (own bignum, no OpenSSL) |

**The algorithm is RSA-2048 with `e = 65537` and PKCS#1 v1.5 signature padding**, i.e. it recomputes
`sig^e mod N` and requires the result to be exactly

```
00 01 FF FF ... FF 00 || M            (M = the base64 request string, 1..244 bytes)
```

The code checks `local_148[0] == 0x00`, `local_148[1] == 0x01`, a run of `0xFF`, a `0x00`
separator, then compares the tail byte-for-byte against the regenerated message. Both exponent
branches present in the code (`0x10001` and `3`) are ordinary public exponents; this key uses
`0x10001`.

**Key location and layout** in `MiTokenDxe.efi` (`int*` view at `0x9108`):

| Offset | Field |
| --- | --- |
| `0x9108` | word count, `0x40` (64 words = 2048 bits) |
| `0x910c` | `n0` = `0x5d57403f`, Montgomery `-N⁻¹ mod 2³²` |
| `0x9110` | modulus `N`, 64 words, **little-endian words, least-significant first** |
| `0x9210` | `R² mod N` (`R = 2²⁰⁴⁸`) |
| `0x9310` | exponent, `0x00010001` |

**Decisive confirmation:** `n0 · N[0] ≡ -1 (mod 2³²)` holds exactly, and the 256 bytes at `0x9210`
equal `pow(2, 4096, N)` exactly. A random 256-byte block has no reason to satisfy either relation, so
`N` is the RSA modulus and not a misread constant. `N` is 2048-bit, odd, and has no prime factor
below 100,000.

| Artifact | Value |
| --- | --- |
| SHA-256 of `N` (256-byte big-endian) | `c21c6c4f9b5365facac2287fc27a22e0279b828fbcfb574ac852600c62b5ca44` |
| `e` | `65537` |
| `.dizi-dumps/mitoken-unlock-pubkey.der` (RSAPublicKey) | SHA-256 `04f02dfde7d7db27a763e43d53dc239d04f9a1022721d6a0992c58d22323fae5` |

This is a **public** key. It is identical in every unit of the build; there is no secret to recover
from the image.

**What is signed.** `FUN_0000160c` assembles a TLV request and base64-encodes it into a 128-byte
buffer cached in BSS at `0x9390`:

- header bytes `55 01 01 02`;
- tag `0x10` + **16 bytes from `EFI_RNG_PROTOCOL`** (a per-boot nonce);
- tag `0x03` + device name (from SMEM, or the literal `undefined`);
- tag `0x02` + `(ChipId << 32) | Serial`, read through `EfiChipinfo`/QFPROM.

The cache is only filled when `DAT_00009390 == 0`, and BSS is zeroed at boot, so the nonce is
regenerated **once per boot** and reused for the rest of that boot.

**Why brute force does not apply.** This is not a password, MAC, or truncated digest:

1. **There is no small secret.** Recovering the signing key from `(N, e)` means factoring a 2048-bit
   modulus. The best published effort for RSA-2048 is the general number field sieve at a cost
   several orders of magnitude beyond any practical budget, and no 2048-bit RSA modulus has been
   factored publicly.
2. **The search space is `2²⁰⁴⁸`.** Guessing a 256-byte signature has the same probability per trial
   as guessing the private key; there is no gradient or partial-credit structure to exploit.
3. **There is no usable oracle.** Verification happens once, inside the bootloader, and a failure
   path in ABL prints `Token Verify Failed, Reboot the device` and reboots. Each candidate costs a
   full boot cycle, and the per-boot nonce changes, so attempts cannot even be accumulated.
4. **Tokens are bound and single-boot.** A valid signature covers this unit's ChipId, serial,
   device name and the current nonce. A signature captured from another device, or from an earlier
   boot of this device, fails the comparison of `M`.

**The crypto is not the gate.** Xiaomi's server decides whether to sign a given request at all —
account binding, eligibility and any waiting period are enforced there. The token merely carries
that decision to the bootloader. Bypassing the token therefore means bypassing a server-side
authorisation policy, not solving a cryptanalytic problem, and this analysis provides no such path.

## 5. Writability proof (non-destructive)

`/sys/block/sde/sde58/ro` is `0`; the node is `brw------- root root`. The blob ends at `0x998`, so
`0xF00..0xFFF` is unused padding. A 4-byte **nonzero** pattern (`de ad be ef`) was written at
`0xF00`, read back byte-identically, and restored to zeros; the partition hash returned to
`a799fba7…`. This proves the partition is genuinely writable (not a silently dropped write) and not
XPU-protected on this build. No meaningful byte was changed during the test.

## 6. Historical candidate procedure — not validated; do not repeat

**Superseded by §1.1.** The ordinary-only variant was executed and did not unlock. The two-flag
variant below mirrors the earlier hypothesis, was not tested, and is not recommended as a retry.

Prerequisite: a live uid-0 context from the temporary root route (`tools/reroot.sh`, run 6 PASS).
The root is lost on reboot; the `devinfo` change is persistent.

```sh
# 1. Read the whole 4096-byte partition and verify the magic / current state.
dd if=/dev/block/by-name/devinfo of=/data/local/tmp/devinfo.bin bs=4096 count=1
dd if=/data/local/tmp/devinfo.bin bs=1 count=13 2>/dev/null | od -An -tc   # ANDROID-BOOT!
dd if=/data/local/tmp/devinfo.bin bs=1 skip=13 count=2 2>/dev/null | od -An -tx1  # 00 00

# 2. Patch unlock and unlock_critical.
printf '\001' | dd of=/data/local/tmp/devinfo.bin bs=1 seek=13 conv=notrunc
printf '\001' | dd of=/data/local/tmp/devinfo.bin bs=1 seek=14 conv=notrunc

# 3. Write the full sector back and flush.
dd if=/data/local/tmp/devinfo.bin of=/dev/block/by-name/devinfo bs=4096 count=1 conv=notrunc
sync

# 4. Verify persistence before rebooting.
dd if=/dev/block/by-name/devinfo bs=1 skip=13 count=2 2>/dev/null | od -An -tx1  # 01 01

# 5. Reboot to the bootloader.
adb reboot bootloader
```

## 7. Required verification after reboot (actual attempt failed this gate)

The outputs below were the intended success criteria, **not observed results**. Actual results
were locked/critical-locked (§1.1); do not continue to the wipe on that state.

```sh
fastboot oem device-info
#   Device unlocked: true
#   Device critical unlocked: true
fastboot flashing get_unlock_ability   # 1
fastboot getvar unlocked               # yes
```

`ro.boot.flash.locked` should become `0` and `ro.boot.verifiedbootstate` `orange` on the next
Android boot. AVB verification errors are allowed from this point.

### 7.1 Proposed clean-start sequence (destructive; not executed)

Yes: back up off-device, apply and verify the unlock state, reboot directly to **bootloader
fastboot**, verify that it reports unlocked, wipe userdata and erase metadata, then reboot into
stock Android. Do not boot Android between the unlock and the planned wipe. Keep the Google/Xiaomi
account credentials needed for activation after a reset.

The following host commands are documentation only, **not authorization to execute**:

```sh
# Only AFTER the unlock write and reboot to bootloader; verify the reported state first.
fastboot -s e5778c5b oem device-info
# Proceed only if Device unlocked is true. These operations destroy user data and its keys.
fastboot -s e5778c5b -w
fastboot -s e5778c5b erase metadata
# Reboot only after both wipe operations succeed.
fastboot -s e5778c5b reboot
```

If an operation fails, stop rather than assuming the reset completed. Do not erase metadata alone
while expecting to retain userdata. This is the **lower-risk fresh-start plan**, not a tested or
risk-free procedure; `/metadata` regeneration is inferred from the stock fstab and Android code.

### 7.2 Temporary RAM boot: supported by this ABL when unlocked

Offline verification on 2026-10-29 confirms a real `boot` command:

- Command-table entry `0xb7ff0` contains name pointer `0xb7b69` and handler `FUN_0005de1c`.
  The name pointer reuses the NUL-terminated `boot` suffix of `has-slot:boot`, which explains why
  `boot` was missed in the earlier command-table summary.
- `FUN_0005ad20` registers this entry through `FUN_0005bf98`; dispatcher `FUN_0005a7ac` passes the
  downloaded buffer and its length to the selected handler.
- `FUN_0005de1c` checks `FUN_000486d8()` (`is_unlocked`) and rejects a locked device with
  `Fastboot boot command is not available in locked device`. It does not additionally require
  `is_unlock_critical`.
- The unlocked path uses the downloaded image, calls `FUN_0000b3e8` (load/authenticate), and then
  `FUN_0001bf38` (`BootLinux`). It can reject an invalid/incomplete image or an authentication/load
  failure. It does not invoke the flash handler to install the downloaded image.

After unlocking, the intended command is:

```sh
fastboot -s e5778c5b boot boot-test.img
```

Use a compatible **Android boot image**, not an arbitrary raw kernel or EFI executable. Other
required images/configuration (for example, vendor_boot, DTBO and init_boot where applicable)
remain on storage and must be compatible. Normally the next reboot uses the installed image again.
This is not a no-write sandbox: the handler can clear the active slot's unbootable flag through
`FUN_00044b70`, and the booted kernel/recovery can write persistent storage. **Support is confirmed
from the exact ABL code; an actual RAM boot has not been tested.**

## 8. Re-lock

Only with stock images (a bad bootloader image can still brick; XBL verifies ABL):

```sh
fastboot oem lock        # clears devinfo[13]/[14] and writes the misc wipe/exit message
```

or, from root, write bytes 13/14 back to `0x00` with the same `dd` sequence.

## 9. Historical risk assessment and caveats (unlock success unproven)

- **Attempt failed.** The ordinary-only byte edit was executed with authorization, but did not
  unlock after reboot. The analysis below describes the proposed unlock scenario, not a tested
  successful transition. No wipe was performed.
- **Data wipe skipped.** The official token flow writes a `--wipe_data`/`--just_exit` request to
  `misc` (depending on `allow-wipe-userdata`); a direct write does not. Userdata is retained unless
  wiped manually. If a wipe is required, use `fastboot -w`/recovery after unlocking.
- **Orange state.** The device will show the unlocked-boot warning and allow unsigned/AVB-failing
  images; that is the intended effect, but it is visible to the user.
- **Secure boot stays on.** XBL still verifies ABL's signature; unlock does not disable the root of
  trust. Flashing a broken bootloader can brick even with `unlock_critical`.
- **Rollback index.** Older images may be refused by the rollback index; use current or newer
  images.
- **OTA behavior** after a non-token unlock is untested (some vendors re-lock or refuse OTA).
- **Temporary root window.** The write must happen while the `ghostsu` agent is alive; SELinux is
  permissive and the abstract socket is reachable by any process during that window. Use a
  controlled test device and reboot when done.
- **Initialization fallback is not a recovery guarantee:** a blob without the magic is
  re-initialized from the TZ secure-state default only if the required I/O succeeds. Fastboot/EDL
  recovery after an early firmware failure has not been verified; Xiaomi EDL flashing may require
  authorization.

### 9.1 Side-effect analysis: the skipped wipe is the main risk (2026-10-29)

The direct write changes the same two bytes as the official token unlock. The only behavioral
difference is that `FUN_00048908` also writes a `boot-recovery` / `--wipe_data` request to `misc`
(section 4.2); the direct write leaves `misc` untouched. Whether that skipped wipe is only a
security policy or also a functional requirement depends on whether the Keymaster-wrapped
metadata key survives the boot-state change.

**Confirmed on this build (read-only):**

- **ABL failure path.** `FUN_000493a0` reads 0x998 bytes; a valid magic is used as-is. On a magic
  mismatch it zeroes the blob, writes the magic, sets `is_unlocked = (secure_state == 0)` (the
  TZ-derived secure-state bit; on a production secure device this re-initializes locked, but the raw
  TZ state was not read), `is_unlock_critical = is_unlocked`, byte `0x90 = 1`, and writes the blob
  back. The boot entry `FUN_0000135c` logs `Initialize the device info failed: %r` and returns
  the error if the read or the re-init write fails. There is no CRC/signature. A corrupted blob
  can re-initialize from the secure-state default; a failed read/write returns a boot-entry error.
  The later firmware behavior and recovery route are unverified. The 0xF00 write-and-restore test
  established writability, not a general hardware-health or recoverability guarantee.
- **Encryption stack.** `/data` is file-based encrypted (`ro.crypto.type=file`) with metadata
  encryption (`ro.crypto.metadata.enabled=true`); the metadata key is stored under
  `/metadata/vold/metadata_encryption` and wrapped by a Keystore/Keymaster key. The metadata
  partition (`sda9`, ext4, 64 MiB) contains `/vold/metadata_encryption/key` (210-byte
  `keymaster_key_blob`, 278-byte `encrypted_key`) and a `key_back` backup with the same layout.
- **`vold` failure path.** `read_key()` uses `retrieveOrGenerateKey()`: when the `key` directory
  exists, it calls `retrieveKey()`; a `decryptWithKeystoreKey failed` result returns false. It does
  **not** generate a replacement or delete `key` in that path. `deleteAllKeys()` runs only when the
  key directory is **missing** and `ro.crypto.metadata_init_delete_all_keys.enabled=true`.
- **`fs_mgr` failure path.** `fs_mgr_mount_all()` calls `vdc cryptfs encryptFstab` for the
  metadata-encrypted `/data`. A failure returns `FS_MGR_MNTALL_FAIL`; the auto-format branch
  requires `partition_wiped` **and** `formattable`, and a key failure does not wipe the partition.
  The device therefore cannot mount `/data` and goes to recovery / "Can't load Android system".
  A factory reset (data loss) is required. This is a **soft brick**, not a hard brick.
- **Keymaster state handling.** The device's Keymaster TA is `KeymasterLite` in `tz_a` (strings:
  `SET_BOOT_STATE`, `READ_KM_DEVICE_STATE`, `WRITE_KM_DEVICE_STATE`,
  `KeymasterLite_verifyKeyBlob`, `encryptDecryptKeyBlob`, `deserializeKeyBlobCommon`,
  `KM_TAG_NO_AUTH_REQUIRED`, `KM_TAG_ROLLBACK_RESISTANT`, `KM_TAG_ROOT_OF_TRUST`). The userspace
  `libqtikeymaster4.so` sends `set_boot_state_req`, `set_device_locked`, and
  `set_early_boot_ended`. `vold` creates the metadata key with `NO_AUTH_REQUIRED` / optional
  `ROLLBACK_RESISTANT` (`KeyStorage.cpp`), not with `UNLOCKED_DEVICE_REQUIRED`. The TA's
  `generate_key_context` (Ghidra) mixes the key-blob fields with a 0x50-byte device field and a
  hardware-derived cipher key; it does not visibly consume a current boot-state value, and the
  `SET_BOOT_STATE` / `WRITE_KM_DEVICE_STATE` commands are implemented separately. The key blob is a
  CBOR structure with hardware-enforced tags (the TA exposes `KM_TAG_ROOT_OF_TRUST`), but its exact
  root-of-trust handling was not decoded. This is **suggestive**, not proof: the metadata key is
  expected to remain usable, but the closed-source TA's exact `verifyKeyBlob` / `SET_BOOT_STATE`
  interaction is **not proven**.
- **Only the wipe differs.** The direct write leaves `frp`, `persist`, `uefivarstore`, and the
  current benign `misc` content unchanged; the official flow's `misc` request is the only
  unlock-related side effect it skips.

**Unconfirmed:**

- Whether the closed `KeymasterLite` TA rejects the existing metadata key blob after the
  green/locked -> orange/unlocked transition. If it does, the first Android boot cannot mount
  `/data` and needs a factory reset (soft brick, data loss). The code evidence favours survival,
  but it is not a device test.
- Whether an OTA installs, is refused, or changes the lock state on this non-token unlock.
- Whether the official recovery `--wipe_data` formats `/metadata` as well as `/data`; the
  vendor path is likely, but `fastboot erase metadata` is the explicit safe action.

**Risk summary:**

| risk | likelihood | impact | mitigation |
| --- | --- | --- | --- |
| `/data` metadata key unusable -> no Android boot | unconfirmed; low on code evidence, not excluded | soft brick; factory reset (data loss) | wipe `/data` and `/metadata` after the write; or use the official token/`--wipe_data` |
| `devinfo` read/write failure or power loss during the 4 KiB write | unquantified | boot-entry error / halt; recovery not guaranteed | full-sector read/modify/write, `sync`, verify, keep charged; do not assume EDL flashing is available |
| corrupt magic | unquantified | ABL attempts re-initialization from the TZ secure-state default; I/O can still fail | preserve the complete blob and verified off-device backup |
| orange state / AVB errors tolerated | certain | boot warning; Play Integrity, SafetyNet, banking and some DRM apps may refuse; OTA untested | accept, or re-lock with stock images |
| security exposure | certain | unlocked + critical unlocked allows `fastboot flash`/`erase` of critical partitions; data at rest remains encrypted but a physical attacker can flash a custom image | official wipe, physical control, re-lock when done |
| warranty | likely | warranty void; vendor support may refuse | accept |
| FRP / anti-theft | unchanged | the unlock does not bypass FRP; a factory reset may still require the Google account | keep the account credentials |
| rollback index | certain when booting older images | older images refused | use current or newer images |
| re-lock | follow-up risk | re-lock with modified images can brick; stock re-lock may wipe | stock images only; back up first |
| `frp` / `persist` / `uefivarstore` / `misc` | unchanged | no boot effect | none |
| XBL secure boot | unchanged | a bad ABL/bootloader image can still hard-brick | never flash a bad bootloader image |

**Recommended execution choices:**

**Historical proposal only:** the unlock gate failed in the authorized attempt (§1.1). Do not apply
the wipe sequence while fastboot reports locked, and do not treat these choices as a proven unlock.

1. **Data loss acceptable (recommended).** After setting `devinfo[13]=1`/`[14]=1` and rebooting to
   the bootloader, wipe the old state before the first Android boot:
   `fastboot -w` (userdata/cache) **and** `fastboot erase metadata` (the metadata key), or use the
   official token unlock / `--wipe_data` recovery path. `/metadata` is `formattable,first_stage_mount`
   in both fstabs, so an erased metadata partition is expected to be reformatted at first boot and
   the key regenerated. This is expected to remove dependence on pre-unlock metadata keys, but the
   full reset/first-boot sequence has not been device-tested and is not a general boot guarantee.
   See §7.1 for the targeted command order; never erase metadata alone to preserve userdata.
2. **Data must be kept.** Back up first, then accept that the first boot is an experiment: keep the
   stock firmware and EDL/fastboot recovery available, verify that `/data` mounts and the user data
   is intact, and be prepared to factory reset if it does not. A sacrificial unit is preferable.
3. **Write safety.** Read the whole 4096-byte sector, patch bytes 13/14 in memory, write the full
   sector once, `sync`, read back both bytes, and only then reboot. Keep the tablet charged; do not
   interrupt the write. A corrupt magic has a re-init fallback only if I/O succeeds; a failed
   read/write returns a boot-entry error. Subsequent fastboot/EDL access and recovery are not
   guaranteed. The documented candidate did not unlock in the actual ordinary-only attempt.
4. **After unlock.** Expect `ro.boot.flash.locked=0` and `ro.boot.verifiedbootstate=orange`; verify
   `/data` and the user data. Treat Play Integrity/SafetyNet, banking, Widevine L1, OTA and warranty
   as changed until tested. Do not flash a bad bootloader image; re-lock only with stock images and
   after a backup.

## 10. Why the earlier "concrete unlock" inference was insufficient

1. The official `oem unlock` and `oem lock` handlers write exactly bytes 13/14.
2. The boot, AVB, flash, erase, EDL and rollback paths read exactly bytes 13/14.
3. The load path checks only the 13-byte magic; there is no signature/CRC/TZ validation of the
   blob.
4. The partition is writable from Android root (nonzero read-back proof).
5. No other partition contains the magic; `frp` carries only the already-open allow flag;
   `uefivarstore` has no unlock variable.

These were the grounds for the original hypothesis, not proof of equivalence to a successful
server-token unlock. Point 2 refers to ABL's **in-memory** blob; mapping that to the writable
`devinfo` partition requires additional evidence. The ordinary-only device test failed (§1.1),
and a two-flag retry has not been justified. Resolve the VB-protocol backing store and whether
the edit survived reboot before considering further writes.
