# DIZI bootloader unlock: the `devinfo` state is unauthenticated

Status: **path identified and verified read-only on 2026-10-29; not executed** (per the user
directive "don't run the unlock"). This document records how the Redmi Pad Pro bootloader decides
it is unlocked, why the stored state can be written from Android root, and the exact procedure to
execute later in a controlled window.

Target: `dizi` / 2405CRPFDC (Redmi Pad Pro, SM7435), firmware `V816.0.19.0.UNSCNXM`,
kernel `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661`. Device serial `e5778c5b` only;
`a37b82` must never be touched.

## 1. Result in one paragraph

The bootloader's unlock state lives in the **`devinfo`** partition
(`/dev/block/by-name/devinfo` → `/dev/block/sde58`, 4096 bytes, GPT #58 on LUN 4), not in `frp`.
It is the persisted 0x998-byte `ANDROID-BOOT!` blob: byte 13 (`0x00d`) is `is_unlocked`, byte 14
(`0x00e`) is `is_unlock_critical`. ABL checks only the 13-byte magic — no signature, CRC, or
TrustZone state is consulted for the blob itself. The partition is a normal writable block device
from Android root on this build. Therefore, with the temporary root from the kernel route, writing
`devinfo[13] = 1` (and `[14] = 1` for critical partitions) is semantically identical to a
token-verified `fastboot oem unlock`: at the next boot ABL reports the device unlocked, allows AVB
verification errors, and permits `fastboot flash`/`erase`.

This is also the bootloader weakness: the server signature gates the *command*, not the *storage*.
Any uid-0 context can flip the persistent state without Xiaomi's token.

## 2. Device state observed (read-only)

```
ro.boot.flash.locked        = 1
ro.boot.verifiedbootstate   = green
ro.boot.vbmeta.device_state = locked
sys.oem_unlock_allowed      = 1
ro.oem_unlock_supported     = 1
```

`frp`'s last byte is `0x01` (the "OEM unlocking" developer-option gate is already open). The device
is locked (`devinfo[13] = 0`), so the missing piece is only the persisted unlock state.

## 3. Partition dumps

Dumps were streamed through the live `ghostsu` root and each device stream was checked against an
on-device `sha256sum` of the same block device. Host copies live in `/tmp/opencode/dizi-dumps/` and
are not committed.

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
  back. A corrupted blob therefore re-initializes from the secure-state default, not bricked.

### 4.2 Setters and the official paths

| function | effect |
| --- | --- |
| `FUN_00048e10(v)` | sets `devinfo[13] = v`, persists the blob |
| `FUN_00048ee8(v)` | sets `devinfo[14] = v`, persists the blob |
| `FUN_000486d8()` | returns `devinfo[13]` |
| `FUN_000486e8()` | returns `devinfo[14]` |
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

The full fastboot command table at `0xb7f80` was enumerated (`flash:`, `erase:`, `set_active`,
`flashing get_unlock_ability`, `oem unlock`, `oem lock`, charger/display/device-info/poweroff/
fbreason/uart/getguid/edl/erase-vb-index/log commands, `getvar:`, `download:`, …). No locked-state
command writes `devinfo` or bypasses the token; `oem unlock` is the only token path.

## 5. Writability proof (non-destructive)

`/sys/block/sde/sde58/ro` is `0`; the node is `brw------- root root`. The blob ends at `0x998`, so
`0xF00..0xFFF` is unused padding. A 4-byte **nonzero** pattern (`de ad be ef`) was written at
`0xF00`, read back byte-identically, and restored to zeros; the partition hash returned to
`a799fba7…`. This proves the partition is genuinely writable (not a silently dropped write) and not
XPU-protected on this build. No meaningful byte was changed during the test.

## 6. Procedure (identified, not executed)

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

## 7. Verification after reboot

```sh
fastboot oem device-info
#   Device unlocked: true
#   Device critical unlocked: true
fastboot flashing get_unlock_ability   # 1
fastboot getvar unlocked               # yes
```

`ro.boot.flash.locked` should become `0` and `ro.boot.verifiedbootstate` `orange` on the next
Android boot. AVB verification errors are allowed from this point.

## 8. Re-lock

Only with stock images (a bad bootloader image can still brick; XBL verifies ABL):

```sh
fastboot oem lock        # clears devinfo[13]/[14] and writes the misc wipe/exit message
```

or, from root, write bytes 13/14 back to `0x00` with the same `dd` sequence.

## 9. Risks and caveats

- **Not executed.** This document records the identified path and read-only evidence; the byte was
  not flipped.
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
- **Corruption is recoverable:** a blob without the magic re-initializes from the TZ secure-state
  default (expected locked), not bricked.

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
  therefore re-initializes from the secure-state default; a failed read/write is a boot-entry error
  that may halt/enter fastboot or EDL. It is not a data change, and the partition is healthy (the
  0xF00 write-and-restore test passed).
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
| `devinfo` read/write failure or power loss during the 4 KiB write | very low on healthy UFS; higher if power is interrupted | boot-entry error / halt; fastboot or EDL recovery | full-sector read/modify/write, `sync`, verify, keep charged, do not interrupt |
| corrupt magic | low | ABL re-initializes the blob from the TZ secure-state default (expected locked; raw TZ state not read) | the blob is magic-only; the re-init does not brick |
| orange state / AVB errors tolerated | certain | boot warning; Play Integrity, SafetyNet, banking and some DRM apps may refuse; OTA untested | accept, or re-lock with stock images |
| security exposure | certain | unlocked + critical unlocked allows `fastboot flash`/`erase` of critical partitions; data at rest remains encrypted but a physical attacker can flash a custom image | official wipe, physical control, re-lock when done |
| warranty | likely | warranty void; vendor support may refuse | accept |
| FRP / anti-theft | unchanged | the unlock does not bypass FRP; a factory reset may still require the Google account | keep the account credentials |
| rollback index | certain when booting older images | older images refused | use current or newer images |
| re-lock | follow-up risk | re-lock with modified images can brick; stock re-lock may wipe | stock images only; back up first |
| `frp` / `persist` / `uefivarstore` / `misc` | unchanged | no boot effect | none |
| XBL secure boot | unchanged | a bad ABL/bootloader image can still hard-brick | never flash a bad bootloader image |

**Recommended execution choices:**

1. **Data loss acceptable (recommended).** After setting `devinfo[13]=1`/`[14]=1` and rebooting to
   the bootloader, wipe the old state before the first Android boot:
   `fastboot -w` (userdata/cache) **and** `fastboot erase metadata` (the metadata key), or use the
   official token unlock / `--wipe_data` recovery path. `/metadata` is `formattable,first_stage_mount`
   in both fstabs, so an erased metadata partition is expected to be reformatted at first boot and
   the key regenerated. The first Android boot then creates a fresh metadata key under the unlocked
   state, so the key-binding question cannot soft-brick the device. This is the only procedure that
   removes the main uncertainty.
2. **Data must be kept.** Back up first, then accept that the first boot is an experiment: keep the
   stock firmware and EDL/fastboot recovery available, verify that `/data` mounts and the user data
   is intact, and be prepared to factory reset if it does not. A sacrificial unit is preferable.
3. **Write safety.** Read the whole 4096-byte sector, patch bytes 13/14 in memory, write the full
   sector once, `sync`, read back both bytes, and only then reboot. Keep the tablet charged; do not
   interrupt the write. A corrupt magic re-initializes from the TZ secure-state default (expected
   locked), not a brick; a failed read/write is a boot-entry error recoverable through fastboot/EDL,
   not an automatic data wipe.
4. **After unlock.** Expect `ro.boot.flash.locked=0` and `ro.boot.verifiedbootstate=orange`; verify
   `/data` and the user data. Treat Play Integrity/SafetyNet, banking, Widevine L1, OTA and warranty
   as changed until tested. Do not flash a bad bootloader image; re-lock only with stock images and
   after a backup.

## 10. Why this counts as the concrete unlock

1. The official `oem unlock` and `oem lock` handlers write exactly bytes 13/14.
2. The boot, AVB, flash, erase, EDL and rollback paths read exactly bytes 13/14.
3. The load path checks only the 13-byte magic; there is no signature/CRC/TZ validation of the
   blob.
4. The partition is writable from Android root (nonzero read-back proof).
5. No other partition contains the magic; `frp` carries only the already-open allow flag;
   `uefivarstore` has no unlock variable.

Together these make a direct `devinfo[13]=1, [14]=1` write equivalent to a successful server-token
unlock, with the one behavioral difference that the data wipe is not requested.
