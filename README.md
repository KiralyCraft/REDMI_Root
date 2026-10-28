# REDMI_Root — kernel root for the Redmi Pad Pro

<div align="center">

[![Bilibili homepage](https://img.shields.io/badge/Bilibili-channel-00A1D6?style=for-the-badge&logo=bilibili&logoColor=white)](https://space.bilibili.com/22940901)

📺 **Follow my Bilibili channel: <https://space.bilibili.com/22940901>** 📺

</div>

A one-click kernel root tool for the **Redmi Pad Pro / POCO Pad (dizi, codename parrot)**.
It is based on CVE-2026-43499 (futex PI UAF, using the `select_stack` route from
[YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)) and has been fully
adapted and verified on real hardware.

- Device: Redmi Pad Pro (2405CRPFDC) / POCO Pad
- Kernels:
  - `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284` — HyperOS 3 (Android 16),
    device gate passed twice in a row (`docs/device-gate-DIZI-01.md`).
  - `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` — HyperOS 1.0.19.0.UNSCNXM
    (Android 14). The profile was derived offline from that build's own kernel image
    (kallsyms + pointer-chase anchors + device-verified stack frames); it has **not**
    been through a device gate run yet, so no device-gate record exists for it.
- Result: temporary root + KernelSU (jailbreak mode / LKM; no bootloader unlock, no boot
  image modification)
- Device gate: two consecutive cold-boot end-to-end passes (record in
  `docs/device-gate-DIZI-01.md`)

A profile is never used across builds: `tools/reroot.sh` reads `uname -r` from the device
and refuses to run when no profile for that exact build exists.

> 📖 **Beginner-friendly walkthrough / full reproduction guide** (diagrams and
> line-by-line script explanation): [docs/tutorial.md](docs/tutorial.md)

## How it works (short version)

The kernel's `remove_waiter()` operates on the wrong task during the PI-futex rollback
path (CVE-2026-43499). The tool reuses a pselect stack frame to forge an
`rt_mutex_waiter` and triggers a controlled kernel write while the PI chain is being
re-prioritized: **W1** turns SELinux off, **W2** overwrites the child process's `cred`
with `init_cred` (uid 0), then **W3** loads the KernelSU kernel module. Everything is a
pure data write; control flow protected by CFI is never touched.

## Requirements

- The device model and kernel version listed above (check Settings → About tablet →
  Kernel version)
- A computer (macOS / Linux) with **Android SDK Platform-Tools** (adb) installed
- **USB debugging** enabled on the tablet (Developer options)
- [KernelSU manager](https://github.com/tiann/KernelSU/releases) APK installed on the
  tablet (the root script extracts `ksud` from the manager APK to load the module)

## Build

```bash
# Install the Android NDK (any of the usual ways), then:
./build.sh
```

Output: `build/native/ghostlock`. The script probes common NDK locations; you can also
point it explicitly: `ANDROID_NDK_HOME=/path/to/ndk ./build.sh`.

Profiles are prebuilt (`profiles/*.bin`); a matching `.conf` is shipped next to each one
for reference, so regenerating them is normally unnecessary.

## Usage

```bash
# Connect the tablet over USB, then:
tools/reroot.sh
```

The script runs the whole flow automatically. The **tablet may reboot a few times**
during the run, which is normal: the exploit's heap reclaim is probabilistic (roughly a
1/3–1/2 chance per attempt), and the script retries until it succeeds. When you see
`ROOTED + KernelSU active`, you are done. In practice this usually takes a few minutes to
about twenty minutes.

Root is **jailbreak mode (lost on reboot)**: just run `reroot.sh` again after a reboot.
KernelSU modules and their authorization state live in `/data/adb` and are restored
automatically after re-rooting.

## FAQ

- **The tablet rebooted during the run?** That is expected (a missed attempt panics the
  kernel); the script waits for the device to come back and continues.
- **It keeps failing?** Make sure the kernel version matches exactly. A different
  MIUI/HyperOS build ships a different kernel and cannot use this profile.
- **How do I go back to stock?** A reboot returns the device to the unrooted state. No
  partition is ever written, so nothing persists (except the KernelSU configuration in
  `/data/adb`, which can be removed from the manager).

## Disclaimer

**Read [DISCLAIMER.md](DISCLAIMER.md) (legal disclaimer & acceptable-use notice) before
using this tool.**

In short: this tool is intended for security research, authorized testing and **devices
you own**. Running it can panic and reboot the device kernel (no partition is written, so
the risk is limited to data loss). Using this tool means you agree to every clause of
DISCLAIMER.md; you are responsible for the consequences.

## Credits and license

- Upstream project: [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)
- Vulnerability research: NebuSec (kernelCTF) and the community adapters
- Released under the Apache License 2.0 (see `LICENSE`). The source contains modified
  parts of the upstream project (dizi adaptation, 5.10 select route fixes, etc.); see
  `docs/adaptation-plan.md` for details.
