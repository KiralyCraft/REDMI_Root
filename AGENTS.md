# AGENTS.md — REDMI_Root working guide

## Read the ledger first

Before doing anything in this repository, **read [LEDGER.md](LEDGER.md)**. It is the running record of
investigation findings, derivations, machine state, and open questions. Do not redo work that the
ledger already records as done or verified; do not contradict it without new evidence, and append a
dated entry whenever you verify, derive, or change something.

## Standing constraints

- **Devices:** two Android devices are connected via adb. The tablet (`dizi`, serial varies — see the
  ledger) is the target. **The other device (`a37b82`, msm8916) must never be touched** — no adb
  commands, no file pushes, no device state changes, not even read-only ones.
- Device work is read-only until a device gate run is explicitly authorized by the user; gate runs
  can panic the kernel and reboot the device.
- Profiles are build-exact: a profile derived for one kernel build must never be used against a
  different build, even a nearby stable point release.
- Anything that cannot be derived offline (empirical gate fields) is recorded in the ledger as
  *unconfirmed*, not assumed.

## Current focus

Deriving a profile for the tablet's actual kernel build (`5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661`)
and validating it against the device, per the status and open items in LEDGER.md.
