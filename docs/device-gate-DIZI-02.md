# DIZI-02 device gate: dizi 5.10.209 temporary root via `ghostsu` — PASS

Gate for the `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` build, using the
temporary-root channel described in [`LEDGER.md`](../LEDGER.md) (2026-10-29 entry).

## Device and artifacts

- Model 2405CRPFDC (Redmi Pad Pro, `dizi`, SM7435); `uname -r` =
  `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661`; Android 14, OS1.0.19.0.UNSCCNXM,
  patch 2024-12-01; SELinux enforcing before the run.
- Target device serial `e5778c5b` only (never `a37b82`).
- Exploit `build/native/ghostlock` sha256
  `14cb155faafee0e48d9b3e75b07a6daa5e8217515778ebd127f0b45fe5c0ba4f` (the same binary that
  produced the 2026-10-28 run 5 log).
- Profile `profiles/5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661.bin` sha256
  `c343b7e1157617c48c776ea0413d905c9d9558999bee3d270d8e781989213953`.
- Root agent/client `build/native/ghostsu` (built with NDK 27c locally; the exploit binary
  was *not* rebuilt).
- Handoff shim `tools/ksud-agent-shim.sh`, installed at `/data/local/tmp/ksud`.

## Flow

1. `tools/reroot.sh` pushes the exploit, the profile, `ghostsu` (also as
   `/data/local/tmp/su`) and the shim, then runs the two-stage W1/W2 loop.
2. W1 makes SELinux permissive; W2 overwrites the victim child's `cred` with uid 0.
3. The rooted handoff script runs as uid 0 and executes `/data/local/tmp/ksud ...`
   (KernelSU's `late-load`, which cannot work here). The shim starts
   `/data/local/tmp/ghostsu --agent` and chains to a real ksud if present.
4. `reroot.sh` declares success when `/data/local/tmp/su -c id` reports `uid=0`.

## Result — PASS (run 6)

Run 6 started cold at 07:56; attempt 9 passed W1, and W2 landed on the first try (08:06).
Log: `/tmp/opencode/gate-209-agent-run6.log` (host-side; not committed).

```
== ROOTED (attempt 9, try 1)
uid=0(root) gid=1514833792(u15148_a3792_ext) ... context=u:r:kernel:s0
Uid: 0 0 0 0
CapEff: 000001ffffffffff
```

Device-side evidence:

- `/data/local/tmp/.ghostlock_ksu.log`:
  `[*] ghostsu agent running: /data/local/tmp/su -c id` (inside the `late-load` step).
- `/data/local/tmp/.ghostsu.log`: `[*] agent start uid=0 label=u:r:kernel:s0`.
- `su -c id` from a later adb session still works (the agent outlives the exploit).
- `su -c 'ls /data/misc/keystore'` and `su -c dmesg` succeed; AVC denials record
  `permissive=1`.
- Interactive path: `adb shell /data/local/tmp/su` gives a `dizi:/ #` shell; `id -u` → 0.

## Caveats (read before using)

- **Temporary:** a reboot removes the agent and restores enforcing. This is not a
  persistent root and does not touch any partition.
- **Permissive while active:** the exploit's W1 leaves SELinux permissive; the agent keeps
  it that way. Any process on the device can reach the abstract socket `ghostsu.v1` during
  that window. Use it only in a controlled test, and reboot when done.
- **Credential artifact:** the rooted cred has uid 0 but gid/groups `1514833792` instead of
  0. Full capabilities and permissive SELinux make the commands tested here work, but this
  is not pristine `init_cred`; it is recorded as an open observation, not a claimed
  property.
- KernelSU's module is still attempted by the handoff and still fails
  (`ksud late-load` needs a KernelSU driver that this stock kernel does not have). A custom
  module would need a CFI+LTO build; see the ledger open item.

## Reproduce

```bash
make -C src ghostlock ghostsu     # NDK 29 on ResearchVM for the exploit, NDK 27+ locally
SERIAL=e5778c5b tools/reroot.sh --check
SERIAL=e5778c5b tools/reroot.sh
# when it prints ROOTED:
adb -s e5778c5b shell '/data/local/tmp/su -c id'
adb -s e5778c5b shell '/data/local/tmp/su'
```
