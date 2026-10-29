#!/bin/bash
# dizi one-shot re-root: connect the tablet over USB and run this script.
# It performs W1 (SELinux permissive) -> W2 (cred root) -> KernelSU module reload.
# Previously installed modules and their authorization state are restored automatically.
# The tablet may reboot several times during the run (normal; USB reconnects on its own).
# You are done when you see ROOTED.
#
# Usage:
#   tools/reroot.sh                 # auto-select the only attached device
#   SERIAL=<adb-serial> tools/reroot.sh
#   tools/reroot.sh --check         # read-only preflight, runs nothing on the device
cd "$(dirname "$0")/.." || exit 1

BIN=build/native/ghostlock
AGENT=build/native/ghostsu
SHIM=tools/ksud-agent-shim.sh
# Select the profile for the device's real kernel build before every push
# (build-exact; never reuse a profile across builds).
# PROFILE=... explicitly overrides the selection, but the file must exist.
PROFILE="${PROFILE:-}"
# Which device to operate on. Refusing to guess when several are attached keeps
# unrelated devices out of reach.
SERIAL="${SERIAL:-${ANDROID_SERIAL:-}}"
CHECK=0
[ "$1" = "--check" ] && CHECK=1

adb_target() {
    if [ -n "$SERIAL" ]; then
        adb -s "$SERIAL" "$@"
    else
        adb "$@"
    fi
}

# 0 = target selected, 1 = no device online yet, 2 = ambiguous (several devices)
select_device() {
    if [ -n "$SERIAL" ]; then
        return 0
    fi
    local list n
    list=$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device"{print $1}')
    n=$(printf '%s\n' "$list" | grep -c . || true)
    [ "$n" -eq 0 ] && return 1
    if [ "$n" -gt 1 ]; then
        echo "!! multiple devices attached:"
        printf '   %s\n' $list
        echo "   set SERIAL=<serial> to pick the tablet (nothing was sent)"
        return 2
    fi
    SERIAL="$list"
    echo "== device: $SERIAL"
    return 0
}

resolve_profile() {
    if [ -n "$PROFILE" ]; then
        [ -f "$PROFILE" ] || { echo "!! PROFILE does not exist: $PROFILE"; return 1; }
        return 0
    fi
    local model uname_r
    model=$(adb_target shell getprop ro.product.device 2>/dev/null | tr -d '\r')
    if [ -n "$model" ] && [ "$model" != "dizi" ] && [ "${ALLOW_ANY_DEVICE:-0}" != "1" ]; then
        echo "!! attached device is '$model', not 'dizi' (set ALLOW_ANY_DEVICE=1 to override)"
        return 1
    fi
    uname_r=$(adb_target shell uname -r 2>/dev/null | tr -d '\r')
    [ -z "$uname_r" ] && { echo "!! failed to read uname -r from the device"; return 1; }
    PROFILE="profiles/${uname_r}.bin"
    [ -f "$PROFILE" ] || {
        echo "!! no profile for this kernel build: $uname_r"
        echo "   expected file: $PROFILE"
        echo "   (refusing to use a profile from another build)"
        return 1
    }
    echo "== profile: $PROFILE"
}

wait_device() {
    while true; do
        select_device
        case $? in
            2) exit 1 ;;
            0)
                if adb_target get-state 2>/dev/null | grep -q device; then
                    if [ "$(adb_target shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
                        return 0
                    fi
                fi
                ;;
        esac
        sleep 5
    done
}

# A parked rooted child keeps the adb shell's stdout open, so a failed handoff
# can block forever. Bound every exploit invocation and reap leftovers.
adb_shell_timeout() {
    local secs=$1
    shift
    if [ -n "$SERIAL" ]; then
        timeout "$secs" adb -s "$SERIAL" shell "$@"
    else
        timeout "$secs" adb shell "$@"
    fi
}

cleanup_strays() {
    adb_target shell 'pkill -9 -f /data/local/tmp/ghostlock 2>/dev/null; pkill -9 ghostleaf 2>/dev/null; true' >/dev/null 2>&1
}

push_all() {
    resolve_profile || exit 1
    [ -f "$BIN" ] || { echo "!! missing binary: $BIN (build it on the build machine and copy it back)"; exit 1; }
    [ -f "$AGENT" ] || { echo "!! missing binary: $AGENT (make -C src ghostsu)"; exit 1; }
    [ -f "$SHIM" ] || { echo "!! missing shim: $SHIM"; exit 1; }
    adb_target push "$BIN" /data/local/tmp/ghostlock >/dev/null 2>&1
    adb_target push "$AGENT" /data/local/tmp/ghostsu >/dev/null 2>&1
    adb_target push "$PROFILE" /data/local/tmp/profile.bin >/dev/null 2>&1
    adb_target shell 'chmod 755 /data/local/tmp/ghostlock /data/local/tmp/ghostsu && cp /data/local/tmp/ghostsu /data/local/tmp/su && chmod 755 /data/local/tmp/su' 2>/dev/null
    # The handoff script runs /data/local/tmp/ksud as uid 0. Preserve a real
    # ksud (if one is there) and install the shim that starts the agent.
    adb_target shell 'if [ -f /data/local/tmp/ksud ] && ! grep -q ghostsu /data/local/tmp/ksud 2>/dev/null; then mv -f /data/local/tmp/ksud /data/local/tmp/ksud.real; fi' >/dev/null 2>&1
    adb_target push "$SHIM" /data/local/tmp/ksud >/dev/null 2>&1
    adb_target shell 'chmod 755 /data/local/tmp/ksud' 2>/dev/null
}

# Root channel probe: the ghostsu agent first (temporary, userspace), then
# KernelSU's su if the module happens to be active.
root_id() {
    adb_target shell '/data/local/tmp/su -c id 2>/dev/null || su -c id 2>/dev/null' 2>/dev/null | tr -d '\r'
}

# Read-only preflight: proves the device, the profile and the binary line up
# without pushing anything or running the exploit.
if [ "$CHECK" = "1" ]; then
    wait_device
    uname_r=$(adb_target shell uname -r 2>/dev/null | tr -d '\r')
    model=$(adb_target shell getprop ro.product.device 2>/dev/null | tr -d '\r')
    rel=$(adb_target shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
    patch=$(adb_target shell getprop ro.build.version.security_patch 2>/dev/null | tr -d '\r')
    enf=$(adb_target shell cat /sys/fs/selinux/enforce 2>/dev/null | tr -d '\r')
    echo "== device:  $SERIAL"
    echo "== model:   $model"
    echo "== android: $rel (patch $patch)"
    echo "== kernel:  $uname_r"
    echo "== selinux: enforcing=$enf"
    resolve_profile || exit 1
    [ -f "$BIN" ] || { echo "!! missing binary: $BIN"; exit 1; }
    [ -f "$AGENT" ] || { echo "!! missing binary: $AGENT"; exit 1; }
    echo "== binary:  $BIN ($(stat -c %s "$BIN") bytes, sha256 $(sha256sum "$BIN" | cut -d' ' -f1))"
    echo "== agent:   $AGENT ($(stat -c %s "$AGENT") bytes, sha256 $(sha256sum "$AGENT" | cut -d' ' -f1))"
    echo "== shim:    $SHIM (starts the agent from the rooted ksud path)"
    echo "== profile: $PROFILE ($(stat -c %s "$PROFILE") bytes, sha256 $(sha256sum "$PROFILE" | cut -d' ' -f1))"
    echo "== preflight OK (nothing was pushed, nothing was executed)"
    exit 0
fi

ATTEMPT=0
while true; do
    ATTEMPT=$((ATTEMPT+1))
    wait_device
    cleanup_strays

    # Already rooted: nothing to do
    if root_id | grep -q "uid=0"; then
        echo "== root active, nothing to do"
        root_id | head -1
        exit 0
    fi

    ENF=$(adb_target shell "cat /sys/fs/selinux/enforce" 2>/dev/null | tr -d '\r')
    if [ "$ENF" != "0" ]; then
        # phase 1: W1 -> permissive
        echo "== attempt $ATTEMPT: W1 (SELinux) $(date '+%H:%M:%S')"
        push_all
        adb_shell_timeout 240 "cd /data/local/tmp && ./ghostlock --load-prebuilt-profile /data/local/tmp/profile.bin --stop-after-w1" > /dev/null 2>&1
        cleanup_strays
        ENF=$(adb_target shell "cat /sys/fs/selinux/enforce" 2>/dev/null | tr -d '\r')
        if [ "$ENF" != "0" ]; then
            echo "   W1 missed (the device may have rebooted; waiting for reconnect...)"
            sleep 3
            continue
        fi
        echo "   W1 succeeded (permissive)"
    fi

    # phase 2: W2 -> root -> KernelSU reload (retry inside the permissive boot)
    for i in $(seq 1 25); do
        wait_device
        ENF=$(adb_target shell "cat /sys/fs/selinux/enforce" 2>/dev/null | tr -d '\r')
        [ "$ENF" != "0" ] && break   # rebooted; back to phase 1
        echo "   W2 try $i/25 $(date '+%H:%M:%S')"
        push_all
        adb_shell_timeout 240 "cd /data/local/tmp && ./ghostlock --load-prebuilt-profile /data/local/tmp/profile.bin" > /dev/null 2>&1
        cleanup_strays
        if root_id | grep -q "uid=0"; then
            echo "== ROOTED (attempt $ATTEMPT, try $i)"
            root_id | head -1
            echo "== temporary root until reboot: adb shell '/data/local/tmp/su -c id'"
            echo "== interactive root shell:       adb shell /data/local/tmp/su"
            exit 0
        fi
        sleep 2
    done
done
