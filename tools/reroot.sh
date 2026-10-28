#!/bin/bash
# dizi one-shot re-root: connect the tablet over USB and run this script.
# It performs W1 (SELinux permissive) -> W2 (cred root) -> KernelSU module reload.
# Previously installed modules and their authorization state are restored automatically.
# The tablet may reboot several times during the run (normal; USB reconnects on its own).
# You are done when you see ROOTED.
cd "$(dirname "$0")/.." || exit 1

BIN=build/native/ghostlock
# Select the profile for the device's real kernel build before every push
# (build-exact; never reuse a profile across builds).
# PROFILE=... explicitly overrides the selection, but the file must exist.
PROFILE="${PROFILE:-}"

resolve_profile() {
    if [ -n "$PROFILE" ]; then
        [ -f "$PROFILE" ] || { echo "!! PROFILE does not exist: $PROFILE"; return 1; }
        return 0
    fi
    local uname_r
    uname_r=$(adb shell uname -r 2>/dev/null | tr -d '\r')
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
        for s in $(adb devices 2>/dev/null | awk '$2=="offline" || /:/{print $1}'); do
            adb disconnect "$s" >/dev/null 2>&1
        done
        if adb get-state 2>/dev/null | grep -q device; then
            if [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
                return 0
            fi
        fi
        sleep 5
    done
}

push_all() {
    resolve_profile || exit 1
    [ -f "$BIN" ] || { echo "!! missing binary: $BIN (build it on the build machine and copy it back)"; exit 1; }
    adb push "$BIN" /data/local/tmp/ghostlock >/dev/null 2>&1
    adb push "$PROFILE" /data/local/tmp/profile.bin >/dev/null 2>&1
    adb shell chmod 755 /data/local/tmp/ghostlock 2>/dev/null
}

ATTEMPT=0
while true; do
    ATTEMPT=$((ATTEMPT+1))
    wait_device

    # Already rooted: nothing to do
    if adb shell "su -c id" 2>/dev/null | grep -q "uid=0"; then
        echo "== KernelSU already active, nothing to do"
        exit 0
    fi

    ENF=$(adb shell "cat /sys/fs/selinux/enforce" 2>/dev/null | tr -d '\r')
    if [ "$ENF" != "0" ]; then
        # phase 1: W1 -> permissive
        echo "== attempt $ATTEMPT: W1 (SELinux) $(date '+%H:%M:%S')"
        push_all
        adb shell "cd /data/local/tmp && ./ghostlock --load-prebuilt-profile /data/local/tmp/profile.bin --stop-after-w1" > /dev/null 2>&1
        ENF=$(adb shell "cat /sys/fs/selinux/enforce" 2>/dev/null | tr -d '\r')
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
        ENF=$(adb shell "cat /sys/fs/selinux/enforce" 2>/dev/null | tr -d '\r')
        [ "$ENF" != "0" ] && break   # rebooted; back to phase 1
        push_all
        adb shell "cd /data/local/tmp && ./ghostlock --load-prebuilt-profile /data/local/tmp/profile.bin" > /dev/null 2>&1
        if adb shell "su -c id" 2>/dev/null | grep -q "uid=0"; then
            echo "== ROOTED + KernelSU active (attempt $ATTEMPT, try $i)"
            exit 0
        fi
        sleep 2
    done
done
