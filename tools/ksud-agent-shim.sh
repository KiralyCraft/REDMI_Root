#!/system/bin/sh
# dizi temporary-root shim — pushed to /data/local/tmp/ksud.
#
# The rooted handoff script (uid 0, SELinux permissive) runs this path as
#     ksud late-load --kmi <kmi> --allow-shell
# KernelSU's late-load cannot work on this stock kernel: ksud's late-load talks
# to the KernelSU driver (anon_inode:[ksu_driver]), which a stock kernel does not
# have, so it exits 0 without loading anything. This shim reuses that guaranteed
# uid-0 execution point to leave a userspace root agent behind, then chains to
# the real ksud (pushed as ksud.real) so KernelSU's own behaviour is unchanged.
#
# Result: /data/local/tmp/su -c '<cmd>' runs <cmd> as uid 0 until the next boot.

AGENT=/data/local/tmp/ghostsu
LOG=/data/local/tmp/.ghostsu.log

if [ -x "$AGENT" ]; then
    if ! "$AGENT" --ping >/dev/null 2>&1; then
        setsid "$AGENT" --agent </dev/null >>"$LOG" 2>&1 &
        i=0
        while [ "$i" -lt 10 ]; do
            "$AGENT" --ping >/dev/null 2>&1 && break
            sleep 0.2
            i=$((i + 1))
        done
    fi
    if "$AGENT" --ping >/dev/null 2>&1; then
        echo '[*] ghostsu agent running: /data/local/tmp/su -c id'
    else
        echo '[!] ghostsu agent failed to start'
    fi
else
    echo '[!] ghostsu missing; temporary adb root unavailable'
fi

if [ -x /data/local/tmp/ksud.real ]; then
    exec /data/local/tmp/ksud.real "$@"
fi
exit 0
