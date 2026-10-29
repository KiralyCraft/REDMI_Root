#!/bin/bash
# Redmi Pad Pro root one-click build script
set -e
cd "$(dirname "$0")"

# 1. Locate the NDK
if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$ANDROID_NDK_ROOT" ]; then
    for c in "$HOME/Library/Android/sdk/ndk" "$HOME/Android/Sdk/ndk" /opt/homebrew/share/android-commandlinetools/ndk; do
        if [ -d "$c" ]; then
            ANDROID_NDK_HOME="$c/$(ls -1 "$c" | sort -V | tail -1)"
            break
        fi
    done
fi
if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "[!] Android NDK not found. Install the NDK or set ANDROID_NDK_HOME"
    echo "    macOS: brew install --cask android-commandlinetools, then install the NDK,"
    echo "    or download it from https://developer.android.com/ndk/downloads"
    exit 1
fi
echo "[*] NDK: $ANDROID_NDK_HOME"
export ANDROID_NDK_HOME

# 2. Build
make -C src ghostlock ghostsu
BIN=build/native/ghostlock
AGENT=build/native/ghostsu
if [ -f "$BIN" ] && [ -f "$AGENT" ]; then
    echo "[+] build succeeded: $BIN"
    echo "[+] agent/client built: $AGENT"
    echo "[*] next: enable USB debugging on the tablet, connect it, and run tools/reroot.sh"
else
    echo "[!] build failed"
    exit 1
fi
