#!/usr/bin/env bash
# Rebuild crates/goauld-art-bridge/android-support/toast_bridge.dex
# (ToastBridge + MainBridge helper classes loaded via InMemoryDexClassLoader)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="$SRC/toast_bridge.dex"
ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BT="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
PLATFORM="$(ls -d "$ANDROID_HOME"/platforms/android-* | sort -V | tail -1)"
JAVA_HOME="${JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
export PATH="$JAVA_HOME/bin:$BT:$PATH"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"/{obj,dex}
javac --release 17 -classpath "$PLATFORM/android.jar" -d "$TMP/obj" \
  "$SRC/goauld/ToastBridge.java" \
  "$SRC/goauld/MainBridge.java"
"$BT/d8" --min-api 26 --output "$TMP/dex" "$TMP/obj"/goauld/*.class
cp "$TMP/dex/classes.dex" "$OUT"
echo "OK $OUT ($(wc -c < "$OUT") bytes)"
