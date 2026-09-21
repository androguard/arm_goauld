#!/usr/bin/env bash
# Build on-device arm64 Android artifacts without relying on cargo-ndk:
#   - goauld-injector
#   - libgoauld_agent.so
#
# Usage:
#   ./scripts/build-android.sh              # QuickJS (default)
#   ./scripts/build-android.sh quickjs
#   ./scripts/build-android.sh symbiote
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

JS_ENGINE="${1:-quickjs}"
case "$JS_ENGINE" in
  -h|--help|help)
    cat <<EOF
Usage: $0 [quickjs|symbiote]

Build arm64 Android injector + agent.
  quickjs   (default) rquickjs / full Frida surface
  symbiote  pure-Rust engine (path dep ../../symbiote)

Artifacts land in dist/android-arm64 unless GOAULD_ANDROID_DIST is set.
EOF
    exit 0
    ;;
  quickjs|symbiote) ;;
  *)
    echo "usage: $0 [quickjs|symbiote] (got: $JS_ENGINE)" >&2
    exit 1
    ;;
esac

API="$(grep '^API_LEVEL=' ndk.txt | cut -d= -f2 || true)"
API="${API:-26}"
NDK_VER="$(grep '^NDK_VERSION=' ndk.txt | cut -d= -f2 || true)"

: "${ANDROID_HOME:=${HOME}/Library/Android/sdk}"
: "${ANDROID_NDK_HOME:=${ANDROID_HOME}/ndk/${NDK_VER}}"
if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  # Fall back to any installed NDK
  ANDROID_NDK_HOME="$(ls -d "${ANDROID_HOME}/ndk"/* 2>/dev/null | sort -V | tail -1 || true)"
fi
[[ -d "$ANDROID_NDK_HOME" ]] || { echo "ANDROID_NDK_HOME not found" >&2; exit 1; }

PREBUILT="$(ls -d "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/* | head -1)"
CLANG="${PREBUILT}/bin/aarch64-linux-android${API}-clang"
AR="${PREBUILT}/bin/llvm-ar"
[[ -x "$CLANG" ]] || { echo "missing clang: $CLANG" >&2; exit 1; }

SYSROOT="${PREBUILT}/sysroot"
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=${SYSROOT} -I${SYSROOT}/usr/include -target aarch64-linux-android${API}"

OUT="${GOAULD_ANDROID_DIST:-${ROOT}/dist/android-arm64}"
mkdir -p "$OUT"

export ANDROID_NDK_HOME
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG"
export CC_aarch64_linux_android="$CLANG"
export AR_aarch64_linux_android="$AR"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$AR"

echo "== NDK=$ANDROID_NDK_HOME API=$API =="
echo "== goauld version (from goauld-proto build.rs) will embed git+UTC =="
echo "== building goauld-injector =="
cargo build -p goauld-injector --release --target aarch64-linux-android

echo "== building goauld-agent (JS engine=$JS_ENGINE) =="
case "$JS_ENGINE" in
  quickjs)
    AGENT_FEATURES=(--features quickjs)
    ;;
  symbiote)
    AGENT_FEATURES=(--no-default-features --features symbiote)
    ;;
esac
cargo build -p goauld-agent --release --target aarch64-linux-android "${AGENT_FEATURES[@]}" 2>&1 | tee /tmp/goauld-agent-build.log | tail -40

NDK_OUT="${ROOT}/target/aarch64-linux-android/release"
cp -f "${NDK_OUT}/goauld-injector" "${OUT}/goauld-injector"
SO="$(find "${ROOT}/target/aarch64-linux-android" -name 'libgoauld_agent.so' | head -1)"
[[ -n "$SO" ]] || { echo "libgoauld_agent.so not found" >&2; exit 1; }
cp -f "$SO" "${OUT}/libgoauld_agent.so"
chmod +x "${OUT}/goauld-injector"
{
  echo "pkg=$(cargo metadata --no-deps --format-version 1 2>/dev/null | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -1)"
  echo "git=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "js=${JS_ENGINE}"
} > "${OUT}/VERSION.txt"
file "${OUT}/goauld-injector" "${OUT}/libgoauld_agent.so"
ls -la "$OUT"
echo "OK: artifacts in $OUT (see VERSION.txt)"
