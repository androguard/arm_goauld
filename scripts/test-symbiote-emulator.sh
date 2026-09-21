#!/usr/bin/env bash
# Symbiote agent on a rooted Android emulator.
#
# Builds the agent with `--features symbiote` into dist/android-arm64-symbiote
# (does not replace the default QuickJS dist/), injects it, and checks:
#   Hello version contains js=symbiote
#   send("hi")
#   Script.runtime === SYMBIOTE + Memory read/write
#   Process/Module/Memory fixture
#   Interceptor.attach installs
#   Arm64Writer fixture
#   java_toast.js inside java-target (android.widget.Toast)
#   inspect_package.js inside java-target
#
# Usage:
#   ./scripts/emulator.sh start
#   ./scripts/test-symbiote-emulator.sh
#
# Env:
#   GOAULD_SKIP_BUILD   skip NDK rebuild when artifacts already exist
#   GOAULD_START_EMU    if no device, run ./scripts/emulator.sh start (default: 1)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${ROOT}/dist/android-arm64-symbiote"
HOST="${ROOT}/target/release/goauld"
FIX="${ROOT}/scripts/fixtures"
export PATH="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools:$PATH"
export GOAULD_ANDROID_DIST="$DIST"

need_device() {
  adb devices | awk 'NR>1 && $2=="device"{print $1}' | head -1
}

ensure_device() {
  if [[ -n "$(need_device)" ]]; then
    return 0
  fi
  if [[ "${GOAULD_START_EMU:-1}" == "0" ]]; then
    echo "ERROR: no adb device — run ./scripts/emulator.sh start" >&2
    exit 2
  fi
  echo "== no device; starting emulator =="
  "$ROOT/scripts/emulator.sh" start
}

ensure_artifacts() {
  if [[ -n "${GOAULD_SKIP_BUILD:-}" && -x "$DIST/goauld-injector" && -f "$DIST/libgoauld_agent.so" ]]; then
    echo "== using existing $DIST (GOAULD_SKIP_BUILD) =="
    return 0
  fi
  echo "== building Symbiote Android agent =="
  "$ROOT/scripts/build-android.sh" symbiote
  grep -q 'js=symbiote' "$DIST/VERSION.txt"
}

ensure_host() {
  if [[ ! -x "$HOST" ]]; then
    echo "== building goauld-host =="
    (cd "$ROOT" && cargo build -p goauld-host --release -q)
  fi
}

prepare_device() {
  local serial
  serial="$(need_device)"
  [[ -n "$serial" ]] || { echo "ERROR: no adb device" >&2; exit 2; }
  echo "device=$serial"
  adb root >/dev/null 2>&1 &
  local root_pid=$!
  ( sleep 12; kill "$root_pid" 2>/dev/null ) &
  local watch=$!
  wait "$root_pid" 2>/dev/null || true
  kill "$watch" 2>/dev/null || true
  wait "$watch" 2>/dev/null || true
  sleep 1
  adb shell "setenforce 0" || true
  adb shell "echo 0 > /proc/sys/kernel/yama/ptrace_scope" || true
  adb shell "mkdir -p /data/local/tmp/goauld"
  adb push "$DIST/goauld-injector" /data/local/tmp/goauld/goauld-injector >/dev/null
  adb push "$DIST/libgoauld_agent.so" /data/local/tmp/goauld/libgoauld_agent.so >/dev/null
  adb shell "chmod 755 /data/local/tmp/goauld/goauld-injector /data/local/tmp/goauld/libgoauld_agent.so"
}

start_native_target() {
  adb shell "pkill -9 -f 'sleep 3600' 2>/dev/null || true" || true
  adb shell "toybox sleep 3600 >/dev/null 2>&1 & echo \$!" | tr -d '\r'
}

inject_into() {
  local pid="$1"
  adb logcat -c || true
  set +e
  local out rc
  out="$(adb shell /data/local/tmp/goauld/goauld-injector --pid "$pid" --so /data/local/tmp/goauld/libgoauld_agent.so 2>&1)"
  rc=$?
  set -e
  echo "$out"
  sleep 1
  echo "$out" | grep -q 'OK handle=' || { echo "FAIL: injector"; return 1; }
  adb shell "grep -q goauld /proc/$pid/maps" || { echo "FAIL: maps"; return 1; }
  adb logcat -d | grep -qi 'goauld agent constructor' || { echo "FAIL: ctor"; return 1; }
  adb shell "cat /proc/net/unix" | grep -q "goauld-agent-$pid" || { echo "FAIL: socket"; return 1; }
  echo "OK inject pid=$pid"
}

attach_expect() {
  local pid="$1"
  local port="$2"
  local script="$3"
  local needle="$4"
  local wait_secs="${5:-20}"
  adb forward --remove "tcp:${port}" >/dev/null 2>&1 || true
  set +e
  local out rc
  out="$("$HOST" attach --pid "$pid" --port "$port" \
    --script "$script" --expect-send "$needle" --max-wait-secs "$wait_secs" 2>&1)"
  rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || return 1
  echo "$out" | grep -q "OK expect-send matched" || return 1
  echo "$out" | grep -q 'js=symbiote' || {
    echo "FAIL: Hello did not report js=symbiote"
    return 1
  }
  adb shell "kill -0 $pid 2>/dev/null" || {
    echo "FAIL: target died after $script"
    return 1
  }
}

ensure_device
ensure_artifacts
ensure_host
prepare_device

# Fresh process per script. A live Interceptor.attach (strlen) stays patched
# after the host disconnects and aborts the next script on the same pid.
run_case() {
  local name="$1"
  local port="$2"
  local script="$3"
  local needle="$4"
  local wait_secs="$5"
  echo "== $name =="
  local pid
  pid="$(start_native_target)"
  echo "target pid=$pid"
  inject_into "$pid"
  attach_expect "$pid" "$port" "$script" "$needle" "$wait_secs"
  adb shell "kill $pid" >/dev/null 2>&1 || true
}

run_case "symbiote hello + send(hi)" 27242 "$FIX/hi.js" "hi" 12
run_case "Script.runtime SYMBIOTE + Memory" 27243 "$FIX/engine_runtime.js" "engine-runtime-SYMBIOTE" 15
run_case "Process / Module / Memory" 27244 "$FIX/process_module_memory.js" "ptmm-ok" 20
run_case "Interceptor.attach install" 27245 "$FIX/interceptor_strlen.js" "interceptor-installed" 15
run_case "Arm64Writer" 27246 "$FIX/arm64_writer.js" "arm64-writer-ok" 20

# Toast needs an app process (ActivityThread.currentApplication). toybox sleep
# has no Android UI, so this case injects into java-target.
run_toast() {
  echo "== android.widget.Toast (java-target) =="
  local apk="$ROOT/testapps/java-target/build/java-target.apk"
  local pkg="com.example.javatarget"
  if [[ ! -f "$apk" ]]; then
    "$ROOT/scripts/build-java-target.sh"
  fi
  adb install -r "$apk"
  adb shell am force-stop "$pkg" >/dev/null 2>&1 || true
  adb shell am start -n "${pkg}/.Target" >/dev/null
  sleep 2
  local pid
  pid="$(adb shell pidof -s "$pkg" | tr -d '\r')"
  [[ -n "$pid" ]] || { echo "FAIL: $pkg not running"; return 1; }
  echo "target pid=$pid"
  adb logcat -c || true
  "$HOST" inject --package "$pkg" \
    --injector "$DIST/goauld-injector" \
    --agent "$DIST/libgoauld_agent.so" \
    --stage-into-app
  sleep 1
  attach_expect "$pid" 27247 "$FIX/java_toast.js" "toast-shown" 20
  sleep 2
  if adb logcat -d | grep -q 'androidToast failed\|main-err:'; then
    echo "FAIL: Toast callback errored"
    adb logcat -d | grep -E 'androidToast|main-err|goauld' | tail -40 || true
    return 1
  fi
  adb shell am force-stop "$pkg" >/dev/null 2>&1 || true
}

run_toast

# Capture attach output so the device dump must name the app, not only send inspect-ok.
run_inspect() {
  echo "== inspect_package =="
  local pkg="com.example.javatarget"
  adb shell am force-stop "$pkg" >/dev/null 2>&1 || true
  adb shell am start -n "${pkg}/.Target" >/dev/null
  sleep 2
  local pid
  pid="$(adb shell pidof -s "$pkg" | tr -d '\r')"
  [[ -n "$pid" ]] || { echo "FAIL: $pkg not running"; return 1; }
  echo "target pid=$pid"
  adb logcat -c || true
  "$HOST" inject --package "$pkg" \
    --injector "$DIST/goauld-injector" \
    --agent "$DIST/libgoauld_agent.so" \
    --stage-into-app
  sleep 1
  set +e
  local out rc
  out="$("$HOST" attach --pid "$pid" --port 27248 \
    --script "$FIX/inspect_package.js" --expect-send inspect-ok --max-wait-secs 30 2>&1)"
  rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || return 1
  echo "$out" | grep -q 'js=symbiote' || { echo "FAIL: Hello did not report js=symbiote"; return 1; }
  echo "$out" | grep -q 'com.example.javatarget' || { echo "FAIL: inspect dump missing package"; return 1; }
  echo "$out" | grep -q 'inspect-ok' || { echo "FAIL: missing inspect-ok"; return 1; }
  if adb logcat -d | grep -q 'ScriptLoad: js:'; then
    echo "FAIL: ScriptLoad error during inspect"
    adb logcat -d | grep -E 'ScriptLoad|goauld' | tail -30 || true
    return 1
  fi
}

run_inspect

if ! adb logcat -d | grep -q 'Symbiote engine ready'; then
  echo "FAIL: logcat missing Symbiote engine ready"
  adb logcat -d | grep -i goauld | tail -40 || true
  exit 1
fi

echo "OK: Symbiote emulator tests"
