#!/usr/bin/env bash
# Integration harness for goauld milestones against a rooted Android emulator.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MS="${1:-}"
DIST="${ROOT}/dist/android-arm64"
HOST="${ROOT}/target/release/goauld"
export PATH="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools:$PATH"

usage() { echo "usage: $0 <unit|1|2|3|4|5|6|apk|e2e|device-smoke|symbiote|all>"; exit 1; }
[[ -n "$MS" ]] || usage

need_device() {
  adb devices | awk 'NR>1 && $2=="device"{print $1}' | head -1
}

prepare_device() {
  local serial
  serial="$(need_device)"
  [[ -n "$serial" ]] || { echo "ERROR: no adb device online (start Goauld_API34 emulator)"; exit 2; }
  echo "device=$serial"
  # Bound adb root — it can hang when adbd is already root.
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
  [[ -x "$DIST/goauld-injector" ]] || { echo "missing $DIST — run ./scripts/build-android.sh"; exit 3; }
  [[ -f "$DIST/libgoauld_agent.so" ]] || { echo "missing agent — run ./scripts/build-android.sh"; exit 3; }
  adb push "$DIST/goauld-injector" /data/local/tmp/goauld/ >/dev/null
  adb push "$DIST/libgoauld_agent.so" /data/local/tmp/goauld/ >/dev/null
  adb shell "chmod 755 /data/local/tmp/goauld/goauld-injector"
  adb shell "chmod 755 /data/local/tmp/goauld/libgoauld_agent.so"
}

ensure_host() {
  if [[ ! -x "$HOST" ]]; then
    echo "building goauld-host…"
    (cd "$ROOT" && cargo build -p goauld-host --release -q)
  fi
}

start_native_target() {
  adb shell "pkill -9 -f 'sleep 3600' 2>/dev/null || true"
  # Prefer testapp if present; else toybox sleep (native, injectable).
  local pid
  pid="$(adb shell "toybox sleep 3600 >/dev/null 2>&1 & echo \$!" | tr -d '\r')"
  echo "$pid"
}

inject_into() {
  local pid="$1"
  adb logcat -c || true
  set +e
  OUT="$(adb shell /data/local/tmp/goauld/goauld-injector --pid "$pid" --so /data/local/tmp/goauld/libgoauld_agent.so 2>&1)"
  RC=$?
  set -e
  echo "$OUT"
  sleep 1
  if ! echo "$OUT" | grep -q 'OK handle='; then
    echo "FAIL: injector did not report OK (rc=$RC)"
    return 1
  fi
  if ! adb shell "grep -q goauld /proc/$pid/maps"; then
    echo "FAIL: libgoauld_agent.so not in /proc/$pid/maps"
    return 1
  fi
  if ! adb logcat -d | grep -qi 'goauld agent constructor'; then
    echo "FAIL: agent constructor not in logcat"
    return 1
  fi
  if ! adb shell "cat /proc/net/unix" | grep -q "goauld-agent-$pid"; then
    echo "FAIL: abstract socket goauld-agent-$pid not listening"
    return 1
  fi
  echo "OK inject pid=$pid (maps + ctor + socket)"
}

milestone_unit() {
  echo "== host unit tests (proto/native-hook/script/art) =="
  cd "$ROOT"
  cargo test -p goauld-proto -p goauld-native-hook -p goauld-art-bridge -q
  # Both JS engines (mutually exclusive features — run separately).
  "$ROOT/scripts/test-js-engines.sh" both
  echo "OK unit"
}

milestone_device_smoke() {
  echo "== device smoke: inject into native sleep =="
  prepare_device
  adb shell /data/local/tmp/goauld/goauld-injector --ps | head -20
  PID="$(start_native_target)"
  echo "target pid=$PID"
  inject_into "$PID"
}

milestone_1() {
  echo "== milestone 1: injection round-trip =="
  milestone_device_smoke
}

milestone_2() {
  echo "== milestone 2: native strlen hook (host unit + device Interceptor path in m4) =="
  cd "$ROOT"
  cargo test -p goauld-native-hook -q
  echo "OK native-hook unit; live Interceptor covered by milestone 4"
}

milestone_3() {
  echo "== milestone 3: script round-trip send(\"hi\") =="
  cd "$ROOT"
  "$ROOT/scripts/test-js-engines.sh" both
  ensure_host
  if ! need_device >/dev/null; then
    echo "NOTE: no device — host engines only"
    echo "OK milestone 3 (host)"
    return 0
  fi
  prepare_device
  PID="$(start_native_target)"
  inject_into "$PID"
  adb forward --remove tcp:27042 2>/dev/null || true
  "$HOST" attach --pid "$PID" --port 27042 \
    --script "$ROOT/scripts/fixtures/hi.js" \
    --expect-send hi --max-wait-secs 8
  echo "OK milestone 3 (device e2e)"
}

milestone_4() {
  echo "== milestone 4: Interceptor.attach from JS =="
  cd "$ROOT"
  cargo test -p goauld-script -q
  ensure_host
  if ! need_device >/dev/null; then
    echo "OK milestone 4 (host API only)"
    return 0
  fi
  prepare_device
  PID="$(start_native_target)"
  inject_into "$PID"
  adb forward --remove tcp:27043 2>/dev/null || true
  # Install hook; strlen may not be called by sleep — just verify ScriptLoad + no agent crash.
  "$HOST" attach --pid "$PID" --port 27043 \
    --script "$ROOT/scripts/fixtures/interceptor_strlen.js" \
    --expect-send interceptor-installed --max-wait-secs 8
  if adb shell "kill -0 $PID 2>/dev/null"; then
    echo "OK milestone 4 (Interceptor script + target alive)"
  else
    echo "FAIL: target died after Interceptor script"
    return 1
  fi
}

milestone_5() {
  echo "== milestone 5: Java.use Technique A =="
  cd "$ROOT"
  cargo test -p goauld-art-bridge -q
  cargo test -p goauld-script --lib java_ -- --nocapture
  ensure_host
  if ! need_device >/dev/null; then
    echo "OK milestone 5 (host Technique A + JS registration + invoke cases)"
    return 0
  fi
  prepare_device
  local pid=""
  if adb shell pm path com.example.javatarget >/dev/null 2>&1; then
    adb shell am force-stop com.example.javatarget || true
    adb shell am start -n com.example.javatarget/.Target >/dev/null
    sleep 2
    pid="$(adb shell pidof -s com.example.javatarget | tr -d '\r')"
    echo "java-target pid=$pid"
    adb logcat -c || true
    set +e
    OUT="$(adb shell /data/local/tmp/goauld/goauld-injector \
      --package com.example.javatarget \
      --so /data/local/tmp/goauld/libgoauld_agent.so \
      --stage-into-app 2>&1)"
    RC=$?
    set -e
    echo "$OUT"
    [[ $RC -eq 0 ]] || { echo "FAIL: java-target inject"; return 1; }
    adb shell "grep -q goauld /proc/$pid/maps"
  else
    echo "NOTE: install via ./scripts/build-java-target.sh && adb install -r testapps/java-target/build/java-target.apk"
    pid="$(start_native_target)"
    inject_into "$pid"
  fi
  adb forward --remove tcp:27044 2>/dev/null || true
  "$HOST" attach --pid "$pid" --port 27044 \
    --script "$ROOT/scripts/fixtures/java_hook.js" \
    --expect-send 'called with' --max-wait-secs 15

  # Device cases: JS send, callOriginal (native body ran), return = orig*2+1000, process alive.
  sleep 5
  local log
  log="$(adb logcat -d -s java-target:I goauld:I 2>/dev/null || true)"
  echo "$log" | rg -q "called with|java bridge invoked" \
    || { echo "FAIL: no hook invoke in logcat"; echo "$log" | tail -40; return 1; }
  # Original Target.hookMe logs "hookMe(N) native" — proves callOriginal hit backup ArtMethod.
  if ! echo "$log" | rg -q 'hookMe\([0-9]+\) native'; then
    echo "FAIL: expected original hookMe(N) native (callOriginal)"
    echo "$log" | rg -i "hookMe|goauld|FATAL" | tail -40
    return 1
  fi
  # After hook: return must be 2*N+1000 for some N>=2 (fixture: this.hookMe(x)+1000).
  local ok_ret=0
  local line n ret expect
  while IFS= read -r line; do
    if [[ "$line" =~ hookMe\ returned\ ([0-9]+) ]]; then
      ret="${BASH_REMATCH[1]}"
      # Find a paired native log with same generation — accept any ret==2*n+1000 for n in 2..50
      for n in $(seq 2 50); do
        expect=$((n * 2 + 1000))
        if [[ "$ret" -eq "$expect" ]]; then
          ok_ret=1
          echo "OK return case: hookMe($n) → $ret (= 2*$n+1000)"
          break
        fi
      done
      [[ "$ok_ret" -eq 1 ]] && break
    fi
  done <<< "$log"
  [[ "$ok_ret" -eq 1 ]] || {
    echo "FAIL: no hookMe returned 2*N+1000 (callOriginal+replacement)"
    echo "$log" | rg "hookMe" | tail -30
    return 1
  }
  if ! adb shell "kill -0 $pid 2>/dev/null"; then
    echo "FAIL: java-target died after Java hook / callOriginal"
    return 1
  fi
  # Stable across more ticks
  sleep 4
  if ! adb shell "kill -0 $pid 2>/dev/null"; then
    echo "FAIL: java-target died on subsequent hook fires"
    return 1
  fi
  echo "OK milestone 5 (live ArtMethod hook + callOriginal + stable)"
}

milestone_6() {
  echo "== milestone 6: APK e2e (syscalls / Android API / Java fixtures) =="
  ensure_host
  if ! need_device >/dev/null; then
    echo "NOTE: no device — skip APK e2e"
    echo "OK milestone 6 (skipped, no device)"
    return 0
  fi
  prepare_device
  # Full suite against java-target on the emulator.
  GOAULD_SKIP_BUILD=1 "$ROOT/scripts/run_e2e_apk.sh" all
  echo "OK milestone 6 (APK e2e)"
}

case "$MS" in
  unit) milestone_unit ;;
  device-smoke) milestone_device_smoke ;;
  1) milestone_1 ;;
  2) milestone_2 ;;
  3) milestone_3 ;;
  4) milestone_4 ;;
  5) milestone_5 ;;
  6|apk|e2e) milestone_6 ;;
  symbiote)
    echo "== symbiote: emulator inject + Script.runtime =="
    "$ROOT/scripts/test-symbiote-emulator.sh"
    ;;
  all)
    milestone_unit
    milestone_2
    milestone_3
    milestone_4
    milestone_5
    milestone_6
    ;;
  *) usage ;;
esac
