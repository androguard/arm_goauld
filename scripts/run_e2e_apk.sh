#!/usr/bin/env bash
# End-to-end feature tests against the real java-target APK on a rooted emulator.
#
# Prerequisites:
#   ./scripts/emulator.sh start
#   ./scripts/build-android.sh
#   cargo build -p goauld-host --release
#
# Usage:
#   ./scripts/run_e2e_apk.sh              # full suite
#   ./scripts/run_e2e_apk.sh list
#   ./scripts/run_e2e_apk.sh syscalls android-api toast …
#
# Env:
#   GOAULD_PKG          package (default: com.example.javatarget)
#   GOAULD_ACTIVITY     activity (default: .Target)
#   GOAULD_SKIP_BUILD   if set, do not rebuild host / APK
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${ROOT}/dist/android-arm64"
HOST="${ROOT}/target/release/goauld"
INJ="${DIST}/goauld-injector"
SO="${DIST}/libgoauld_agent.so"
PKG="${GOAULD_PKG:-com.example.javatarget}"
ACTIVITY="${GOAULD_ACTIVITY:-.Target}"
APK="${ROOT}/testapps/java-target/build/java-target.apk"
FIX="${ROOT}/scripts/fixtures"
export PATH="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools:$PATH"

PASS=0
FAIL=0
SKIP=0
PORT_BASE=27110

usage() {
  cat <<EOF
Usage: $0 [all|list|<case>…]

Cases:
  syscalls       attach syscall + trace syscalls (injector ptrace, no agent)
  inject         inject agent into java-target (--stage-into-app)
  hi             attach + hi.js
  ptmm           Process / Module / Memory fixture
  interceptor    native Interceptor.attach (enter)
  interceptor-attach  Interceptor.attach onEnter/onLeave
  interceptor-replace Interceptor.replace + flush
  interceptor-api     Interceptor attach/replace/flush/detach smoke
  thread-api     Thread observers / runOnThread / exception handler
  backtrace      Thread.backtrace / Backtracer
  memory-scan    Memory.scan / scanSync
  memory-patch   Memory.patchCode
  memory-access  MemoryAccessMonitor
  module-enum    Module.enumerateExports/Imports/Symbols/Sections/deps
  misc-apis      console / hexdump / timers / gc / Cloak / Profiler
  toast          android.widget.Toast
  java-api       Java.* surface smoke
  java-perform   Java.perform / performNow
  inspect        package / fields / prefs dump
  java-hook      Technique-A hookMe
  android-api    attach java (ART invoke events)
  android-api-hooks  attach java + --java-hooks hookMe
  trace-java     trace java (restart + inject + events)

Default: all
EOF
}

# Portable timeout (macOS has no GNU timeout by default).
run_timeout() {
  local secs="$1"
  shift
  "$@" &
  local cmd_pid=$!
  (
    sleep "$secs"
    kill "$cmd_pid" 2>/dev/null || true
  ) &
  local watch_pid=$!
  wait "$cmd_pid" 2>/dev/null
  local rc=$?
  kill "$watch_pid" 2>/dev/null || true
  wait "$watch_pid" 2>/dev/null || true
  return "$rc"
}

need_device() {
  adb devices | awk 'NR>1 && $2=="device"{print $1}' | head -1
}

log() { printf '[e2e] %s\n' "$*"; }
ok() { PASS=$((PASS + 1)); log "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); log "FAIL: $*"; return 1; }
skip() { SKIP=$((SKIP + 1)); log "SKIP: $*"; }

prepare_device() {
  local serial
  serial="$(need_device)"
  [[ -n "$serial" ]] || {
    echo "ERROR: no adb device online — run ./scripts/emulator.sh start" >&2
    exit 2
  }
  log "device=$serial"
  # `adb root` can hang if already root / adbd restarting — bound it.
  run_timeout 12 adb root >/dev/null 2>&1 || true
  sleep 1
  run_timeout 8 adb shell "setenforce 0" >/dev/null 2>&1 || true
  run_timeout 8 adb shell "echo 0 > /proc/sys/kernel/yama/ptrace_scope" >/dev/null 2>&1 || true
  run_timeout 8 adb shell "mkdir -p /data/local/tmp/goauld" >/dev/null 2>&1 || true
  [[ -x "$INJ" ]] || {
    echo "ERROR: missing $INJ — run ./scripts/build-android.sh" >&2
    exit 3
  }
  [[ -f "$SO" ]] || {
    echo "ERROR: missing $SO — run ./scripts/build-android.sh" >&2
    exit 3
  }
  run_timeout 60 adb push "$INJ" /data/local/tmp/goauld/ >/dev/null
  run_timeout 60 adb push "$SO" /data/local/tmp/goauld/ >/dev/null
  run_timeout 8 adb shell "chmod 755 /data/local/tmp/goauld/goauld-injector /data/local/tmp/goauld/libgoauld_agent.so" >/dev/null
}

ensure_host() {
  if [[ -n "${GOAULD_SKIP_BUILD:-}" && -x "$HOST" ]]; then
    return 0
  fi
  if [[ ! -x "$HOST" ]]; then
    log "building goauld-host…"
    (cd "$ROOT" && cargo build -p goauld-host --release -q)
  fi
}

ensure_apk() {
  if [[ ! -f "$APK" ]]; then
    log "building java-target APK…"
    "$ROOT/scripts/build-java-target.sh"
  fi
  if adb shell pm path "$PKG" >/dev/null 2>&1; then
    if [[ -z "${GOAULD_SKIP_BUILD:-}" ]]; then
      set +e
      local inst
      inst="$(adb install -r "$APK" 2>&1)"
      local rc=$?
      set -e
      if [[ $rc -ne 0 ]] && echo "$inst" | grep -qi 'UPDATE_INCOMPATIBLE\|INSTALL_FAILED'; then
        log "reinstall: uninstalling mismatched $PKG ..."
        adb uninstall "$PKG" >/dev/null 2>&1 || true
        adb install "$APK" >/dev/null
      elif [[ $rc -ne 0 ]]; then
        echo "$inst" >&2
        return 1
      fi
    fi
  else
    log "installing $APK ..."
    adb install "$APK" >/dev/null
  fi
}

pidof_pkg() {
  adb shell pidof -s "$PKG" 2>/dev/null | tr -d '\r' || true
}

force_stop() {
  adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
  sleep 0.4
}

start_pkg() {
  force_stop
  adb shell am start -n "${PKG}/${ACTIVITY}" >/dev/null
  sleep 2
  local pid
  pid="$(pidof_pkg)"
  [[ -n "$pid" ]] || {
    echo "ERROR: $PKG not running after start" >&2
    return 1
  }
  echo "$pid"
}

inject_pkg() {
  local pid="$1"
  adb logcat -c >/dev/null 2>&1 || true
  set +e
  local out rc
  out="$("$HOST" inject --package "$PKG" --injector "$INJ" --agent "$SO" --stage-into-app 2>&1)"
  rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || return 1
  sleep 1
  adb shell "grep -q goauld /proc/$pid/maps" || return 1
  adb shell "cat /proc/net/unix" | grep -q "goauld-agent-$pid" || return 1
}

next_port() {
  # Must not run via $(next_port) — command substitution is a subshell and would
  # drop the PORT_BASE update.
  PORT_BASE=$((PORT_BASE + 1))
}

# Capture host attach output; succeed if exit 0 and stdout matches needles.
run_attach_script() {
  local port="$1"
  local script="$2"
  local expect="$3"
  local wait_secs="${4:-25}"
  local pid
  pid="$(pidof_pkg)"
  [[ -n "$pid" ]] || {
    echo "ERROR: package not running" >&2
    return 1
  }
  adb forward --remove "tcp:${port}" >/dev/null 2>&1 || true
  set +e
  local out
  out="$("$HOST" attach --pid "$pid" --port "$port" \
    --script "$script" --expect-send "$expect" --max-wait-secs "$wait_secs" 2>&1)"
  local rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || return 1
  echo "$out" | grep -q "OK expect-send matched" || return 1
  adb shell "kill -0 $pid 2>/dev/null" || {
    echo "ERROR: process died after attach" >&2
    return 1
  }
}

# ---------- cases ----------

case_syscalls() {
  log "== syscalls (attach + trace) =="
  local pid out
  pid="$(start_pkg)"

  set +e
  out="$("$HOST" attach syscall --pid "$pid" \
    --injector "$INJ" \
    --max-events 80 \
    --max-wait-secs 8 \
    --filter openat,write,read,clock_gettime,nanosleep 2>&1)"
  local rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || fail "attach syscall exit $rc" || return 1
  echo "$out" | grep -Eiq 'openat|write|read|clock_gettime|nanosleep' \
    || fail "attach syscall: no decoded syscall lines" || return 1
  ok "attach syscall (pid=$pid)"

  # Still alive? ptrace should have detached.
  if ! adb shell "kill -0 $pid 2>/dev/null"; then
    pid="$(start_pkg)"
  fi

  set +e
  out="$("$HOST" trace syscalls --package "$PKG" \
    --injector "$INJ" \
    --duration-secs 6 \
    --max-events 60 \
    --filter openat,write,read,clock_gettime 2>&1)"
  rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || fail "trace syscalls exit $rc" || return 1
  echo "$out" | grep -Eiq 'openat|write|read|clock_gettime' \
    || fail "trace syscalls: no decoded syscall lines" || return 1
  ok "trace syscalls (--package)"
}

case_inject() {
  log "== inject agent into $PKG =="
  local pid
  pid="$(start_pkg)"
  inject_pkg "$pid" || fail "inject" || return 1
  ok "inject stage-into-app (pid=$pid)"
}

require_injected() {
  local pid
  pid="$(pidof_pkg)"
  if [[ -n "$pid" ]] \
    && adb shell "grep -q goauld /proc/$pid/maps" 2>/dev/null \
    && adb shell "cat /proc/net/unix" | grep -q "goauld-agent-$pid"; then
    return 0
  fi
  log "re-injecting (no live agent socket)…"
  case_inject || return 1
}

attach_expect() {
  local script="$1"
  local expect="$2"
  local wait_secs="${3:-25}"
  next_port
  local port="$PORT_BASE"
  run_attach_script "$port" "$script" "$expect" "$wait_secs"
}

case_hi() {
  log "== hi.js =="
  require_injected || return 1
  attach_expect "$FIX/hi.js" "hi" 10 || fail "hi.js" || return 1
  ok "hi.js"
}

case_ptmm() {
  log "== process_module_memory.js =="
  require_injected || return 1
  attach_expect "$FIX/process_module_memory.js" "ptmm-ok" 15 || fail "ptmm" || return 1
  ok "process/module/memory"
}

case_interceptor() {
  log "== interceptor_strlen.js =="
  require_injected || return 1
  attach_expect "$FIX/interceptor_strlen.js" "interceptor-installed" 15 \
    || fail "interceptor" || return 1
  ok "Interceptor.attach (enter)"
}

case_interceptor_attach() {
  log "== interceptor_attach.js =="
  require_injected || return 1
  attach_expect "$FIX/interceptor_attach.js" "interceptor-attach-ok" 20 \
    || fail "interceptor-attach" || return 1
  ok "Interceptor.attach onEnter/onLeave"
}

case_interceptor_replace() {
  log "== interceptor_replace.js =="
  require_injected || return 1
  attach_expect "$FIX/interceptor_replace.js" "interceptor-replace-ok" 20 \
    || fail "interceptor-replace" || return 1
  ok "Interceptor.replace/flush"
  force_stop
}

case_interceptor_api() {
  log "== interceptor_api.js =="
  require_injected || return 1
  attach_expect "$FIX/interceptor_api.js" "interceptor-api-ok" 20 \
    || fail "interceptor-api" || return 1
  ok "Interceptor API smoke"
  force_stop
}

case_java_perform() {
  log "== java_perform.js =="
  require_injected || return 1
  attach_expect "$FIX/java_perform.js" "java-perform-ok" 20 \
    || fail "java-perform" || return 1
  ok "Java.perform/performNow"
}

case_thread_api() {
  log "== thread_api.js =="
  require_injected || return 1
  attach_expect "$FIX/thread_api.js" "thread-api-ok" 25 \
    || fail "thread-api" || return 1
  ok "Thread observers/runOnThread/exception"
}

case_backtrace() {
  log "== thread_backtrace.js =="
  require_injected || return 1
  attach_expect "$FIX/thread_backtrace.js" "backtrace-ok" 15 \
    || fail "backtrace" || return 1
  ok "Thread.backtrace/Backtracer"
}

case_memory_scan() {
  log "== memory_scan.js =="
  require_injected || return 1
  attach_expect "$FIX/memory_scan.js" "memory-scan-ok" 15 \
    || fail "memory-scan" || return 1
  ok "Memory.scan/scanSync"
}

case_memory_patch() {
  log "== memory_patch.js =="
  require_injected || return 1
  attach_expect "$FIX/memory_patch.js" "memory-patch-ok" 15 \
    || fail "memory-patch" || return 1
  ok "Memory.patchCode"
}

case_arm64_writer() {
  log "== arm64_writer.js =="
  require_injected || return 1
  attach_expect "$FIX/arm64_writer.js" "arm64-writer-ok" 15 \
    || fail "arm64-writer" || return 1
  ok "Arm64Writer/Relocator/enums"
}

case_arm64_examples() {
  log "== arm64_writer_examples.js =="
  require_injected || return 1
  attach_expect "$FIX/arm64_writer_examples.js" "arm64-examples-ok" 20 \
    || fail "arm64-examples" || return 1
  ok "Arm64Writer real examples"
}

case_memory_access() {
  log "== memory_access.js =="
  require_injected || return 1
  attach_expect "$FIX/memory_access.js" "memory-access-ok" 20 \
    || fail "memory-access" || return 1
  ok "MemoryAccessMonitor"
}

case_module_enum() {
  log "== module_enumerate.js =="
  require_injected || return 1
  attach_expect "$FIX/module_enumerate.js" "module-enum-ok" 20 \
    || fail "module-enum" || return 1
  ok "Module enumerateExports/Imports/Symbols/Sections"
}

case_misc_apis() {
  log "== misc_apis.js =="
  require_injected || return 1
  attach_expect "$FIX/misc_apis.js" "misc-apis-ok" 20 \
    || fail "misc-apis" || return 1
  ok "console/hexdump/timers/gc/Cloak/Profiler"
}

case_toast() {
  log "== java_toast.js =="
  require_injected || return 1
  attach_expect "$FIX/java_toast.js" "toast-shown" 15 || fail "toast" || return 1
  ok "android.widget.Toast"
}

case_java_api() {
  log "== java_api.js =="
  require_injected || return 1
  next_port
  local port="$PORT_BASE" out rc
  set +e
  out="$(run_attach_script "$port" "$FIX/java_api.js" "java-api-ok" 25)"
  rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || fail "java-api" || return 1
  echo "$out" | grep -q 'hasTarget' || fail "java-api missing hasTarget" || return 1
  ok "Java.* API smoke"
}

case_inspect() {
  log "== inspect_package.js =="
  require_injected || return 1
  next_port
  local port="$PORT_BASE" out rc
  set +e
  out="$(run_attach_script "$port" "$FIX/inspect_package.js" "inspect-ok" 35)"
  rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || fail "inspect" || return 1
  echo "$out" | grep -Eiq 'com\.example\.javatarget|dataDir|SharedPreferences|hookMe' \
    || fail "inspect payload too thin" || return 1
  ok "inspect_package"
}

case_java_hook() {
  log "== java_hook.js =="
  # Fresh process so hookMe semantics are clean.
  local pid
  pid="$(start_pkg)"
  inject_pkg "$pid" || fail "inject for java-hook" || return 1
  adb logcat -c >/dev/null 2>&1 || true
  attach_expect "$FIX/java_hook.js" "java-hook-installed" 15 \
    || fail "java-hook install" || return 1
  sleep 5
  local logc
  logc="$(adb logcat -d -s java-target:I goauld:I 2>/dev/null || true)"
  echo "$logc" | grep -Eq 'hookMe\([0-9]+\) native' \
    || fail "java-hook: no callOriginal native log" || return 1
  echo "$logc" | grep -Eq 'hookMe returned' \
    || fail "java-hook: no returned log" || return 1
  adb shell "kill -0 $pid 2>/dev/null" || fail "java-hook: process died" || return 1
  ok "java_hook (install + callOriginal)"
}

case_android_api() {
  log "== attach java (android-api events) =="
  require_injected || return 1
  local pid out rc
  pid="$(pidof_pkg)"
  next_port
  local port="$PORT_BASE"
  adb forward --remove "tcp:${port}" >/dev/null 2>&1 || true
  set +e
  out="$("$HOST" attach java --pid "$pid" --port "$port" \
    --filter 'android.,java.,dalvik.' \
    --max-events 40 \
    --max-wait-secs 18 2>&1)"
  rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || fail "attach java exit $rc" || return 1
  echo "$out" | grep -q 'java-api-trace-installed' \
    || fail "attach java: missing install ack" || return 1
  echo "$out" | grep -Eiq 'android-api|"type":"android-api"' \
    || fail "attach java: no android-api events" || return 1
  adb shell "kill -0 $pid 2>/dev/null" || fail "attach java: process died" || return 1
  ok "attach java android-api"
}

case_android_api_hooks() {
  log "== attach java --java-hooks =="
  require_injected || return 1
  local pid out rc
  pid="$(pidof_pkg)"
  next_port
  local port="$PORT_BASE"
  adb forward --remove "tcp:${port}" >/dev/null 2>&1 || true
  set +e
  out="$("$HOST" attach java --pid "$pid" --port "$port" \
    --java-hooks 'com.example.javatarget.Target.hookMe:(I)I' \
    --filter 'android.,java.' \
    --max-events 30 \
    --max-wait-secs 18 2>&1)"
  rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || fail "attach java --java-hooks exit $rc" || return 1
  echo "$out" | grep -q 'java-api-trace-installed' \
    || fail "java-hooks: missing install ack" || return 1
  # Either Technique-A java-api send or android-api events count as success.
  echo "$out" | grep -Eiq 'java-api|android-api|hookMe' \
    || fail "java-hooks: no hook/api events" || return 1
  ok "attach java --java-hooks"
}

case_trace_java() {
  log "== trace java (restart + inject) =="
  local out rc
  set +e
  out="$("$HOST" trace java \
    --package "$PKG" \
    --injector "$INJ" \
    --agent "$SO" \
    --stage-into-app \
    --activity "${PKG}/${ACTIVITY}" \
    --filter 'android.,java.,dalvik.' \
    --max-events 50 \
    --max-wait-secs 22 2>&1)"
  rc=$?
  set -e
  echo "$out"
  [[ $rc -eq 0 ]] || fail "trace java exit $rc" || return 1
  echo "$out" | grep -q 'java-api-trace-installed' \
    || fail "trace java: missing install ack" || return 1
  echo "$out" | grep -Eiq 'android-api|"type":"android-api"' \
    || fail "trace java: no android-api events" || return 1
  ok "trace java"
}

run_case() {
  local name="$1"
  case "$name" in
    syscalls) case_syscalls ;;
    inject) case_inject ;;
    hi) case_hi ;;
    ptmm) case_ptmm ;;
    interceptor) case_interceptor ;;
    interceptor-attach) case_interceptor_attach ;;
    interceptor-replace) case_interceptor_replace ;;
    interceptor-api) case_interceptor_api ;;
    toast) case_toast ;;
    java-api) case_java_api ;;
    java-perform) case_java_perform ;;
    thread-api) case_thread_api ;;
    backtrace) case_backtrace ;;
    memory-scan) case_memory_scan ;;
    memory-patch) case_memory_patch ;;
    arm64-writer) case_arm64_writer ;;
    arm64-examples) case_arm64_examples ;;
    memory-access) case_memory_access ;;
    module-enum) case_module_enum ;;
    misc-apis) case_misc_apis ;;
    inspect) case_inspect ;;
    java-hook) case_java_hook ;;
    android-api) case_android_api ;;
    android-api-hooks) case_android_api_hooks ;;
    trace-java) case_trace_java ;;
    *)
      echo "unknown case: $name" >&2
      usage >&2
      exit 2
      ;;
  esac
}

ALL_CASES=(
  syscalls
  inject
  hi
  ptmm
  toast
  java-api
  java-perform
  thread-api
  backtrace
  memory-scan
  memory-patch
  arm64-writer
  arm64-examples
  memory-access
  module-enum
  misc-apis
  inspect
  android-api
  android-api-hooks
  java-hook
  interceptor
  interceptor-attach
  interceptor-replace
  interceptor-api
  trace-java
)

main() {
  local args=("$@")
  if [[ ${#args[@]} -eq 0 || "${args[0]}" == "all" ]]; then
    args=("${ALL_CASES[@]}")
  elif [[ "${args[0]}" == "list" ]]; then
    usage
    exit 0
  elif [[ "${args[0]}" == "-h" || "${args[0]}" == "--help" ]]; then
    usage
    exit 0
  fi

  ensure_host
  prepare_device
  ensure_apk

  local c
  for c in "${args[@]}"; do
    # Soft-continue so one failure does not skip the rest of the suite.
    set +e
    run_case "$c"
    local rc=$?
    set -e
    if [[ $rc -ne 0 && $FAIL -eq 0 ]]; then
      # run_case already counted fail; ensure counter moved.
      :
    fi
  done

  echo
  log "summary: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
  [[ "$FAIL" -eq 0 ]]
}

main "$@"
