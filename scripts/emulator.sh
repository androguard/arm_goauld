#!/usr/bin/env bash
# Start / stop the goauld AVD (GUI or headless).
#
# Usage:
#   ./scripts/emulator.sh start          # headless (default)
#   ./scripts/emulator.sh start --gui
#   ./scripts/emulator.sh stop
#   ./scripts/emulator.sh status
#   ./scripts/emulator.sh restart [--gui]
#
# Env:
#   GOAULD_AVD          AVD name (default: Goauld_API34)
#   ANDROID_HOME        SDK root (default: ~/Library/Android/sdk)
#   GOAULD_EMU_SERIAL   adb serial to target (default: first emulator-*)
set -euo pipefail

AVD="${GOAULD_AVD:-Goauld_API34}"
: "${ANDROID_HOME:=${HOME}/Library/Android/sdk}"
export PATH="${ANDROID_HOME}/emulator:${ANDROID_HOME}/platform-tools:${PATH}"

usage() {
  cat <<EOF
Usage: $0 {start|stop|status|restart} [--gui|--no-gui] [--avd NAME]

  start     boot AVD (headless unless --gui); wait for boot; adb root + setenforce 0
  stop      kill matching emulator process / emu-kill
  status    print adb devices + whether ${AVD} looks running
  restart   stop then start

Env: GOAULD_AVD, ANDROID_HOME, GOAULD_EMU_SERIAL
EOF
}

GUI=0
CMD=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    start|stop|status|restart) CMD="$1" ;;
    --gui) GUI=1 ;;
    --no-gui|--headless) GUI=0 ;;
    --avd)
      shift
      [[ $# -gt 0 ]] || { echo "ERROR: --avd needs a name" >&2; exit 2; }
      AVD="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: unknown arg: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

[[ -n "$CMD" ]] || { usage >&2; exit 2; }

need_tools() {
  command -v emulator >/dev/null || {
    echo "ERROR: emulator not on PATH (ANDROID_HOME=${ANDROID_HOME})" >&2
    exit 1
  }
  command -v adb >/dev/null || {
    echo "ERROR: adb not on PATH" >&2
    exit 1
  }
}

emulator_pids() {
  # Match qemu/emulator for this AVD only.
  pgrep -f "qemu-system.*-avd[ =]${AVD}|emulator.*-avd[ =]${AVD}" 2>/dev/null || true
}

pick_serial() {
  if [[ -n "${GOAULD_EMU_SERIAL:-}" ]]; then
    echo "$GOAULD_EMU_SERIAL"
    return
  fi
  adb devices | awk '/^emulator-/{print $1; exit}'
}

wait_boot() {
  local serial="$1"
  local i
  echo "waiting for boot (${serial})…"
  adb -s "$serial" wait-for-device
  for i in $(seq 1 120); do
    local prop
    prop="$(adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
    if [[ "$prop" == "1" ]]; then
      echo "boot completed"
      return 0
    fi
    sleep 1
  done
  echo "ERROR: timed out waiting for sys.boot_completed" >&2
  return 1
}

prepare_root() {
  local serial="$1"
  adb -s "$serial" root >/dev/null || true
  sleep 1
  adb -s "$serial" wait-for-device
  adb -s "$serial" shell "setenforce 0" >/dev/null 2>&1 || true
  echo "adb root + setenforce 0 on ${serial}"
}

cmd_status() {
  need_tools
  echo "AVD: ${AVD}"
  local pids
  pids="$(emulator_pids | tr '\n' ' ')"
  if [[ -n "${pids// }" ]]; then
    echo "emulator pids: ${pids}"
  else
    echo "emulator pids: (none)"
  fi
  echo "adb devices:"
  adb devices
}

cmd_stop() {
  need_tools
  local serial
  serial="$(pick_serial || true)"
  if [[ -n "${serial:-}" ]]; then
    echo "adb -s ${serial} emu kill"
    adb -s "$serial" emu kill >/dev/null 2>&1 || true
  fi
  # Fallback if emu kill did not catch it.
  local pids
  pids="$(emulator_pids)"
  if [[ -n "$pids" ]]; then
    echo "killing leftover pids: $(echo "$pids" | tr '\n' ' ')"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    sleep 1
    pids="$(emulator_pids)"
    if [[ -n "$pids" ]]; then
      # shellcheck disable=SC2086
      kill -9 $pids 2>/dev/null || true
    fi
  fi
  echo "stopped"
}

cmd_start() {
  need_tools
  if [[ -n "$(emulator_pids)" ]]; then
    echo "already running (${AVD}); use stop/restart if you want a fresh boot"
    local serial
    serial="$(pick_serial || true)"
    if [[ -n "${serial:-}" ]]; then
      prepare_root "$serial"
    fi
    return 0
  fi

  if ! emulator -list-avds 2>/dev/null | grep -qx "$AVD"; then
    echo "ERROR: AVD '${AVD}' not found. Available:" >&2
    emulator -list-avds >&2 || true
    exit 1
  fi

  local -a args=(
    -avd "$AVD"
    -no-audio
    -no-boot-anim
    -gpu swiftshader_indirect
    -accel on
    -writable-system
  )
  if [[ "$GUI" -eq 0 ]]; then
    args+=(-no-window)
    echo "starting ${AVD} headless…"
  else
    echo "starting ${AVD} with GUI…"
  fi

  # Detach so this script can wait on adb without holding the emulator tty.
  local log="${TMPDIR:-/tmp}/goauld-emulator-${AVD}.log"
  nohup emulator "${args[@]}" >"$log" 2>&1 &
  echo "emulator pid $!  log: $log"

  # Serial appears after qemu binds adb.
  local serial=""
  local i
  for i in $(seq 1 60); do
    serial="$(pick_serial || true)"
    if [[ -n "$serial" ]]; then
      break
    fi
    sleep 1
  done
  [[ -n "$serial" ]] || {
    echo "ERROR: no emulator serial in adb devices (see $log)" >&2
    exit 1
  }

  wait_boot "$serial"
  prepare_root "$serial"
  echo "ready: ${serial} (AVD=${AVD})"
}

case "$CMD" in
  status) cmd_status ;;
  stop) cmd_stop ;;
  start) cmd_start ;;
  restart)
    cmd_stop
    sleep 2
    cmd_start
    ;;
esac
