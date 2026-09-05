#!/usr/bin/env bash
# Stress agent↔host communication against java-target.
#
# Modes:
#   flood (default) — unidirectional send() + apk-tick impact
#   frida           — Frida-style send/recv ping-pong + binary data + rpc.exports
#                     (https://frida.re/docs/javascript-api/#communication-between-host-and-injected-process)
#
# Usage:
#   ./scripts/stress_comm.sh
#   ./scripts/stress_comm.sh --mode frida
#   ./scripts/stress_comm.sh --count 5000 --payload 256
#   ./scripts/stress_comm.sh --mode frida --count 500 --rpc-count 100
#   ./scripts/stress_comm.sh --no-restart
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${ROOT}/target/release/goauld"
DIST="${ROOT}/dist/android-arm64"
export PATH="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools:$PATH"

MODE=flood
COUNT=2000
PAYLOAD=64
BASELINE=1
MAX_WAIT=60
RPC_COUNT=200
RESTART=1
STAGE=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --payload) PAYLOAD="$2"; shift 2 ;;
    --baseline-secs) BASELINE="$2"; shift 2 ;;
    --max-wait-secs) MAX_WAIT="$2"; shift 2 ;;
    --rpc-count) RPC_COUNT="$2"; shift 2 ;;
    --no-restart) RESTART=0; shift ;;
    --no-stage) STAGE=0; shift ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ ! -x "$HOST" ]]; then
  echo "building goauld-host…"
  (cd "$ROOT" && cargo build -p goauld-host --release -q)
fi
[[ -f "$DIST/libgoauld_agent.so" ]] || {
  echo "missing $DIST — run ./scripts/build-android.sh" >&2
  exit 3
}

ARGS=(
  stress
  --mode "$MODE"
  --package com.example.javatarget
  --injector "$DIST/goauld-injector"
  --agent "$DIST/libgoauld_agent.so"
  --count "$COUNT"
  --payload "$PAYLOAD"
  --baseline-secs "$BASELINE"
  --max-wait-secs "$MAX_WAIT"
  --rpc-count "$RPC_COUNT"
)
[[ "$STAGE" -eq 1 ]] && ARGS+=(--stage-into-app)
[[ "$RESTART" -eq 0 ]] && ARGS+=(--no-restart)

exec "$HOST" "${ARGS[@]}"
