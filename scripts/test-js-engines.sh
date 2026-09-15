#!/usr/bin/env bash
# Host unit tests for both JS engines (QuickJS + Symbiote).
#
# Usage:
#   ./scripts/test-js-engines.sh           # both
#   ./scripts/test-js-engines.sh quickjs
#   ./scripts/test-js-engines.sh symbiote
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

run_engine() {
  local eng="$1"
  echo "== goauld-script tests ($eng) =="
  case "$eng" in
    quickjs)
      cargo test -p goauld-script --features quickjs --lib js_engine_ -- --test-threads=1
      ;;
    symbiote)
      cargo test -p goauld-script --no-default-features --features symbiote --lib js_engine_ \
        -- --test-threads=1
      ;;
    *)
      echo "unknown engine: $eng" >&2
      exit 1
      ;;
  esac
  echo "OK $eng"
}

TARGET="${1:-both}"
case "$TARGET" in
  -h|--help|help)
    cat <<EOF
Usage: $0 [both|quickjs|symbiote]

Runs shared host smoke tests (`js_engine_*`: send + Process/Memory/timers/Script.runtime)
against each JS engine feature set.
EOF
    exit 0
    ;;
  both)
    run_engine quickjs
    run_engine symbiote
    ;;
  quickjs|symbiote)
    run_engine "$TARGET"
    ;;
  *)
    echo "usage: $0 [both|quickjs|symbiote]" >&2
    exit 1
    ;;
esac

echo "OK: JS engine tests passed ($TARGET)"
