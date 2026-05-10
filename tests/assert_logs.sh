#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <log_file> <timeout_seconds> <pattern1> [pattern2 ...]"
  exit 1
fi

LOG_FILE="$1"
TIMEOUT_SECONDS="$2"
shift 2

if [[ ! -f "$LOG_FILE" ]]; then
  echo "log file not found: $LOG_FILE"
  exit 1
fi

deadline=$((SECONDS + TIMEOUT_SECONDS))

while (( SECONDS < deadline )); do
  all_ok=1

  for pattern in "$@"; do
    if ! grep -Fq -- "$pattern" "$LOG_FILE"; then
      all_ok=0
      break
    fi
  done

  if [[ "$all_ok" -eq 1 ]]; then
    echo "OK: all patterns found in $LOG_FILE"
    exit 0
  fi

  sleep 1
done

echo "TIMEOUT: missing pattern(s) in $LOG_FILE"
for pattern in "$@"; do
  if ! grep -Fq -- "$pattern" "$LOG_FILE"; then
    echo "  missing: $pattern"
  fi
done

exit 1
