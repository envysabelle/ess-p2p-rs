#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/tests/logs"
mkdir -p "$LOG_DIR"

ROLE="${NODE_ROLE:-client}"
PUBLIC_IP="${PUBLIC_IP:-127.0.0.1}"
PORT="${PORT:-4001}"
P2P_PORT="${P2P_PORT:-5001}"
BOOTSTRAP_P2P_MULTIADDRS="${BOOTSTRAP_P2P_MULTIADDRS:-}"
GATEWAY_ROUTE_P2P_MULTIADDRS="${GATEWAY_ROUTE_P2P_MULTIADDRS:-}"

LOG_FILE="$LOG_DIR/${ROLE}.log"
FIFO_FILE="$LOG_DIR/${ROLE}.fifo"

rm -f "$LOG_FILE" "$FIFO_FILE"
mkfifo "$FIFO_FILE"

cleanup() {
  rm -f "$FIFO_FILE"
}
trap cleanup EXIT

echo "[test] starting $ROLE"
(
  cd "$ROOT_DIR"
  env \
    NODE_ROLE="$ROLE" \
    PUBLIC_IP="$PUBLIC_IP" \
    PORT="$PORT" \
    P2P_PORT="$P2P_PORT" \
    BOOTSTRAP_P2P_MULTIADDRS="$BOOTSTRAP_P2P_MULTIADDRS" \
    GATEWAY_ROUTE_P2P_MULTIADDRS="$GATEWAY_ROUTE_P2P_MULTIADDRS" \
    cargo run --release
) <"$FIFO_FILE" >"$LOG_FILE" 2>&1 &
APP_PID=$!

writer() {
  {
    sleep 12
    echo "peers"
    sleep 6
    echo "help"
    sleep 6
    echo "peers"
  } >"$FIFO_FILE"
}

writer &
WRITER_PID=$!

echo "[test] waiting for boot logs..."
"$ROOT_DIR/tests/assert_logs.sh" "$LOG_FILE" 90 \
  "[ESS] ID" \
  "[ESS] PEER" \
  "[BOOT] role=${ROLE}" \
  "[CLI] type: send <text>"

echo "[test] waiting for runtime logs..."
"$ROOT_DIR/tests/assert_logs.sh" "$LOG_FILE" 120 \
  "[PING] Event" \
  "[PEERS] connected="

wait "$WRITER_PID" || true
kill "$APP_PID" 2>/dev/null || true
wait "$APP_PID" 2>/dev/null || true

echo "[test] smoke test done: $LOG_FILE"
