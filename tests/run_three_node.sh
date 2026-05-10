#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/tests/logs"
mkdir -p "$LOG_DIR"

: "${SSH_SUPERNODE:?set SSH_SUPERNODE=user@host for supernode london}"
: "${SSH_RELAY:?set SSH_RELAY=user@host for relay singapore}"
: "${SSH_CLIENT:?set SSH_CLIENT=user@host for client jakarta}"

REMOTE_REPO="${REMOTE_REPO:-~/ess-p2p-rs}"

SUPERNODE_PUBLIC_IP="${SUPERNODE_PUBLIC_IP:-13.41.78.146}"
RELAY_PUBLIC_IP="${RELAY_PUBLIC_IP:-13.229.48.49}"
CLIENT_PUBLIC_IP="${CLIENT_PUBLIC_IP:-36.69.90.152}"

SUPERNODE_P2P_PORT="${SUPERNODE_P2P_PORT:-5001}"
RELAY_P2P_PORT="${RELAY_P2P_PORT:-5001}"
CLIENT_P2P_PORT="${CLIENT_P2P_PORT:-5001}"

SUPERNODE_BOOTSTRAP="${SUPERNODE_BOOTSTRAP:-}"
RELAY_BOOTSTRAP="${RELAY_BOOTSTRAP:-/ip4/13.41.78.146/tcp/5001/p2p/12D3KooWQ5eWBMjjterLiYqJtguDxGXJrxmA63G6xnatYk5PDsRB}"
CLIENT_BOOTSTRAP="${CLIENT_BOOTSTRAP:-/ip4/13.41.78.146/tcp/5001/p2p/12D3KooWQ5eWBMjjterLiYqJtguDxGXJrxmA63G6xnatYk5PDsRB}"
CLIENT_ROUTE="${CLIENT_ROUTE:-/ip4/13.229.48.49/tcp/5001/p2p/12D3KooWNckY6nXzwBSKDmsScZt5x8zW7KPZA9S2SkkHwoLNMb5b,/ip4/13.41.78.146/tcp/5001/p2p/12D3KooWQ5eWBMjjterLiYqJtguDxGXJrxmA63G6xnatYk5PDsRB}"

start_remote() {
  local name="$1"
  local ssh_target="$2"
  local role="$3"
  local public_ip="$4"
  local p2p_port="$5"
  local bootstrap="$6"
  local route="${7:-}"
  local log_file="$LOG_DIR/${name}.log"
  local fifo_file="$LOG_DIR/${name}.fifo"

  rm -f "$log_file" "$fifo_file"
  mkfifo "$fifo_file"

  {
    if [[ -n "$route" ]]; then
      ssh "$ssh_target" "cd '$REMOTE_REPO' && env NODE_ROLE='$role' PUBLIC_IP='$public_ip' P2P_PORT='$p2p_port' BOOTSTRAP_P2P_MULTIADDRS='$bootstrap' GATEWAY_ROUTE_P2P_MULTIADDRS='$route' cargo run --release"
    else
      ssh "$ssh_target" "cd '$REMOTE_REPO' && env NODE_ROLE='$role' PUBLIC_IP='$public_ip' P2P_PORT='$p2p_port' BOOTSTRAP_P2P_MULTIADDRS='$bootstrap' cargo run --release"
    fi
  } <"$fifo_file" >"$log_file" 2>&1 &
  echo $! >"$LOG_DIR/${name}.pid"

  if [[ "$name" == "client" ]]; then
    {
      sleep 18
      echo "gw get https://envysabelle.com"
      sleep 10
      echo "gw post https://httpbin.org/post hello=world"
      sleep 10
      echo "peers"
    } >"$fifo_file" &
  else
    {
      sleep 20
      echo "peers"
    } >"$fifo_file" &
  fi
}

cleanup() {
  for f in "$LOG_DIR"/*.pid; do
    [[ -e "$f" ]] || continue
    pid="$(cat "$f" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  rm -f "$LOG_DIR"/*.pid "$LOG_DIR"/*.fifo
}
trap cleanup EXIT

start_remote "supernode" "$SSH_SUPERNODE" "supernode" "$SUPERNODE_PUBLIC_IP" "$SUPERNODE_P2P_PORT" "$SUPERNODE_BOOTSTRAP"
sleep 3
start_remote "relay" "$SSH_RELAY" "relay" "$RELAY_PUBLIC_IP" "$RELAY_P2P_PORT" "$RELAY_BOOTSTRAP"
sleep 3
start_remote "client" "$SSH_CLIENT" "client" "$CLIENT_PUBLIC_IP" "$CLIENT_P2P_PORT" "$CLIENT_BOOTSTRAP" "$CLIENT_ROUTE"

"$ROOT_DIR/tests/assert_logs.sh" "$LOG_DIR/supernode.log" 120 \
  "[ESS] ROLE supernode" \
  "[BOOT] role=supernode" \
  "[CFG ACK]" \
  "[GW SENT]"

"$ROOT_DIR/tests/assert_logs.sh" "$LOG_DIR/relay.log" 120 \
  "[ESS] ROLE relay" \
  "[BOOT] role=relay" \
  "[CFG ACK]" \
  "[GW FORWARD]" \
  "[GW ACK]"

"$ROOT_DIR/tests/assert_logs.sh" "$LOG_DIR/client.log" 120 \
  "[ESS] ROLE client" \
  "[BOOT] role=client" \
  "[CFG ACK]" \
  "[GW->]" \
  "[GW ACK]"

echo "all three nodes passed"
