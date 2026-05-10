#!/usr/bin/env bash
# =============================================================================
# ESS P2P — join.sh
# Bergabung ke jaringan yang sudah ada sebagai supernode baru.
# Usage: bash join.sh /ip4/<IP>/tcp/5001/p2p/<PEER_ID>
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

BOOTSTRAP_ADDR="${1:-}"

if [ -z "$BOOTSTRAP_ADDR" ]; then
    echo -e "${RED}[✗]${NC} Usage: bash join.sh /ip4/<IP>/tcp/5001/p2p/<PEER_ID>"
    echo -e "       Dapatkan multiaddr dari output genesis.sh di node pertama."
    exit 1
fi

# Validasi format multiaddr
if ! echo "$BOOTSTRAP_ADDR" | grep -qE '^/ip4/.+/tcp/[0-9]+/p2p/12D3Koo'; then
    echo -e "${YELLOW}[!]${NC} Format multiaddr mungkin salah: $BOOTSTRAP_ADDR"
    echo -e "     Format yang benar: /ip4/1.2.3.4/tcp/5001/p2p/12D3Koo..."
fi

# Load .env
if [ -f .env ]; then
    set -a; source .env; set +a
else
    echo -e "${YELLOW}[!]${NC} .env tidak ada, menjalankan setup dulu..."
    bash setup.sh
    set -a; source .env; set +a
fi

# Override bootstrap
export BOOTSTRAP_P2P_MULTIADDRS="$BOOTSTRAP_ADDR"
# Juga update .env
sed -i "s|^BOOTSTRAP_P2P_MULTIADDRS=.*|BOOTSTRAP_P2P_MULTIADDRS=${BOOTSTRAP_ADDR}|" .env

echo -e ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}   ESS P2P — JOINING NETWORK              ${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  Bootstrap : ${GREEN}${BOOTSTRAP_ADDR}${NC}"
echo -e "  Public IP : ${CYAN}${PUBLIC_IP:-auto-detect}${NC}"
echo -e "  Port      : ${CYAN}${P2P_PORT:-5001}${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e ""
echo -e "  ${YELLOW}Node akan otomatis:${NC}"
echo -e "  → Dial ke supernode bootstrap"
echo -e "  → Kirim onboarding request"
echo -e "  → Sync policy dari supernode"
echo -e "  → Join Kademlia DHT (auto-discover peer lain)"
echo -e "  → Governance voting untuk aktivasi"
echo -e ""

cargo run --release
