#!/usr/bin/env bash
# =============================================================================
# ESS P2P — genesis.sh
# Otomatis handle 2-step genesis supernode pertama:
#   Step 1: Run singkat → tangkap PeerID → Ctrl+C otomatis
#   Step 2: Set AUTHORITY_SUPERNODES → Run permanen sebagai supernode
# Usage: bash genesis.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}══════════════════════════════════════════${NC}\n  $*\n${CYAN}══════════════════════════════════════════${NC}"; }

# Load .env
if [ -f .env ]; then
    set -a; source .env; set +a
else
    error ".env tidak ditemukan! Jalankan: bash setup.sh"
fi

section "STEP 1 — Deteksi PeerID"
warn "Menjalankan node sementara untuk mendapatkan PeerID (akan stop otomatis dalam 10 detik)..."

# Build dulu
cargo build --release 2>&1 | tail -5

LOGFILE=$(mktemp /tmp/ess_genesis_XXXXX.log)
# Jalankan di background, tangkap log
./target/release/ess-p2p-rs > "$LOGFILE" 2>&1 &
ESS_PID=$!

info "Node berjalan (PID: $ESS_PID), menunggu PeerID..."

PEER_ID=""
for i in $(seq 1 30); do
    sleep 1
    # Cari PeerID dari log (format JSON tracing)
    PEER_ID=$(grep -o '"12D3Koo[A-Za-z0-9]*"' "$LOGFILE" 2>/dev/null | head -1 | tr -d '"' || true)
    if [ -n "$PEER_ID" ]; then
        break
    fi
    # Fallback: cari dari format plain log
    PEER_ID=$(grep -o 'Identity ready: 12D3Koo[A-Za-z0-9]*' "$LOGFILE" 2>/dev/null | head -1 | awk '{print $NF}' || true)
    if [ -n "$PEER_ID" ]; then
        break
    fi
done

# Stop node
kill "$ESS_PID" 2>/dev/null || true
wait "$ESS_PID" 2>/dev/null || true

if [ -z "$PEER_ID" ]; then
    warn "PeerID tidak terdeteksi otomatis. Log tersimpan di: $LOGFILE"
    warn "Cari PeerID secara manual di log (format: 12D3Koo...):"
    grep -o '12D3Koo[A-Za-z0-9]*' "$LOGFILE" | head -5 || true
    echo ""
    read -rp "  Paste PeerID di sini: " PEER_ID
fi

if [ -z "$PEER_ID" ]; then
    error "PeerID tidak ditemukan. Cek log: $LOGFILE"
fi

info "PeerID terdeteksi: ${CYAN}${PEER_ID}${NC}"

# ── Update .env ───────────────────────────────────────────────────────────────
section "STEP 2 — Configure Genesis Authority"

# Update AUTHORITY_SUPERNODES di .env
if grep -q "^AUTHORITY_SUPERNODES=" .env; then
    sed -i "s|^AUTHORITY_SUPERNODES=.*|AUTHORITY_SUPERNODES=${PEER_ID}|" .env
else
    echo "AUTHORITY_SUPERNODES=${PEER_ID}" >> .env
fi
info ".env diupdate: AUTHORITY_SUPERNODES=${PEER_ID}"

# Reload env
set -a; source .env; set +a

# Hapus authority.bin lama agar genesis ulang
rm -f data/authority.bin
info "data/authority.bin dihapus — genesis authority akan dibuat ulang."

rm -f "$LOGFILE"

section "STEP 3 — Launching Genesis Supernode"
echo ""
echo -e "  ${GREEN}PeerID Supernode:${NC} ${CYAN}${PEER_ID}${NC}"
echo -e "  ${GREEN}Multiaddr:${NC}        ${CYAN}/ip4/${PUBLIC_IP:-127.0.0.1}/tcp/${P2P_PORT:-5001}/p2p/${PEER_ID}${NC}"
echo ""
echo -e "  ${YELLOW}Simpan multiaddr di atas untuk konfigurasi node-node berikutnya!${NC}"
echo ""

cargo run --release
