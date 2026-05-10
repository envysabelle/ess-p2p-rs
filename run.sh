#!/usr/bin/env bash
# =============================================================================
# ESS P2P — run.sh
# Start node dengan otomatis load .env
# Usage: bash run.sh [--release]
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

# Load .env
if [ -f .env ]; then
    set -a; source .env; set +a
    echo -e "${GREEN}[✓]${NC} .env loaded"
else
    echo -e "${RED}[✗]${NC} .env tidak ditemukan! Jalankan: bash setup.sh"
    exit 1
fi

# Cek wajib
if [ -z "${ESS_MASTER_SECRET:-}" ]; then
    echo -e "${RED}[✗]${NC} ESS_MASTER_SECRET tidak di-set di .env!"; exit 1
fi

# Pastikan policy file ada
if [ ! -f "data/policy_inner.toml" ]; then
    echo -e "${YELLOW}[!]${NC} data/policy_inner.toml tidak ada — menjalankan setup..."
    bash setup.sh
fi

# Tampilkan info
echo -e ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}   ESS P2P BACKBONE STARTING              ${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "  Role        : ${GREEN}${NODE_ROLE:-client}${NC}"
echo -e "  Public IP   : ${CYAN}${PUBLIC_IP:-not-set}${NC}"
echo -e "  P2P Port    : ${CYAN}${P2P_PORT:-5001}${NC}"
echo -e "  Bootstrap   : ${CYAN}${BOOTSTRAP_P2P_MULTIADDRS:-(genesis mode)}${NC}"
echo -e "  Dashboard   : ${CYAN}http://${ESS_DASHBOARD_BIND:-127.0.0.1:8080}${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e ""

BUILD_FLAG="${1:---release}"
if [ "$BUILD_FLAG" = "--release" ]; then
    cargo run --release
else
    cargo run
fi
