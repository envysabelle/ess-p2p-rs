#!/usr/bin/env bash
# =============================================================================
# ESS P2P — setup.sh
# Jalankan SEKALI sebelum cargo run untuk menyiapkan semua file konfigurasi.
# Usage: bash setup.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}══════════════════════════════════════════${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}══════════════════════════════════════════${NC}"; }

section "ESS P2P — Setup Script"

# ── 1. Cek env .env (opsional load) ──────────────────────────────────────────
if [ -f .env ]; then
    info "Memuat .env..."
    set -a; source .env; set +a
fi

# ── 2. Cek ESS_MASTER_SECRET ──────────────────────────────────────────────────
if [ -z "${ESS_MASTER_SECRET:-}" ]; then
    warn "ESS_MASTER_SECRET tidak ditemukan di env."
    read -rp "  Masukkan ESS_MASTER_SECRET (atau Enter untuk pakai default dev): " inp_secret
    if [ -z "$inp_secret" ]; then
        ESS_MASTER_SECRET="ESS_Dev_Secret_Change_In_Production_2026"
        warn "Memakai secret default. GANTI untuk produksi!"
    else
        ESS_MASTER_SECRET="$inp_secret"
    fi
    export ESS_MASTER_SECRET
fi
info "ESS_MASTER_SECRET: [SET]"

# ── 3. Buat direktori ─────────────────────────────────────────────────────────
mkdir -p data/identity data/bootstrap data/kad_store data/world_state
info "Direktori data/ dibuat."

# ── 4. Buat data/policy_inner.toml (format JSON) ─────────────────────────────
POLICY_FILE="data/policy_inner.toml"
if [ ! -f "$POLICY_FILE" ]; then
    cat > "$POLICY_FILE" << 'POLICY_EOF'
{
  "allowed_peers": [],
  "allowed_actions": ["connect", "route", "gateway_access", "web_traffic", "network_runner_boot"],
  "bootstrap_addrs": [],
  "trusted_bundle_hash": null,
  "response_verification_enabled": false
}
POLICY_EOF
    info "File $POLICY_FILE dibuat."
else
    info "File $POLICY_FILE sudah ada — tidak diubah."
fi

# ── 5. Hitung Serial Number dari ESS_MASTER_SECRET ───────────────────────────
# Format: ESSBB-NODE-001-XXXX (XXXX = 4 char terakhir HMAC-SHA256)
BASE_SN="ESSBB-NODE-001"
CHECKSUM=$(echo -n "$BASE_SN" | openssl dgst -sha256 -hmac "$ESS_MASTER_SECRET" | awk '{print $2}' | tail -c 5 | tr '[:lower:]' '[:upper:]')
SERIAL_NUMBER="${BASE_SN}-${CHECKSUM}"
info "Serial Number digenerate: $SERIAL_NUMBER"

# ── 6. Buat .env file ─────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    # Deteksi public IP otomatis
    PUBLIC_IP_DETECTED=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "127.0.0.1")

    cat > .env << ENV_EOF
# ============================================================
# ESS P2P — Environment Configuration
# Edit sesuai kebutuhan, lalu: source .env && cargo run
# ============================================================

# SECRET — WAJIB, sama di semua node dalam satu jaringan
ESS_MASTER_SECRET="${ESS_MASTER_SECRET}"

# IDENTITAS NODE
ESS_NODE_NAME="ESS Node $(hostname)"
ESS_NODE_EMAIL="node@$(hostname).local"
ESS_SERIAL_NUMBER="${SERIAL_NUMBER}"

# ROLE: supernode | gateway | client
NODE_ROLE=supernode

# NETWORK
PUBLIC_IP=${PUBLIC_IP_DETECTED}
P2P_PORT=5001

# BOOTSTRAP: kosongkan untuk supernode PERTAMA (genesis).
# Untuk node ke-2 dst, isi dengan multiaddr supernode pertama:
# BOOTSTRAP_P2P_MULTIADDRS=/ip4/<IP_NODE1>/tcp/5001/p2p/<PEER_ID_NODE1>
BOOTSTRAP_P2P_MULTIADDRS=

# AUTHORITY: kosongkan untuk genesis (akan diisi setelah run pertama).
# Setelah run pertama, isi AUTHORITY_SUPERNODES dengan PeerID yang muncul di log,
# hapus data/authority.bin, lalu run lagi.
AUTHORITY_SUPERNODES=

# DASHBOARD
ESS_DASHBOARD_BIND=127.0.0.1:8080
# ESS_DASHBOARD_TOKEN=ganti-dengan-token-rahasia

# LOGGING
RUST_LOG=info
ENV_EOF
    info "File .env dibuat. Edit PUBLIC_IP dan BOOTSTRAP_P2P_MULTIADDRS sesuai kebutuhan."
else
    info "File .env sudah ada — tidak ditimpa."
fi

# ── 7. Tampilkan ringkasan ────────────────────────────────────────────────────
section "Setup Selesai!"
echo ""
echo -e "  ${CYAN}Langkah selanjutnya:${NC}"
echo ""
echo -e "  ${YELLOW}=== SUPERNODE PERTAMA (Genesis) ===${NC}"
echo -e "  1. Edit .env — pastikan PUBLIC_IP benar"
echo -e "  2. ${GREEN}source .env && cargo run --release${NC}"
echo -e "     → Catat PeerID di log: ${CYAN}[DEBUG] Identity ready: 12D3Koo...${NC}"
echo -e "  3. Ctrl+C setelah dapat PeerID"
echo -e "  4. Edit .env → set ${CYAN}AUTHORITY_SUPERNODES=<PeerID>    ${NC}"
echo -e "  5. ${GREEN}rm -f data/authority.bin${NC}"
echo -e "  6. ${GREEN}source .env && cargo run --release${NC}"
echo -e "     → Node sekarang berjalan sebagai supernode resmi ✅"
echo ""
echo -e "  ${YELLOW}=== SUPERNODE KE-2, KE-3, DST ===${NC}"
echo -e "  1. Copy folder ini ke server baru, jalankan ${GREEN}bash setup.sh${NC}"
echo -e "  2. Edit .env:"
echo -e "     ${CYAN}BOOTSTRAP_P2P_MULTIADDRS=/ip4/<IP_NODE1>/tcp/5001/p2p/<PEER_ID_NODE1>${NC}"
echo -e "     ${CYAN}PUBLIC_IP=<IP_SERVER_INI>${NC}"
echo -e "  3. ${GREEN}source .env && cargo run --release${NC}"
echo -e "     → Auto-join ke jaringan, governance voting aktif ✅"
echo ""
echo -e "  ${YELLOW}Dashboard:${NC} http://127.0.0.1:8080"
echo ""
