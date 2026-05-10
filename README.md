# ESS P2P RS — Backbone Network Node

> **ESS P2P Backbone** adalah node jaringan peer-to-peer terdesentralisasi yang dibangun di atas [libp2p](https://libp2p.io/), ditulis dalam Rust. Sistem ini dirancang untuk komunikasi aman, otonom, dan tahan sensor, dengan lapisan kriptografi berlapis mulai dari onion routing hingga post-quantum cryptography (PQC).

---

## Daftar Isi

- [Fitur Utama](#fitur-utama)
- [Arsitektur Sistem](#arsitektur-sistem)
- [Prasyarat](#prasyarat)
- [Struktur Proyek](#struktur-proyek)
- [Konfigurasi Environment](#konfigurasi-environment)
- [Quick Start](#quick-start)
  - [Node Pertama (Genesis Supernode)](#1-node-pertama-genesis-supernode)
  - [Node Berikutnya (Join)](#2-node-berikutnya-join)
  - [Manual via run.sh](#3-manual-via-runsh)
- [Peran Node (Node Role)](#peran-node-node-role)
- [Sistem Keamanan](#sistem-keamanan)
- [Dashboard HTTP](#dashboard-http)
- [Ghost Engine](#ghost-engine)
- [Governance](#governance)
- [CRDT & Merkle-DAG](#crdt--merkle-dag)
- [Onboarding](#onboarding)
- [Pengujian](#pengujian)
- [Utilitas](#utilitas)
- [Catatan Produksi](#catatan-produksi)

---

## Fitur Utama

| Fitur | Detail |
|---|---|
| **P2P Networking** | libp2p dengan Kademlia DHT, Noise protocol, Yamux multiplexing |
| **Onion Routing** | 3-hop default, X25519 ECDH ephemeral + ChaCha20-Poly1305 per hop |
| **Post-Quantum Crypto** | ML-KEM-1024 (Kyber) hybrid dengan X25519 via HKDF |
| **Shamir Secret Sharing** | Skema threshold (k, n) di GF(2⁸), kompatibel AES polynomial |
| **Authority & RBAC** | Supernode-based authority dengan 7 level role dan signed config bundle |
| **CRDT State** | LWW-Register, G-Set, G-Counter, LWW-Map, OR-Set — eventual consistency |
| **Merkle-DAG Audit** | Audit trail immutable untuk setiap perubahan state CRDT |
| **Ghost Engine** | Daemon otonom (8 state machine) untuk self-healing & peer management |
| **Governance** | On-chain voting proposal dengan quorum ratio antar supernode |
| **Key Rotation** | Forward secrecy via hash-chain seed rotation setiap 24 jam |
| **Encrypted Keystore** | AES-256-GCM + PBKDF2 untuk perlindungan kunci lokal |
| **Dashboard HTTP** | REST API + SSE live telemetry di port 8080 |
| **Onboarding** | HMAC-SHA256 serial verification + X25519 pubkey exchange |
| **Bootstrap Cache** | Peer caching otomatis untuk reconnect setelah restart |

---

## Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────┐
│                        main.rs                              │
│  Lifecycle: Boot → Ready → Recovery → Shutdown              │
└────────────┬────────────────────────────────────────────────┘
             │
     ┌───────┴──────────────────────────────────────┐
     │              Subsystem Layer                 │
     │                                              │
     │  ┌──────────────┐  ┌──────────────────────┐  │
     │  │  Identity    │  │  Authority Manager   │  │
     │  │  (Ed25519)   │  │  (RBAC + Policy)     │  │
     │  └──────────────┘  └──────────────────────┘  │
     │                                              │
     │  ┌──────────────┐  ┌──────────────────────┐  │
     │  │  Ghost Engine│  │  Security Runtime    │  │
     │  │  (8 states)  │  │  (Replay + Sig check)│  │
     │  └──────────────┘  └──────────────────────┘  │
     │                                              │
     │  ┌──────────────┐  ┌──────────────────────┐  │
     │  │  Governance  │  │  CRDT State Engine   │  │
     │  │  (Voting)    │  │  + Merkle-DAG        │  │
     │  └──────────────┘  └──────────────────────┘  │
     └───────────────────────┬──────────────────────┘
                             │
             ┌───────────────┴────────────────┐
             │         Network Layer          │
             │  libp2p Swarm                  │
             │  ├─ Kademlia DHT               │
             │  ├─ Identify                   │
             │  ├─ Ping                       │
             │  ├─ RequestResponse            │
             │  └─ Noise + Yamux             │
             │                               │
             │  Onion Routing Layer          │
             │  (X25519 + ChaCha20-Poly1305) │
             └───────────────────────────────┘
                             │
             ┌───────────────┴────────────────┐
             │       Dashboard HTTP           │
             │  REST API + SSE Telemetry      │
             │  Port: ESS_DASHBOARD_BIND      │
             └───────────────────────────────┘
```

### Alur Startup (`main.rs`)

1. **Boot** — Load identity (Ed25519), init keystore, generate X25519 onion key
2. **Authority Init** — Load atau genesis `AuthorityState` dari `data/authority.bin`
3. **Onboarding** — Verifikasi profile lokal, kirim `OnboardRequest` ke supernode (jika bukan genesis)
4. **Ghost + Bridge** — Spawn `GhostRuntime` dan `GhostBridge` (daemon otonom)
5. **Dashboard** — Spawn HTTP server + `DashboardBridge` untuk live telemetry
6. **Network Run** — Jalankan libp2p swarm + `ControlLoop`
7. **Ready** → Recovery / Shutdown jika ada sinyal

---

## Prasyarat

- **Rust** ≥ 1.75 (dengan Cargo)
- **OpenSSL** / `libssl-dev` (Linux) atau `openssl` (macOS)
- **curl** (untuk deteksi public IP otomatis di `setup.sh`)
- **bash** ≥ 4.0

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev curl

# macOS
brew install openssl pkg-config
```

---

## Struktur Proyek

```
ess-p2p-rs-main/
├── Cargo.toml                  # Dependensi utama
├── export_pubkey.rs            # Utilitas ekspor public key dari identity.bin
├── genesis.sh                  # Script otomatis setup genesis supernode
├── join.sh                     # Script join jaringan yang sudah ada
├── run.sh                      # Script start node (load .env otomatis)
├── setup.sh                    # Setup awal: .env, direktori, policy file
├── src/
│   ├── main.rs                 # Entry point, lifecycle management
│   ├── config.rs               # NetworkConfig, ConfigBundle, ConfigRequest/Response
│   ├── identity.rs             # EssIdentity (Ed25519 keypair + ESS ID)
│   ├── authority.rs            # AuthorityManager, NodeRole, RBAC, signed policy
│   ├── keystore.rs             # SoftwareKeystore (AES-256-GCM + PBKDF2)
│   ├── onboarding.rs           # LocalProfile, OnboardingManager, X25519 key exchange
│   ├── storage.rs              # Atomic JSON I/O, WorldStateStore
│   ├── world_state.rs          # WorldState (SharedWorldState via Arc<RwLock>)
│   ├── control_loop.rs         # ControlLoop (event dispatch, ID rotation trigger)
│   ├── network_controller.rs   # NetworkController, peer reputation tracking
│   ├── bootstrap_cache.rs      # Bootstrap peer caching
│   ├── kad_store.rs            # Kademlia custom store
│   ├── message.rs              # DirectRequest/Response message types
│   ├── codec.rs                # Custom libp2p codec
│   ├── system_event.rs         # SystemEvent, SystemEventKind enum
│   │
│   ├── security.rs             # SecurityError taxonomy, signing helpers
│   ├── security_runtime.rs     # SecurityRuntime (replay detection, sig verify)
│   │
│   ├── onion.rs                # Onion routing: X25519 ECDH + ChaCha20-Poly1305
│   ├── pqc.rs                  # Post-quantum: ML-KEM-1024 + X25519 hybrid
│   ├── sss.rs                  # Shamir Secret Sharing di GF(2⁸)
│   ├── id_rotation.rs          # Forward-secrecy key rotation (hash-chain, 24 jam)
│   │
│   ├── crdt_state.rs           # CRDT: LWW-Register, G-Set, G-Counter, OR-Set
│   ├── merkle_dag.rs           # Merkle-DAG audit trail untuk CRDT state
│   │
│   ├── ghost.rs                # GhostEngine (8 state machine)
│   ├── ghost_bridge.rs         # GhostBridge (channel antara Ghost & Network)
│   ├── ghost_health.rs         # GhostHealthSnapshot, health assessment
│   ├── ghost_policy.rs         # GhostPolicy (reputation, throttle, self-heal)
│   ├── ghost_runtime.rs        # GhostRuntime (async task spawner)
│   ├── ghost_store.rs          # GhostSnapshot persistence
│   │
│   ├── gateway.rs              # Gateway access validation, rate limiting, audit log
│   ├── web.rs                  # WebRequest/Response via gateway
│   │
│   ├── governance/
│   │   ├── mod.rs              # Re-export modul governance
│   │   ├── engine.rs           # GovernanceEngine, Proposal, quorum voting
│   │   ├── messages.rs         # ProposalType, VoteMessage, GovernanceMessage
│   │   ├── store.rs            # Persistence proposal ke sled
│   │   └── tests.rs            # Unit test governance
│   │
│   ├── dashboard/
│   │   ├── mod.rs              # Re-export dashboard
│   │   ├── api.rs              # JSON payload builder (world, summary, logs)
│   │   ├── http.rs             # HTTP handler (axum/hyper route)
│   │   ├── model.rs            # DashboardSummary, NodeInfo, NodeHealth, RouteInfo, LogEvent
│   │   ├── server.rs           # serve_dashboard_http (bind + listen)
│   │   ├── service.rs          # DashboardService (query ke DashboardStore)
│   │   └── store.rs            # DashboardStore (in-memory state untuk dashboard)
│   ├── dashboard_bridge.rs     # DashboardBridge (channel update dari network ke dashboard)
│   │
│   └── network/
│       ├── mod.rs              # Re-export `run` entry point
│       ├── util.rs             # Network utility helpers
│       └── runtime/
│           ├── mod.rs          # Re-export runner
│           ├── runner.rs       # RuntimeContext, run_with_dashboard_and_authority
│           ├── swarm.rs        # libp2p Swarm builder (Noise, Yamux, Kad, Identify)
│           ├── events.rs       # SwarmEvent handler
│           ├── governance.rs   # Governance message handler di network layer
│           ├── support.rs      # Helper fungsi network runtime
│           └── types.rs        # OnboardRequest, TelemetryEvent, shared types
│
└── tests/
    ├── onboarding_tests.rs     # Unit test onboarding flow
    ├── run_smoke.sh            # Smoke test: single node startup
    ├── run_three_node.sh       # Integration test: 3-node cluster
    └── assert_logs.sh          # Helper: assert log output
```

---

## Konfigurasi Environment

File `.env` dibuat otomatis oleh `setup.sh`. Berikut semua variabel yang digunakan:

```env
# ── WAJIB ──────────────────────────────────────────────────────────────────
# Secret utama jaringan — HARUS SAMA di semua node dalam satu cluster.
# Digunakan untuk: PBKDF2 keystore, HMAC serial verification, key derivation.
ESS_MASTER_SECRET="ubah-ini-di-produksi"

# Alternatif password khusus untuk keystore (jika berbeda dari MASTER_SECRET)
# ESS_KEYSTORE_PASSWORD="password-keystore"

# ── IDENTITAS NODE ─────────────────────────────────────────────────────────
ESS_NODE_NAME="ESS Node hostname"
ESS_NODE_EMAIL="node@hostname.local"
ESS_SERIAL_NUMBER="ESSBB-NODE-001-XXXX"   # Di-generate oleh setup.sh

# ── ROLE NODE ──────────────────────────────────────────────────────────────
# Pilihan: supernode | gateway | client | observer | validator | blocked
NODE_ROLE=supernode

# ── NETWORK ────────────────────────────────────────────────────────────────
PUBLIC_IP=1.2.3.4        # IP publik node ini
P2P_PORT=5001            # Port TCP untuk libp2p

# Bootstrap peer (kosong untuk genesis supernode pertama)
# Format: /ip4/<IP>/tcp/<PORT>/p2p/<PEER_ID>
BOOTSTRAP_P2P_MULTIADDRS=

# ── AUTHORITY ──────────────────────────────────────────────────────────────
# PeerID supernode yang menjadi authority (diisi setelah genesis)
AUTHORITY_SUPERNODES=12D3KooW...

# ── DASHBOARD ──────────────────────────────────────────────────────────────
ESS_DASHBOARD_BIND=127.0.0.1:8080
# ESS_DASHBOARD_TOKEN=token-rahasia    # Opsional: Bearer token auth

# ── GHOST ENGINE ───────────────────────────────────────────────────────────
# Siklus minimum Ghost aktif sebelum boleh sleep (default: 10)
# GHOST_MIN_AWAKE_CYCLES=10

# ── ONION ROUTING ──────────────────────────────────────────────────────────
# Jumlah hop (0 = nonaktif, default: 3)
# ONION_HOPS=3
# Ukuran payload setelah padding bytes (0 = tanpa padding, default: 1400)
# ONION_PAYLOAD_SIZE=1400

# ── LOGGING ────────────────────────────────────────────────────────────────
RUST_LOG=info
# Format JSON: RUST_LOG_FORMAT=json
```

---

## Quick Start

### 1. Node Pertama (Genesis Supernode)

Gunakan script otomatis `genesis.sh` — menangani seluruh proses 2-step secara otomatis:

```bash
# Clone & masuk direktori
git clone <repo-url> ess-p2p-rs
cd ess-p2p-rs

# Jalankan setup awal
bash setup.sh

# Jalankan genesis (otomatis deteksi PeerID, update .env, lalu run permanen)
bash genesis.sh
```

`genesis.sh` melakukan:
1. Build binary (`cargo build --release`)
2. Jalankan node sementara (10–30 detik), tangkap PeerID dari log
3. Update `AUTHORITY_SUPERNODES` di `.env` dengan PeerID tersebut
4. Hapus `data/authority.bin` agar genesis authority dibuat ulang
5. Jalankan node permanen sebagai genesis supernode

Catat output multiaddr yang ditampilkan:
```
PeerID Supernode: 12D3KooW...
Multiaddr:        /ip4/1.2.3.4/tcp/5001/p2p/12D3KooW...
```

---

### 2. Node Berikutnya (Join)

```bash
# Di node baru, setup terlebih dahulu
bash setup.sh

# Join dengan multiaddr supernode pertama
bash join.sh /ip4/1.2.3.4/tcp/5001/p2p/12D3KooW...
```

`join.sh` akan:
1. Validasi format multiaddr
2. Set `BOOTSTRAP_P2P_MULTIADDRS` di `.env`
3. Jalankan node (`cargo run --release`)

---

### 3. Manual via run.sh

```bash
# Edit .env sesuai kebutuhan, lalu:
bash run.sh           # mode release (default)
bash run.sh --debug   # mode debug
```

---

## Peran Node (Node Role)

Diatur via `NODE_ROLE` di `.env`. Setiap role memiliki hak akses berbeda yang di-enforce oleh `AuthorityManager`:

| Role | Level | Hak Akses |
|---|---|---|
| `blocked` | 0 | Tidak boleh connect sama sekali |
| `observer` | 1 | Connect saja, tidak bisa route |
| `client` | 2 | Connect + route dasar |
| `standard` | 3 | Connect + route + web traffic |
| `gateway` | 4 | Semua standard + gateway access/egress |
| `validator` | 5 | Semua gateway + admin update |
| `supernode` | 6 | Full authority, bisa update policy cluster |

**Actions yang di-check:** `Connect`, `Route`, `GatewayAccess`, `GatewayEgress`, `WebTraffic`, `AdminUpdate`

Role disimpan di `data/identity/role.txt` dan di-bind ke `EssIdentity` saat startup. Perubahan role oleh authority supernode disebarkan via `ConfigBundle` yang ditandatangani secara kriptografis.

---

## Sistem Keamanan

### Kriptografi

| Layer | Algoritma | Implementasi |
|---|---|---|
| Identity | Ed25519 | `ed25519-dalek`, libp2p keypair |
| Transport | Noise Protocol + Yamux | libp2p built-in |
| Onion Routing | X25519 ECDH ephemeral + ChaCha20-Poly1305 | `x25519-dalek`, `chacha20poly1305` |
| Post-Quantum | ML-KEM-1024 (Kyber) + X25519 hybrid | `ml-kem` crate + HKDF-SHA3-256 |
| Keystore | AES-256-GCM + PBKDF2-SHA256 | `aes-gcm`, `pbkdf2` |
| Secret Sharing | Shamir GF(2⁸) threshold | Custom implementation di `sss.rs` |
| Message Auth | HMAC-SHA256 | `hmac` + `sha2` |
| Key Derivation | HKDF-SHA256 | `hkdf` |

### Security Runtime (`security_runtime.rs`)

- **Replay Detection**: Nonce-based, window timestamp ±N menit
- **Signature Verification**: Setiap `DirectRequest` diverifikasi tanda tangan Ed25519
- **Peer Identity Validation**: Hash pubkey peer vs. yang terdaftar di authority
- **Timestamp Window Enforcement**: Request di luar window langsung ditolak

### Onion Routing (`onion.rs`)

Setiap pesan melalui 3 hop default:

1. Sender generate **ephemeral X25519 keypair** per hop
2. ECDH antara ephemeral privkey + pubkey penerima hop → shared secret
3. `HKDF(shared_secret)` → ChaCha20-Poly1305 key + nonce
4. Payload dibungkus dari luar ke dalam (multi-layer encryption)
5. Setiap hop hanya bisa decrypt satu lapisan, hanya tahu hop berikutnya

**Keamanan tambahan:**
- Setiap `HopInfo` wajib menyertakan `activation_cert` — tanda tangan Ed25519 dari authority yang mengikat PeerID ke X25519 pubkey
- Di mode release: `authority_pubkey` wajib ada untuk verifikasi setiap hop

### Key Rotation (`id_rotation.rs`)

Setiap 24 jam, sistem merotasi seed internal menggunakan **hash-chain forward secrecy**:

```
epoch_0: seed = HKDF(master_secret, epoch_number)
epoch_1: seed = SHA256(epoch_0_seed)
epoch_2: seed = SHA256(epoch_1_seed)
...
```

Seed lama tidak bisa dihitung dari seed saat ini (backward secrecy). PeerID tidak berubah sehingga koneksi tetap stabil.

### Post-Quantum (`pqc.rs`)

Hybrid key exchange: **ML-KEM-1024 + X25519** dengan HKDF:

```
final_key = HKDF(mlkem_shared_secret || x25519_shared_secret)
```

Kunci di-zeroize setelah digunakan (`ZeroizeOnDrop`).

---

## Dashboard HTTP

Server HTTP otomatis berjalan di `ESS_DASHBOARD_BIND` (default: `127.0.0.1:8080`).

### Endpoint

| Endpoint | Method | Deskripsi |
|---|---|---|
| `/` | GET | Status node: world state, ghost, authority, peers |
| `/summary` | GET | Ringkasan: total node, supernode, relay, client |
| `/nodes` | GET | List semua node yang diketahui |
| `/routes` | GET | Tabel routing aktif |
| `/logs` | GET | Log events terbaru |
| `/health` | GET | Health check node (level: healthy/degraded/critical) |
| `/events` | GET | **SSE** live telemetry stream |

### Contoh Response `/`

```json
{
  "ok": true,
  "timestamp": "2026-01-01T00:00:00Z",
  "world": {
    "available": true,
    "authority_version": 5,
    "ghost_state": "idle",
    "health_level": "healthy",
    "connected_peers": 3,
    "known_peers": 10,
    "trusted_peers": 3
  },
  "summary": {
    "total_nodes": 10,
    "supernodes": 2,
    "relays": 3,
    "clients": 5
  }
}
```

Jika `ESS_DASHBOARD_TOKEN` di-set, setiap request wajib menyertakan header:
```
Authorization: Bearer <token>
```

---

## Ghost Engine

Ghost adalah daemon otonom yang berjalan di background, mengatur kesehatan dan perilaku node secara otomatis. Diimplementasikan sebagai state machine 8 state:

```
Init → Wake → Beacon → Sync → Idle → Sleep
                                    ↓
                               Panic → Zeroized
```

| State | Deskripsi |
|---|---|
| `Init` | Inisialisasi, validasi config |
| `Wake` | Aktif, mulai proses |
| `Beacon` | Broadcast kehadiran ke jaringan |
| `Sync` | Sinkronisasi state dengan peer |
| `Idle` | Tidak ada aktivitas, menunggu |
| `Sleep` | Hemat resource (jika `allow_sleep_when_healthy = true`) |
| `Panic` | Kondisi kritis, isolasi diri |
| `Zeroized` | Self-destruct: semua data sensitif di-zeroize |

### Ghost Policy (`ghost_policy.rs`)

| Parameter | Default | Deskripsi |
|---|---|---|
| `min_reputation_to_connect` | 0.2 | Reputasi minimum peer untuk terima koneksi |
| `quarantine_threshold` | < 0.2 | Threshold isolasi peer |
| `throttle_connected_peer_threshold` | configurable | Batasan peer sebelum throttle |
| `min_trusted_peers` | configurable | Minimum peer trusted sebelum panic |
| `panic_on_critical` | true | Auto-panic jika kondisi kritis |
| `drop_on_policy_denial` | true | Drop koneksi jika ditolak policy |

### GhostBridge

Channel komunikasi antara Ghost Engine dan Network Layer:
- Ghost menerima events dari network (peer connect/disconnect, route changes)
- Ghost mengirim perintah ke network (disconnect peer, broadcast beacon)

---

## Governance

Sistem voting desentralisasi antar supernode untuk perubahan policy jaringan.

### Tipe Proposal (`governance/messages.rs`)

- `AddSupernode` — Tambah supernode baru ke authority
- `RemoveSupernode` — Hapus supernode dari authority
- `UpdatePolicy` — Update policy (allowed_peers, actions, bootstrap_addrs)
- `BanPeer` — Ban peer dari jaringan
- `RotateKeys` — Trigger rotasi kunci jaringan

### Alur Voting

1. Supernode buat proposal → broadcast ke semua supernode
2. Setiap supernode kirim vote (`true`/`false`) dengan tanda tangan HMAC
3. Jika `votes_for / total_supernodes >= quorum_ratio` → proposal dieksekusi
4. **Bootstrap mode**: aktif jika supernode < 2, satu vote sudah cukup
5. **Bootstrap deadline**: 1 jam — setelah itu bootstrap mode otomatis exit

Proposal dan votes di-persist ke sled database via `governance/store.rs`.

---

## CRDT & Merkle-DAG

### CRDT State (`crdt_state.rs`)

Implementasi 5 primitive CRDT untuk strong eventual consistency:

| Tipe | Deskripsi | Use Case |
|---|---|---|
| `LwwRegister<T>` | Last-Write-Wins, timestamp terbaru menang | Config values, status |
| `GSet<T>` | Grow-only set, hanya bisa tambah | Peer list, audit entries |
| `GCounter` | Grow-only counter per node | Message count, hop count |
| `LwwMap<K,V>` | LWW per key | Peer registry |
| `OrSet<T>` | Observed-Remove Set | Peer presence dengan remove support |

**Merge rule**: `merge(A, B)` = state dengan timestamp terbaru menang (LWW). Semua node yang menerima set update yang sama akan converge ke state identik tanpa koordinasi central.

### Merkle-DAG Audit Trail (`merkle_dag.rs`)

Setiap perubahan state CRDT yang signifikan menghasilkan node baru:

```
MerkleNode {
  index:       u64,         // Sequential index
  state_hash:  SHA256(...), // Hash dari state JSON
  parent_hash: Option<...>, // Hash node sebelumnya
  timestamp:   u64,         // Unix timestamp
  metadata:    String,      // Deskripsi perubahan
}
```

Buffer dibatasi 1024 node (circular). Digunakan untuk verifikasi riwayat perubahan dan deteksi partisi jaringan.

---

## Onboarding

Node baru harus menyelesaikan proses onboarding sebelum dapat berpartisipasi penuh:

1. **LocalProfile** dibuat dari `ESS_NODE_NAME`, `ESS_NODE_EMAIL`, dan `ESS_SERIAL_NUMBER`
2. Serial number diverifikasi menggunakan `HMAC-SHA256(ESS_MASTER_SECRET, base_serial)`
3. Node generate **X25519 static keypair** (`data/identity/x25519_secret.bin`) untuk onion routing
4. `OnboardRequest` dikirim ke supernode via libp2p Request-Response:
   ```
   OnboardRequest {
     peer_id,
     serial_number,
     hmac_signature,
     x25519_pubkey,   // Hex-encoded
     timestamp,
   }
   ```
5. Supernode verifikasi HMAC, assign role, kirim `ConfigBundle` yang ditandatangani

File persisten onboarding: `data/identity/profile.json`

---

## Pengujian

```bash
# Unit test semua modul (termasuk governance tests)
cargo test

# Smoke test: start single node, cek startup berhasil
bash tests/run_smoke.sh

# Integration test: jalankan cluster 3 node lokal
bash tests/run_three_node.sh

# Assert log output (digunakan oleh smoke & integration test)
bash tests/assert_logs.sh <logfile> <expected_pattern>
```

Test governance ada di `src/governance/tests.rs` dan dijalankan via `cargo test`.

---

## Utilitas

### Export Public Key

Ekspor public key Ed25519 dari identity file (hex-encoded protobuf):

```bash
cargo run --bin export_pubkey
# Output: 08011220abcdef...
```

File identity ada di `data/identity/ess_identity.bin` (dibuat otomatis saat pertama run).

### Direktori Data

```
data/
├── identity/
│   ├── ess_identity.bin        # Ed25519 keypair (protobuf encoded)
│   ├── x25519_secret.bin       # X25519 static secret untuk onion routing
│   ├── profile.json            # LocalProfile (onboarding data)
│   └── role.txt                # NodeRole saat ini
├── keystore.enc                # Encrypted keystore (AES-256-GCM)
├── authority.bin               # AuthorityState (serialized + HMAC protected)
├── bootstrap/                  # Bootstrap peer cache
├── kad_store/                  # Kademlia DHT persistent store
├── world_state/                # WorldState snapshots
└── policy_inner.toml           # Policy configuration (JSON format)
```

---

## Catatan Produksi

> ⚠️ **PENTING** — Baca seluruh bagian ini sebelum deploy ke lingkungan produksi.

### Keamanan

- **Ganti `ESS_MASTER_SECRET`** — Jangan gunakan default dev. Secret harus sama di semua node dalam satu cluster dan disimpan aman (misalnya HashiCorp Vault, AWS Secrets Manager).
- **Set `ESS_DASHBOARD_TOKEN`** — Jika dashboard diekspos ke jaringan, wajib set token auth.
- **Bind Dashboard Lokal** — Default `127.0.0.1:8080` aman. Jangan expose ke `0.0.0.0` tanpa reverse proxy + TLS.
- **File Permission** — `data/identity/` dan `data/keystore.enc` harus permission `600` (hanya owner yang bisa baca). Script setup.sh menangani ini di Unix.
- **`authority.bin` dan HMAC** — File authority di-protect dengan HMAC. Jangan edit manual.

### Networking

- **Firewall**: Buka port `P2P_PORT` (default 5001/TCP) untuk traffic antar node.
- **`PUBLIC_IP`**: Harus diisi dengan IP publik yang dapat dijangkau node lain. Deteksi otomatis via `ipify.org` dilakukan di `setup.sh`.
- **NAT Traversal**: Saat ini belum ada built-in hole punching. Gunakan IP publik langsung atau VPN overlay.

### Performa & Stabilitas

- Gunakan `cargo run --release` atau binary dari `target/release/ess-p2p-rs` untuk produksi.
- Set `RUST_LOG=warn` di produksi untuk mengurangi overhead logging.
- Ghost Engine secara otomatis mengatur koneksi peer dan throttling. Tidak perlu konfigurasi manual kecuali ada kebutuhan khusus.

### Backup

- **`data/identity/ess_identity.bin`** — PeerID node berasal dari file ini. Backup dengan aman. Jika hilang, node akan memiliki PeerID baru dan perlu onboarding ulang.
- **`data/authority.bin`** — State authority jaringan. Backup rutin.

---

## Dependensi Utama

| Crate | Versi | Fungsi |
|---|---|---|
| `tokio` | 1.x | Async runtime |
| `libp2p` | 0.56 | P2P networking stack |
| `serde` / `serde_json` | 1.x | Serialisasi |
| `ed25519-dalek` | 1.x | Ed25519 signatures |
| `x25519-dalek` | 2.x | X25519 ECDH (onion routing) |
| `chacha20poly1305` | 0.10 | AEAD encryption (onion) |
| `aes-gcm` | 0.10 | AEAD encryption (keystore) |
| `ml-kem` | 0.3 | ML-KEM-1024 post-quantum |
| `hkdf` | 0.12 | Key derivation |
| `hmac` | 0.12 | Message authentication |
| `pbkdf2` | 0.12 | Password-based key derivation |
| `sled` | 0.34 | Embedded database (Kademlia store, governance) |
| `dashmap` | 5.x | Concurrent hash map (peer pubkey store) |
| `sha2` / `sha3` | 0.10 | Hash functions |
| `zeroize` | 1.7 | Secure memory zeroization |
| `tracing` / `tracing-subscriber` | 0.1/0.3 | Structured logging |
| `chrono` | 0.4 | Timestamp handling |
| `uuid` | 1.x | UUID generation (CRDT node IDs) |

---

*ESS P2P RS — Backbone Network Node*

