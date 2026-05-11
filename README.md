<div align="center">
  <img src="https://envysabelle.com/assets/images/logo.png" alt="ESS Logo" width="180"/>
  <h1>ESS — Sovereign Network Operating System</h1>
  <p><em>Autonomous · Self-Healing · Censorship-Resistant · Post-Quantum Ready</em></p>
</div>

---

## The Two Layers of ESS

> Understanding the distinction between hardware and software is the foundation of everything ESS does.

```
┌─────────────────────────────────────────────────────────────────┐
│               PHYSICAL LAYER — Sabelle Black Box                │
│                                                                 │
│   Hardware node optimized for running ESS.                      │
│   Plug-and-play deployment, isolated secure enclave,            │
│   with zero dependency on any hyperscaler.                      │
│                                                                 │
│   [Can be replaced by: VPS / Bare-metal / Cloud Instance]      │
└─────────────────────┬───────────────────────────────────────────┘
                      │ runs on top of
┌─────────────────────▼───────────────────────────────────────────┐
│              SOFTWARE LAYER — ESS Node (this repo)              │
│                                                                 │
│   Network Operating System written in Rust.                     │
│   Manages identity, authority, routing, security,               │
│   governance, and state consistency autonomously.               │
│                                                                 │
│   This is what you deploy, configure, and operate.              │
└─────────────────────────────────────────────────────────────────┘
```

**ESS (Essential Sovereign System)** is not a messaging protocol. ESS is a **Network Operating System** — an autonomous infrastructure layer that enables sovereign, self-healing, and censorship-resistant networks to operate without dependency on public cloud providers, centralized authorities, or any third-party infrastructure.

This Rust codebase is the **Software Layer** of the ESS ecosystem. It is designed to run on top of **Sabelle Black Box** hardware (Physical Layer), but can be deployed on any VPS, bare-metal server, or cloud environment as a fully operator-controlled **Sovereign IaaS (Infrastructure as a Service)**.

> ESS transforms raw compute (hardware) into a **Sovereign IaaS** environment, where infrastructure services like networking, security, and state consistency are automated by the Ghost Engine.

---

## What Makes ESS Different?

Most people hear "P2P" and immediately think: *a decentralized chat app*. ESS is not that.

| Category | Common Examples | ESS |
|---|---|---|
| **Messaging P2P** | Signal, Session, Briar | ❌ Not this |
| **File Sharing P2P** | BitTorrent, IPFS | ❌ Not this |
| **Blockchain P2P** | Bitcoin, Ethereum | ❌ Not this |
| **Sovereign Infrastructure** | — | ✅ This is ESS |

**P2P in ESS is the transport layer, not the end product.** Running on top of it is a full infrastructure ecosystem: decentralized governance, autonomous routing, immutable audit trails, and node identity management that depends on no single entity.

---

## Core Capabilities

| Capability | Description |
|---|---|
| **Autonomous Mesh Routing** | libp2p + Kademlia DHT — the network discovers and sustains itself |
| **Onion Routing** | 3-hop minimum (enforced by `MIN_HOPS = 3`), ephemeral X25519 ECDH + ChaCha20-Poly1305 per hop, no single point of observation |
| **Post-Quantum Cryptography** | ML-KEM-1024 (Kyber / FIPS 203) hybrid with X25519 via HKDF — resistant to quantum computing attacks |
| **Ghost Engine** | Autonomous 8-state machine daemon: self-healing, peer management, panic isolation, and network-wide zeroization |
| **Sovereign Governance** | Decentralized voting among supernodes — network policy is decided collectively, not by a single admin |
| **CRDT State + Merkle-DAG** | Eventual consistency without a central coordinator + immutable forensic trail for every state change |
| **RBAC + Authority Chain** | 7 role levels, policy distributed via signed ConfigBundle |
| **Forward Secrecy** | 24-hour key rotation via hash-chain — past sessions cannot be decrypted even if the current key is compromised |
| **Shamir Secret Sharing** | Threshold scheme (k, n) over GF(2⁸) for distributing critical secrets |
| **Encrypted Keystore** | AES-256-GCM + PBKDF2 for local key protection |

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                           main.rs                                │
│         Lifecycle: Boot → Ready → Recovery → Shutdown            │
└──────────────┬───────────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────────┐
│                      SOVEREIGNTY LAYER                           │
│                                                                  │
│  ┌─────────────────┐   ┌──────────────────────────────────────┐  │
│  │   Identity      │   │        Authority Manager             │  │
│  │   (Ed25519)     │   │   (RBAC + Signed Policy Bundle)      │  │
│  └─────────────────┘   └──────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────────┐   ┌──────────────────────────────────────┐  │
│  │  Governance     │   │         Security Runtime             │  │
│  │  (On-chain      │   │   (Replay detection + Sig verify     │  │
│  │   Voting)       │   │    + Timestamp window enforcement)   │  │
│  └─────────────────┘   └──────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────────┐
│                     AUTONOMOUS LAYER                             │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                      Ghost Engine                           │ │
│  │   Init → Wake → Beacon → Sync → Idle → Sleep               │ │
│  │                              ↓                             │ │
│  │                         Panic → Zeroized                   │ │
│  │                                                            │ │
│  │  Self-healing • Peer reputation • Autonomous isolation     │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌─────────────────┐   ┌──────────────────────────────────────┐  │
│  │  CRDT State     │   │         Merkle-DAG                   │  │
│  │  Engine         │   │   Immutable forensic trail per       │  │
│  │  (5 primitives) │   │   state change                       │  │
│  └─────────────────┘   └──────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────────┐
│                      TRANSPORT LAYER                             │
│                                                                  │
│  libp2p Swarm                                                    │
│  ├─ Kademlia DHT        (peer discovery & routing)               │
│  ├─ Noise Protocol      (encrypted transport)                    │
│  ├─ Yamux               (multiplexing)                           │
│  ├─ Identify / Ping     (liveness)                               │
│  └─ RequestResponse     (direct messaging)                       │
│                                                                  │
│  Onion Routing Layer                                             │
│  (3-hop min • Ephemeral X25519 + ChaCha20-Poly1305 per hop)     │
│                                                                  │
│  Post-Quantum Hybrid Layer                                       │
│  (ML-KEM-1024 / FIPS 203 + X25519 → HKDF)                       │
│                                                                  │
│  Identity-Centric Networking (Zero-Trust)                        │
│  No IP-Based Trust: connections are never trusted based on IP    │
│  or location. Trust is derived solely from Ed25519 identity keys │
│  and valid Authority-signed activation certificates.             │
└──────────────────────────────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────────────┐
│                   OBSERVABILITY LAYER                            │
│            HTTP Dashboard: REST API + SSE Telemetry              │
│                    Port: ESS_DASHBOARD_BIND                      │
└──────────────────────────────────────────────────────────────────┘
```

### Startup Flow (`main.rs`)

1. **Boot** — Load Ed25519 identity, initialize keystore, generate X25519 onion key
2. **Authority Init** — Load or genesis `AuthorityState` from `data/authority.bin`
3. **Onboarding** — Verify local profile, send `OnboardRequest` to supernode (if not genesis)
4. **Ghost + Bridge** — Spawn `GhostRuntime` and `GhostBridge` (autonomous daemon)
5. **Dashboard** — Spawn HTTP server + `DashboardBridge` for live telemetry
6. **Network Run** — Start libp2p swarm + `ControlLoop`
7. **Ready** → Recovery / Shutdown on signal

---

## Prerequisites

- **Rust** ≥ 1.75 (with Cargo)
- **OpenSSL** / `libssl-dev` (Linux) or `openssl` (macOS)
- **curl** (for automatic public IP detection in `setup.sh`)
- **bash** ≥ 4.0

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev curl

# macOS
brew install openssl pkg-config
```

---

## Project Structure

```
ess-p2p-rs/
├── Cargo.toml                  # Main dependencies
├── export_pubkey.rs            # Utility to export public key from identity.bin
├── genesis.sh                  # Automated genesis supernode setup script
├── join.sh                     # Script to join an existing network
├── run.sh                      # Node start script (auto-loads .env)
├── setup.sh                    # Initial setup: .env, directories, policy file
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
│   ├── kad_store.rs            # Custom Kademlia store
│   ├── message.rs              # DirectRequest/Response message types
│   ├── codec.rs                # Custom libp2p codec
│   ├── system_event.rs         # SystemEvent, SystemEventKind enum
│   │
│   ├── security.rs             # SecurityError taxonomy, signing helpers
│   ├── security_runtime.rs     # SecurityRuntime (replay detection, signature verify)
│   │
│   ├── onion.rs                # Onion routing: X25519 ECDH + ChaCha20-Poly1305
│   ├── pqc.rs                  # Post-quantum: ML-KEM-1024 + X25519 hybrid
│   ├── sss.rs                  # Shamir Secret Sharing over GF(2⁸)
│   ├── id_rotation.rs          # Forward-secrecy key rotation (hash-chain, 24h)
│   │
│   ├── crdt_state.rs           # CRDT: LWW-Register, G-Set, G-Counter, OR-Set
│   ├── merkle_dag.rs           # Merkle-DAG audit trail for CRDT state
│   │
│   ├── ghost.rs                # GhostEngine (8-state machine)
│   ├── ghost_bridge.rs         # GhostBridge (channel Ghost ↔ Network)
│   ├── ghost_health.rs         # GhostHealthSnapshot, health assessment
│   ├── ghost_policy.rs         # GhostPolicy (reputation, throttle, self-heal)
│   ├── ghost_runtime.rs        # GhostRuntime (async task spawner)
│   ├── ghost_store.rs          # GhostSnapshot persistence
│   │
│   ├── gateway.rs              # Gateway access validation, rate limiting, audit log
│   ├── web.rs                  # WebRequest/Response via gateway
│   │
│   ├── governance/
│   │   ├── mod.rs              # Re-export governance module
│   │   ├── engine.rs           # GovernanceEngine, Proposal, quorum voting
│   │   ├── messages.rs         # ProposalType, VoteMessage, GovernanceMessage
│   │   ├── store.rs            # Proposal persistence to sled
│   │   └── tests.rs            # Governance unit tests
│   │
│   ├── dashboard/
│   │   ├── mod.rs
│   │   ├── api.rs              # JSON payload builder (world, summary, logs)
│   │   ├── http.rs             # HTTP handler (axum/hyper routes)
│   │   ├── model.rs            # DashboardSummary, NodeInfo, NodeHealth, etc.
│   │   ├── server.rs           # serve_dashboard_http (bind + listen)
│   │   ├── service.rs          # DashboardService (queries DashboardStore)
│   │   └── store.rs            # DashboardStore (in-memory state)
│   ├── dashboard_bridge.rs     # DashboardBridge (network updates → dashboard)
│   │
│   └── network/
│       ├── mod.rs
│       ├── util.rs
│       └── runtime/
│           ├── mod.rs
│           ├── runner.rs       # RuntimeContext, run_with_dashboard_and_authority
│           ├── swarm.rs        # libp2p Swarm builder
│           ├── events.rs       # SwarmEvent handler
│           ├── governance.rs   # Governance message handler in network layer
│           ├── support.rs      # Network runtime helpers
│           └── types.rs        # OnboardRequest, TelemetryEvent, shared types
│
└── tests/
    ├── onboarding_tests.rs
    ├── run_smoke.sh            # Smoke test: single node startup
    ├── run_three_node.sh       # Integration test: 3-node cluster
    └── assert_logs.sh
```

---

## Environment Configuration

The `.env` file is generated automatically by `setup.sh`. All supported variables:

```env
# ── REQUIRED ─────────────────────────────────────────────────────────────────
# Master network secret — MUST BE IDENTICAL across all nodes in a cluster.
# Used for: PBKDF2 keystore, HMAC serial verification, key derivation.
ESS_MASTER_SECRET="change-this-in-production"

# ESS_KEYSTORE_PASSWORD="keystore-password"  # Optional if different from MASTER_SECRET

# ── NODE IDENTITY ─────────────────────────────────────────────────────────────
ESS_NODE_NAME="ESS Node hostname"
ESS_NODE_EMAIL="node@hostname.local"
ESS_SERIAL_NUMBER="ESSBB-NODE-001-XXXX"   # Generated by setup.sh

# ── NODE ROLE ─────────────────────────────────────────────────────────────────
# Options: supernode | gateway | client | observer | validator | blocked
NODE_ROLE=supernode

# ── NETWORK ───────────────────────────────────────────────────────────────────
PUBLIC_IP=1.2.3.4        # Public IP of this node
P2P_PORT=5001            # TCP port for libp2p

# Bootstrap peer (leave empty for the first genesis supernode)
# Format: /ip4/<IP>/tcp/<PORT>/p2p/<PEER_ID>
BOOTSTRAP_P2P_MULTIADDRS=

# ── AUTHORITY ─────────────────────────────────────────────────────────────────
# PeerID of the authority supernode (filled in after genesis)
AUTHORITY_SUPERNODES=12D3KooW...

# ── DASHBOARD ─────────────────────────────────────────────────────────────────
ESS_DASHBOARD_BIND=127.0.0.1:8080
# ESS_DASHBOARD_TOKEN=secret-token    # Required if dashboard is exposed to the network

# ── GHOST ENGINE ──────────────────────────────────────────────────────────────
# GHOST_MIN_AWAKE_CYCLES=10

# ── ONION ROUTING ─────────────────────────────────────────────────────────────
# ONION_HOPS=3             # Minimum enforced: MIN_HOPS = 3 (cannot be set below 3)
# ONION_PAYLOAD_SIZE=1400  # Bytes after padding

# ── LOGGING ───────────────────────────────────────────────────────────────────
RUST_LOG=info
# RUST_LOG_FORMAT=json
```

---

## Quick Start

### 1. First Node — Genesis Supernode

The `genesis.sh` script automates the entire 2-step process:

```bash
git clone <repo-url> ess-p2p-rs
cd ess-p2p-rs

bash setup.sh
bash genesis.sh
```

`genesis.sh` performs the following:
1. Builds the binary (`cargo build --release`)
2. Runs the node temporarily (10–30 seconds), captures the PeerID from logs
3. Updates `AUTHORITY_SUPERNODES` in `.env` with the detected PeerID
4. Deletes `data/authority.bin` so the genesis authority is re-created fresh
5. Starts the node permanently as the genesis supernode

Save the multiaddr printed in the output — you will need it for subsequent nodes:

```
PeerID Supernode: 12D3KooW...
Multiaddr:        /ip4/1.2.3.4/tcp/5001/p2p/12D3KooW...
```

---

### 2. Subsequent Nodes — Join Cluster

```bash
bash setup.sh
bash join.sh /ip4/1.2.3.4/tcp/5001/p2p/12D3KooW...
```

---

### 3. Manual via run.sh

```bash
bash run.sh           # release mode (default)
bash run.sh --debug   # debug mode
```

---

## Node Roles

Configured via `NODE_ROLE` in `.env`. Each role has distinct access rights enforced by `AuthorityManager`:

| Role | Level | Access Rights | Decision Power |
|---|---|---|---|
| `blocked` | 0 | No connections allowed | None |
| `observer` | 1 | Connect only, cannot route | None |
| `client` | 2 | Connect + basic routing | None (Consumer) |
| `standard` | 3 | Connect + route + web traffic | None (Consumer) |
| `gateway` | 4 | All standard + gateway access/egress | None |
| `validator` | 5 | All gateway + admin update | Local Consensus |
| `supernode` | 6 | Full authority, can update cluster policy | **Network Governance (Vote)** |

The role is stored in `data/identity/role.txt` and bound to `EssIdentity` at startup. Role changes issued by an authority supernode are propagated via a cryptographically signed `ConfigBundle`.

---

## Ghost Engine — The Autonomous Brain of ESS

Ghost is not just a health checker. It is an **autonomous daemon** that runs the network's full intelligence layer: detecting anomalies, isolating misbehaving peers, maintaining minimum connectivity, and zeroizing sensitive data under critical conditions — all without human intervention.

```
Init → Wake → Beacon → Sync → Idle → Sleep
                                    ↓
                               Panic → Zeroized
```

| State | Description |
|---|---|
| `Init` | Initialization, config validation |
| `Wake` | Active, starting processing |
| `Beacon` | Broadcasting presence to the network |
| `Sync` | Synchronizing state with peers |
| `Idle` | No activity, waiting |
| `Sleep` | Resource-saving mode |
| `Panic` | Critical condition, self-isolation |
| `Zeroized` | Self-destruct: all sensitive data is securely zeroized from memory |

### Ghost Policy

| Parameter | Default | Description |
|---|---|---|
| `min_reputation_to_connect` | 0.2 | Minimum peer reputation to accept a connection |
| `quarantine_threshold` | < 0.2 | Peer isolation threshold |
| `panic_on_critical` | true | Auto-panic on critical condition |
| `drop_on_policy_denial` | true | Drop connection if denied by policy |

- **Anti-Tamper Logic:** Ghost can trigger a network-wide `Panic` state if it detects abnormal consensus partition or hardware compromise, instantly isolating the affected node — before any human operator needs to intervene.

---

## Security System

### Cryptography Stack

| Layer | Algorithm | Implementation |
|---|---|---|
| Identity | Ed25519 | `ed25519-dalek`, libp2p keypair |
| Transport | Noise Protocol + Yamux | libp2p built-in |
| Onion Routing | Ephemeral X25519 ECDH + ChaCha20-Poly1305 | `x25519-dalek`, `chacha20poly1305` |
| Post-Quantum | ML-KEM-1024 (Kyber / **FIPS 203**) + X25519 hybrid | `ml-kem` + HKDF-SHA3-256 |
| Keystore | AES-256-GCM + PBKDF2-SHA256 | `aes-gcm`, `pbkdf2` |
| Secret Sharing | Shamir GF(2⁸) threshold | Custom in `sss.rs` |
| Message Auth | HMAC-SHA256 | `hmac` + `sha2` |
| Key Derivation | HKDF-SHA256 | `hkdf` |

### Onion Routing (`onion.rs`)

Each message passes through a **minimum of 3 hops** (enforced via `MIN_HOPS = 3` — users cannot configure below this threshold, which would risk metadata leakage):

1. Sender generates an ephemeral X25519 keypair per hop
2. ECDH between the ephemeral private key + recipient hop's X25519 public key → shared secret
3. HKDF(shared_secret) → ChaCha20-Poly1305 key + nonce
4. Payload is wrapped from outermost to innermost (multi-layer encryption)
5. Each hop can only decrypt one layer and only knows the next hop

Every `HopInfo` must include an `activation_cert` — an Ed25519 signature from the authority binding the PeerID to its X25519 public key.

### Forward Secrecy via Key Rotation (`id_rotation.rs`)

Every 24 hours, the internal seed is rotated using a hash-chain scheme:

```
epoch_0: seed = HKDF(master_secret, epoch_number)
epoch_1: seed = SHA256(epoch_0_seed)
epoch_2: seed = SHA256(epoch_1_seed)
...
```

Past seeds cannot be computed from the current seed (backward secrecy). The PeerID does not change, so existing connections remain stable.

### Post-Quantum (`pqc.rs`)

Hybrid key exchange using **ML-KEM-1024 (standardized as FIPS 203)** + X25519 with HKDF. ESS follows the latest NIST post-quantum standard, making it future-proof against quantum computing attacks:

```
final_key = HKDF(mlkem_shared_secret || x25519_shared_secret)
```

Keys are zeroized after use (`ZeroizeOnDrop`).

---

## Governance — Collective Sovereignty

A decentralized voting system among supernodes for network policy changes. No single admin can decide unilaterally.

### Proposal Types

| Proposal | Description |
|---|---|
| `AddSupernode` | Add a new supernode to the authority |
| `RemoveSupernode` | Remove a supernode from the authority |
| `UpdatePolicy` | Update network policy (allowed_peers, actions, bootstrap_addrs) |
| `BanPeer` | Ban a peer from the network |
| `RotateKeys` | Trigger a network-wide key rotation |

### Voting Flow

1. A supernode creates a proposal → broadcasts to all supernodes
2. Each supernode sends a vote (`true`/`false`) with an HMAC signature
3. If `votes_for / total_supernodes >= quorum_ratio` → proposal is executed
4. **Bootstrap mode:** active when supernode count < 2; a single vote is sufficient
5. **Bootstrap deadline:** 1 hour — after this, bootstrap mode exits automatically

Proposals and votes are persisted to a `sled` database via `governance/store.rs`.

---

## CRDT & Merkle-DAG — Consistency Without a Central Coordinator

### CRDT State (`crdt_state.rs`)

5 CRDT primitives for strong eventual consistency:

| Type | Description | Use Case |
|---|---|---|
| `LwwRegister<T>` | Last-Write-Wins; highest timestamp wins | Config values, status |
| `GSet<T>` | Grow-only set; elements can only be added | Peer list, audit entries |
| `GCounter` | Grow-only counter per node | Message count, hop count |
| `LwwMap<K,V>` | LWW per key | Peer registry |
| `OrSet<T>` | Observed-Remove Set | Peer presence with remove support |

### Merkle-DAG Audit Trail (`merkle_dag.rs`)

Every significant CRDT state change produces a new node:

```
MerkleNode {
  index:       u64,         // Sequential index
  state_hash:  SHA256(...), // Hash of the state JSON
  parent_hash: Option<...>, // Hash of the previous node
  timestamp:   u64,         // Unix timestamp
  metadata:    String,      // Description of the change
}
```

The buffer is limited to 1024 nodes (circular). Used for verifying change history and detecting network partitions.

- **Why both CRDT and Merkle-DAG?** CRDT handles data convergence across nodes without coordination. The Merkle-DAG complements it by providing an **immutable forensic trail**, allowing operators to verify *who changed what and when* across the entire mesh — something CRDT alone cannot answer.
- **Auditability:** Every state transition is cryptographically chained, making retroactive tampering detectable.

---

## HTTP Dashboard

The HTTP server runs automatically on `ESS_DASHBOARD_BIND` (default: `127.0.0.1:8080`).

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Node status: world state, ghost, authority, peers |
| `/summary` | GET | Summary: total nodes, supernodes, relays, clients |
| `/nodes` | GET | List of all known nodes |
| `/routes` | GET | Active routing table |
| `/logs` | GET | Recent log events |
| `/health` | GET | Node health check (healthy / degraded / critical) |
| `/events` | GET | SSE live telemetry stream |

### Example Response `/`

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

If `ESS_DASHBOARD_TOKEN` is set, every request must include:

```
Authorization: Bearer <token>
```

### Production Deployment with TLS

1. Copy `nginx.conf` to the server and adjust the domain and SSL path.
2. Ensure the firewall only opens port `443` (HTTPS) and the P2P port.
3. Set `ESS_DASHBOARD_TOKEN` with a strong token.
4. Start the node with `bash run.sh`.

---

## Node Onboarding

New nodes must complete the onboarding process before fully participating in the network:

1. `LocalProfile` is created from `ESS_NODE_NAME`, `ESS_NODE_EMAIL`, and `ESS_SERIAL_NUMBER`
2. Serial number is verified using `HMAC-SHA256(ESS_MASTER_SECRET, base_serial)`
3. Node generates a static X25519 keypair (`data/identity/x25519_secret.bin`) for onion routing
4. An `OnboardRequest` is sent to the supernode via libp2p Request-Response:
   ```json
   {
     "peer_id": "...",
     "serial_number": "...",
     "hmac_signature": "...",
     "x25519_pubkey": "hex-encoded",
     "timestamp": 1234567890
   }
   ```
5. The supernode verifies the HMAC, assigns a role, and returns a signed `ConfigBundle`

Persistent onboarding file: `data/identity/profile.json`

---

## Testing

```bash
# Unit tests for all modules (including governance tests)
cargo test

# Smoke test: start a single node, verify startup succeeds
bash tests/run_smoke.sh

# Integration test: run a local 3-node cluster
bash tests/run_three_node.sh

# Assert log output (used by smoke & integration tests)
bash tests/assert_logs.sh <logfile> <expected_pattern>
```

---

## Utilities

### Export Public Key

Export the Ed25519 public key from the identity file (hex-encoded protobuf):

```bash
cargo run --bin export_pubkey
# Output: 08011220abcdef...
```

The identity file is located at `data/identity/ess_identity.bin` (created automatically on first run).

### Data Directory

```
data/
├── identity/
│   ├── ess_identity.bin        # Ed25519 keypair (protobuf encoded)
│   ├── x25519_secret.bin       # X25519 static secret for onion routing
│   ├── profile.json            # LocalProfile (onboarding data)
│   └── role.txt                # Current NodeRole
├── keystore.enc                # Encrypted keystore (AES-256-GCM)
├── authority.bin               # AuthorityState (serialized + HMAC protected)
├── bootstrap/                  # Bootstrap peer cache
├── kad_store/                  # Kademlia DHT persistent store
├── world_state/                # WorldState snapshots
└── policy_inner.toml           # Policy configuration (JSON format)
```

---

## Production Notes

> ⚠️ **IMPORTANT** — Read this entire section before deploying to a production environment.

### Security

- **Change `ESS_MASTER_SECRET`** — Do not use the dev default. The secret must be identical across all nodes in a cluster and stored securely (HashiCorp Vault, AWS Secrets Manager, or equivalent).
- **Set `ESS_DASHBOARD_TOKEN`** — Required if the dashboard is exposed to the network.
- **Bind Dashboard Locally** — The default `127.0.0.1:8080` is safe. Do not expose to `0.0.0.0` without a reverse proxy + TLS in front.
- **File Permissions** — `data/identity/` and `data/keystore.enc` must have permission `600` (owner read-only). `setup.sh` handles this automatically on Unix systems.
- **`authority.bin` and HMAC** — The authority file is HMAC-protected. Do not edit it manually.

### Networking

- **Firewall:** Open `P2P_PORT` (default `5001/TCP`) for inter-node traffic.
- **`PUBLIC_IP`:** Must be set to the public IP reachable by other nodes. Automatic detection via `ipify.org` is performed by `setup.sh`.
- **NAT Traversal:** There is currently no built-in hole punching. Use a direct public IP or a VPN overlay.

### Performance & Stability

- Use `cargo run --release` or the compiled binary at `target/release/ess-p2p-rs` for production.
- Set `RUST_LOG=warn` in production to reduce logging overhead.
- The Ghost Engine automatically manages peer connections and throttling. No manual tuning is required unless you have specific performance requirements.

### Backup

- `data/identity/ess_identity.bin` — The node's PeerID is derived from this file. Back it up securely. If lost, the node will have a new PeerID and must re-onboard.
- `data/authority.bin` — Network authority state. Back up regularly.

---

## Key Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `tokio` | 1.x | Async runtime |
| `libp2p` | 0.56 | P2P networking stack |
| `serde` / `serde_json` | 1.x | Serialization |
| `ed25519-dalek` | 1.x | Ed25519 signatures |
| `x25519-dalek` | 2.x | X25519 ECDH (onion routing) |
| `chacha20poly1305` | 0.10 | AEAD encryption (onion) |
| `aes-gcm` | 0.10 | AEAD encryption (keystore) |
| `ml-kem` | 0.3 | ML-KEM-1024 / FIPS 203 post-quantum |
| `hkdf` | 0.12 | Key derivation |
| `hmac` | 0.12 | Message authentication |
| `pbkdf2` | 0.12 | Password-based key derivation |
| `sled` | 0.34 | Embedded database (Kademlia store, governance) |
| `dashmap` | 5.x | Concurrent hash map |
| `sha2` / `sha3` | 0.10 | Hash functions |
| `zeroize` | 1.7 | Secure memory zeroization |
| `tracing` / `tracing-subscriber` | 0.1/0.3 | Structured logging |
| `chrono` | 0.4 | Timestamp handling |
| `uuid` | 1.x | UUID generation (CRDT node IDs) |

---

*ESS — Sovereign Network Operating System · Software Layer v1.0*
*Optimized for Sabelle Black Box · Compatible with VPS, Bare-metal, and Cloud*

