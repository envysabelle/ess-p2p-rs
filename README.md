# ESS Black Box — The Syndicate P2P Protocol

> Autonomous, privacy-preserving, encrypted P2P supernode network built with Rust and libp2p.  
> **Advanced cryptographic & autonomous features fully implemented (Phases 1–8)**  
> *Onion routing, Post‑Quantum hybrid KEM, Shamir's Secret Sharing, CRDT state, Governance engine, Ghost engine, ID rotation, PUF simulation, and more.*

![Infrastructure - Mission Critical](https://img.shields.io/badge/Infrastructure-Mission--Critical-red.svg)
![Architecture - Zero Trust](https://img.shields.io/badge/Architecture-Zero--Trust-blue.svg)
![Runtime - Rust/Hardened](https://img.shields.io/badge/Runtime-Rust--Hardened-orange.svg)
![Network - Active Global Mesh](https://img.shields.io/badge/Network-Active_Global_Mesh-green.svg)
![Crypto - Post‑Quantum](https://img.shields.io/badge/Crypto-Post--Quantum-blueviolet.svg)
![State - CRDT Convergent](https://img.shields.io/badge/State-CRDT_Convergent-brightgreen.svg)

---

## About the Project

ESS Black Box is an autonomous peer‑to‑peer network designed for encrypted communication, decentralized node discovery, and authority‑based security policies. Each node acts as a **supernode** that onboards others using cryptographic identities.

The system has gone through **eight hardening phases** toward production, covering:
- Base security (nonce, timestamp, rate limiting, replay protection)
- Persistence, auto‑onboarding, Kademlia DHT
- Structured JSON logging, error handling
- Unit & integration tests, orchestration scripts
- Systemd service, health‑check endpoints, dashboard
- Onion routing with X25519 DH + ChaCha20‑Poly1305 (configurable, default off)
- Post‑Quantum Hybrid KEM (ML‑KEM‑1024 + X25519)
- Shamir's Secret Sharing for identity key splitting
- CRDT distributed state with vector clocks and Merkle‑DAG
- Governance engine with quorum voting
- Software PUF simulation (hardware PUF ready for production upgrade)
- Deterministic internal key rotation (hash chain, PeerID stable)

---

## Key Features

- **Multi‑Supernode Mesh** — pure supernode mesh, no separate relay/client tiers; all nodes equal
- **Secure Onboarding** — serial‑number verification, ed25519 signatures, nonce + timestamp, rate limiting
- **Policy Engine** — file‑based authority with role‑based access control (RBAC) and allowed actions
- **Ghost Engine** — autonomous decision engine for peer reputation, quarantine, drop, and sleep/wake cycles
- **Onion Routing** — multi‑hop encrypted routing with X25519 ephemeral DH + ChaCha20‑Poly1305 (integrated, optional; enabled via NetworkConfig)
- **Post‑Quantum Hybrid KEM** — ML‑KEM‑1024 + X25519 key exchange with concatenation + HKDF derivation
- **Shamir's Secret Sharing (SSS)** — threshold (k, n) splitting of identity keys over GF(2⁸)
- **Governance Engine** — proposal lifecycle, supernode voting, quorum‑based peer activation
- **CRDT State** — LWW‑Register, G‑Set, G‑Counter, OR‑Set, LWW‑Map for Strong Eventual Consistency across the mesh
- **Internal Key Rotation** — deterministic 24‑hour peer identity rotation derived from seed + epoch (PeerID remains stable)
- **PUF Simulation** — software‑based Physical Unclonable Function for machine binding (hardware‑ready)
- **Dashboard & Health Check** — REST API at `/api/ess/*` and HTML dashboard on port `8080`
- **Structured Logging** — JSON output via `tracing`, ready for observability stacks
- **Systemd Service Support** — ready to run as a Linux service with auto‑restart
- **Prometheus Metrics** — onboarding counters available as optional metrics

---

## Security & Audit Status

**Current Status:** Pre‑Audit / Hardening Phase.

The cryptographic stack (ML‑KEM‑1024, X25519, GF(2⁸) SSS, ChaCha20‑Poly1305) is functionally integrated. Key derivation uses HKDF (RFC 5869) with domain separation. All key material is managed with `ZeroizeOnDrop`. The implementation is under active hardening; a formal third‑party cryptographic audit is scheduled post‑Seed funding. Do not use in mission‑critical production environments until the formal audit is published.

---

## Architecture

```text
┌─────────────┐     onboarding      ┌─────────────┐
│  Supernode  │◄──────────────────►│  Supernode  │
│  London     │                     │  Singapore  │
└─────────────┘                     └─────────────┘
      ▲                                    ▲
      │ onboarding                         │
      │                                    │
┌─────────────┐                     ┌─────────────┐
│  Supernode  │                     │  ... others  │
│ California  │                     │             │
└─────────────┘                     └─────────────┘
```

All nodes are equal supernodes. Governance, state sync, and onion routing run directly between them.

---

## Project Structure

```text
src/
├── main.rs                 # Entrypoint & lifecycle
├── onboarding.rs           # Identity, SN verification, auto‑onboard, X25519 key gen
├── security_runtime.rs     # Identity verification, nonce cache, rate limiter
├── network_controller.rs   # Central network & onboarding controller
├── world_state.rs          # Global state, peer activation, persistence
├── network/
│   ├── runtime/
│   │   ├── types.rs        # OnboardRequest/Response, Behaviour, Event
│   │   ├── events.rs       # Main event loop (all protocols + onion relay)
│   │   ├── governance.rs   # Peer registration & onboarding verification
│   │   ├── runner.rs       # Swarm creation & runtime context
│   │   ├── support.rs      # Dashboard builders, onion helper functions
│   │   └── swarm.rs        # Swarm builder with all behaviours
│   └── util.rs             # Peer address registration, public address checks
├── authority.rs            # Authority & access manager (RBAC)
├── ghost.rs                # Ghost Engine core loop, states, commands
├── ghost_bridge.rs         # Bridge between Ghost and network events
├── ghost_health.rs         # Ghost health scoring & assessment
├── ghost_policy.rs         # Autonomous decision policy
├── ghost_runtime.rs        # Runtime handle & scheduler for Ghost actions
├── ghost_store.rs          # Persistence for Ghost state snapshots
├── dashboard/
│   ├── api.rs              # JSON payload builders
│   ├── http.rs             # HTTP request routing
│   ├── model.rs            # Dashboard data models
│   ├── server.rs           # Embedded HTTP server (Tokio)
│   ├── service.rs          # Dashboard service logic
│   └── store.rs            # In‑memory store for dashboard data
├── gateway.rs              # Gateway rate limiter, audit, request/response structs
├── message.rs              # Direct message structs (request/response)
├── onion.rs                # Onion routing crypto (X25519, ChaCha20, layers)
├── pqc.rs                  # Post‑Quantum Hybrid KEM (ML‑KEM‑1024 + X25519)
├── sss.rs                  # Shamir's Secret Sharing over GF(2⁸)
├── crdt_state.rs           # CRDT LWW‑Register, G‑Set, LWW‑Map, vector clock
├── governance/
│   ├── engine.rs           # Governance engine (proposals, voting, quorum)
│   ├── messages.rs         # Governance message types
│   ├── mod.rs
│   └── store.rs            # Governance state persistence
├── id_rotation.rs          # Deterministic internal key rotation (hash chain)
├── puf.rs                  # Software PUF simulation (hardware fingerprint)
├── config.rs               # Config bundle, network config, request/response structs
├── identity.rs             # ESS identity (keypair + authority binding)
├── bootstrap_cache.rs      # Bootstrap peer cache persistence
├── kad_store.rs            # Kademlia record persistence (sled)
├── storage.rs              # World state atomic JSON storage
├── system_event.rs         # Internal event bus
├── web.rs                  # Web service registry, ESS URI parser
├── control_loop.rs         # System control loop (health checks, sync, rotation)
├── dashboard_bridge.rs     # Bridge for dashboard telemetry
├── security.rs             # Security helpers & signing material
└── tests/                  # Unit & integration tests, scripts
```

---

## Configuration

All configuration is done via environment variables.

| Variable | Description | Default / Example |
|---|---|---|
| `ESS_MASTER_SECRET` | Secret for serial‑number HMAC checksum | `Sabelle_Syndicate_...` |
| `NODE_ROLE` | `supernode`, `gateway`, or `client` | `supernode` |
| `PUBLIC_IP` | Node public IP (for external multiaddr) | `198.51.100.146` |
| `P2P_PORT` | P2P listening port | `5001` |
| `BOOTSTRAP_P2P_MULTIADDRS` | Bootstrap addresses (empty for first node) | `/ip4/.../tcp/5001/p2p/12D...` |
| `RUST_LOG` | Log level (`info`, `debug`, etc.) | `info` |
| `AUTHORITY_FILE` | Path to authority state file | `data/authority.bin` |
| `AUTHORITY_SUPERNODES` | Comma‑separated supernode peer IDs (genesis only) | — |
| `AUTHORITY_PUBLIC_KEY_B64` | Base64 ed25519 public key for authority | — |
| `KAD_STORE_PATH` | Persistent Kademlia store path | `data/kad_store` |
| `ESS_AUTHORITY_ROLE` | Authority role for identity binding | — |
| `ESS_CLEAR_AUTHORITY_BINDING` | Clear authority binding on boot (`1`/`true`) | — |

Onion routing is enabled via `NetworkConfig` (see `src/config.rs`). By default, `onion_hops = 0` (direct). To enable, set `onion_hops > 0` and `onion_payload_size` (e.g., `1400`) in the source or provide a custom `NetworkConfig` at startup.

---

## How to Run

### Prerequisites

- Rust toolchain (edition 2021)
- `cargo` installed
- Environment variables set, or a `.env` file

### 1. Clone and build

```bash
git clone https://github.com/envysabelle/ess-p2p-rs.git
cd ess-p2p-rs
cargo build --release
```

### 2. Run the first supernode (London)

The first node does not need a bootstrap address.

```bash
export ESS_MASTER_SECRET="Sabelle_Syndicate_Syndicate_2026_Top_Secret"
export NODE_ROLE=supernode
export PUBLIC_IP=198.51.100.146
export P2P_PORT=5001
cargo run --release
```

### 3. Run the second supernode (Singapore)

Point its bootstrap to the first node's multiaddress.

```bash
export ESS_MASTER_SECRET="..."       # same secret
export NODE_ROLE=supernode
export PUBLIC_IP=203.0.113.49
export P2P_PORT=5001
export BOOTSTRAP_P2P_MULTIADDRS="/ip4/198.51.100.146/tcp/5001/p2p/12D3Koo..."
cargo run --release
```

After boot, the node automatically sends an onboarding request to the first supernode, and the governance engine will propose & vote to activate the new peer.

---

## Testing

### Unit and Integration Tests

```bash
cargo test --test onboarding_tests
cargo test --test onboarding_integration -- --nocapture
cargo test --lib                       # run all unit tests
```

### Three‑Supernode Orchestration

Run on three different machines (e.g., London, Singapore, California) to test onboarding, consensus, and routing.

```bash
./tests/run_three_node.sh
```

---

## Observability

### Dashboard HTTP API

The dashboard runs on port `8080` by default. Key endpoints:

| Endpoint | Description |
|---|---|
| `GET /api/ess/dashboard` | Full health summary |
| `GET /api/ess/nodes` | List of known nodes |
| `GET /api/ess/nodes/{peer_id}` | Detailed node health |
| `GET /api/ess/routes` | Active routes |
| `GET /api/ess/logs?limit=100&level=warn` | Filtered logs |
| `GET /api/ess/authority` | Authority state snapshot |
| `GET /api/policy` | Current security policy |
| `POST /api/policy/reload` | Reload policy from file |
| `POST /api/ess/send` | Send direct message to a peer (`{"peer_id":"...", "message":"..."}`) |

The root path (`/`) serves an HTML dashboard. Access is protected with a mandatory Bearer token (constant‑time comparison).

### Structured Logging

All logs are emitted in JSON via `tracing` and can be piped to any log aggregator.

### Health Check

`GET /health` returns a quick JSON status. The dashboard also provides comprehensive health data.

---

## Production‑Readiness Phases

| Phase | Description | Status |
|---|---|---|
| 0 | Backup and branching | ✅ |
| 1 | MASTER_SECRET_KEY from env, nonce + timestamp, rate limit, replay protection | ✅ |
| 2 | Persist activated_peers, auto‑send onboarding, Kademlia integration | ✅ |
| 3 | Replace `expect` with error handling, structured JSON logging | ✅ |
| 4 | Unit and integration tests, 3‑node script | ✅ |
| 5 | Systemd service, health check, Prometheus metrics | ✅ |
| 6 | Onion routing (X25519 + ChaCha20‑Poly1305, integrated with fallback) | ✅ *(default off)* |
| 7 | Post‑Quantum Hybrid KEM (ML‑KEM‑1024 + X25519) | ✅ |
| 8 | Shamir's Secret Sharing, CRDT state, Governance engine, PUF simulation, ID rotation | ✅ |

Advanced features (onion routing, PQC, CRDT, governance) are implemented and working; onion routing is opt‑in, and the PUF is a software simulation. Hardware PUF and SMM‑based Ghost are on the roadmap for production hardware.

---

## Systemd Service

Example unit file at `/etc/systemd/system/ess-p2p.service`:

```ini
[Unit]
Description=ESS P2P Supernode
After=network.target

[Service]
User=ess
Group=ess
WorkingDirectory=/opt/ess-p2p
Environment="ESS_MASTER_SECRET=..."
Environment="NODE_ROLE=supernode"
Environment="PUBLIC_IP=198.51.100.146"
Environment="P2P_PORT=5001"
Environment="BOOTSTRAP_P2P_MULTIADDRS=..."
ExecStart=/opt/ess-p2p/target/release/ess-p2p-rs
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Enable it with:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ess-p2p
```

---

## Implementation Status (Detailed)

| Component | Whitepaper v4.0 | Actual Code (May 2026) | Status |
|---|---|---|---|
| Hybrid PQC (ML‑KEM + X25519) | ✅ Full match | ✅ Full match | MATCH |
| SSS over GF(2⁸) | ✅ Full match | ✅ Full match | MATCH |
| Kademlia DHT | ✅ Full match | ✅ Full match | MATCH |
| ID Rotation (internal keys) | ✅ Full match | ✅ Full match | MATCH |
| Ghost Engine (software) | ✅ Full match | ✅ Full match | MATCH |
| Governance Engine | ✅ Full match | ✅ Full match | MATCH |
| Onion Routing | ✅ Integrated | ✅ Integrated, configurable | MATCH |
| CRDT (5 types + Merkle‑DAG) | ✅ Full match | ✅ Full match | MATCH |
| Binary Serialization (Bincode) | ✅ Full match | ✅ Full match | MATCH |
| PUF (software sim) | ✅ SW Simulation | ✅ SW Simulation | MATCH |
| Hardware (SBB, Ring‑1 Ghost) | ❌ Roadmap | ❌ Roadmap | MATCH |

The onion routing is fully wired into the event loop and `NetworkController`. It activates when `onion_hops > 0` in the `NetworkConfig`. Padding size is configurable and defaults to 1400 bytes.

---

## Syndicate Participation & Integration

ESS Black Box is an autonomous infrastructure. Direct code contributions are currently restricted to core engineers and verified Genesis Seat holders.

If you are a hardware vendor (for SRAM PUF integration) or represent an institutional entity seeking an architectural review, please contact the concierge at:

- **Email:** concierge@envysabelle.com  
- **Web:** https://envysabelle.com

---

## License & Legal

Copyright © 2026 PT Envy Sabelle Sinergi. All Rights Reserved.

This source code is provided for architectural review, technical due diligence, and white‑hat security assessment only. Commercial deployment, fork modification, or operating an ESS Supernode outside of the authorized Sabelle Sovereign Syndicate requires a formal Genesis License.

---

*ESS Black Box — The Syndicate*  
*Private. Autonomous. Resilient.*

