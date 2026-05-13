// src/main.rs (updated with security patches – H-07 applied, compute layer integrated)
mod authority;
mod bootstrap_cache;
mod config;
mod codec;
mod control_loop;
mod dashboard;
mod dashboard_bridge;
mod gateway;
mod ghost;
mod ghost_bridge;
mod ghost_health;
mod ghost_policy;
mod ghost_runtime;
mod ghost_store;
mod governance;
mod identity;
mod kad_store;
mod message;
mod network;
mod network_controller;
mod onboarding;
mod onion;
mod security;
mod security_runtime;
mod storage;
mod system_event;
mod web;
mod world_state;

mod sss;
mod pqc;
mod crdt_state;
mod keystore;
mod merkle_dag;
mod id_rotation;

// ── Compute Layer (NEW) ──────────────────────────────────────────────────────
mod compute;

// ── Storage Layer (Sharded DHT) ──────────────────────────────────────────────
mod storage_layer;

use std::{
    env, error::Error, fs,
    io,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};
use log::{error, info, warn};
use tokio::sync::{broadcast, mpsc, RwLock as TokioRwLock};
use tokio::time::{sleep, timeout, Duration};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::network::run;
use crate::system_event::SystemEvent;
use authority::{AuthorityManager, AuthorityState, NodeRole};
use control_loop::ControlLoop;
use dashboard::{
    serve_dashboard_http, DashboardService, DashboardStore,
    prime_dashboard_models, NodeInfo, NodeHealth, RouteInfo, LogEvent,
};
use dashboard_bridge::{
    spawn_dashboard_bridge, DashboardBridgeConfig, DashboardBridgeHandle,
    DashboardBridgeInput, send_node_info, send_telemetry, send_node_health,
    send_route, send_log, TelemetryUpdate,
};
use ghost::{GhostConfig, GhostEngine};
use ghost_bridge::{spawn_ghost_bridge, GhostBridgeConfig, GhostBridgeHandle, GhostBridgeOutputs};
use ghost_runtime::{spawn_ghost_runtime, GhostRuntimeConfig, GhostRuntimeHandle};
use network_controller::NetworkController;
use security_runtime::SecurityRuntime;
use storage::WorldStateStore;
use world_state::WorldState;

use crate::config::{ConfigResponse, NetworkConfig};
use crate::onboarding::{OnboardingManager, LocalProfile};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;

// ── Compute Layer use (NEW) ──────────────────────────────────────────────────
use compute::{
    store::ComputeStore,
    scheduler::{spawn_scheduler, SchedulerConfig, ComputeSchedulerHandle},
    executor::WasmEngine,
};

// ── Storage Layer use ────────────────────────────────────────────────────────
use storage_layer::{StorageLayer, StorageLayerConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecyclePhase {
    Boot,
    Ready,
    Recovery,
    Shutdown,
}

struct Lifecycle {
    phase: Arc<RwLock<LifecyclePhase>>,
    keypair: Keypair,
    profile: LocalProfile,
    bridge_handle: Option<DashboardBridgeHandle>,
    shutdown_tx: broadcast::Sender<()>,
}

impl Lifecycle {
    fn new(
        keypair: Keypair,
        profile: LocalProfile,
        bridge_handle: Option<DashboardBridgeHandle>,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            phase: Arc::new(RwLock::new(LifecyclePhase::Boot)),
            keypair,
            profile,
            bridge_handle,
            shutdown_tx,
        }
    }

    fn set_phase(&self, phase: LifecyclePhase) {
        if let Ok(mut guard) = self.phase.write() {
            *guard = phase;
            tracing::info!("[LIFECYCLE] System transitioned to {:?}", phase);
        }
    }

    async fn execute(mut self) -> Result<(), Box<dyn Error>> {
        tracing::info!("[DEBUG] Lifecycle execute started.");

        let phase_signal = self.phase.clone();
        let bridge_handle_opt = self.bridge_handle.take();

        if let Some(bridge_handle) = bridge_handle_opt {
            let phase_signal = phase_signal.clone();
            let bridge_handle_clone = bridge_handle.clone();
            let shutdown_tx = self.shutdown_tx.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                warn!("[SHUTDOWN] Interrupt received. Flushing autonomous state...");
                if !bridge_handle_clone.is_closed() {
                    bridge_handle_clone.abort();
                    tracing::info!("[SHUTDOWN] Dashboard bridge aborted.");
                }
                if let Ok(mut guard) = phase_signal.write() {
                    *guard = LifecyclePhase::Shutdown;
                }
                let _ = shutdown_tx.send(());
            });
        }

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            let current = { *self.phase.read().unwrap() };
            if current == LifecyclePhase::Shutdown {
                break;
            }

            self.set_phase(LifecyclePhase::Boot);
            prime_dashboard_models();

            tracing::info!("[DEBUG] Starting bootstrap_runtime...");
            let (ctx, shutdown_controller) = match bootstrap_runtime(
                self.keypair.clone(),
                self.profile.clone(),
            )
            .await
            {
                Ok(ctx) => {
                    tracing::info!("[DEBUG] bootstrap_runtime succeeded, entering Ready phase.");
                    self.set_phase(LifecyclePhase::Ready);
                    ctx
                }
                Err(e) => {
                    error!("[BOOT] Initialization Failed: {}", e);
                    self.set_phase(LifecyclePhase::Recovery);
                    continue;
                }
            };

            // Compute handle sudah disiapkan di bootstrap_runtime, tinggal ambil.
            let compute_handle = ctx.compute_handle.clone();

            let autonomous_loop = ControlLoop::new(
                ctx.controller.clone(),
                ctx.world_state.clone(),
                ctx.ghost_runtime_handle.clone(),
                ctx.ghost_bridge.clone(),
                ctx.world_store.clone(),
                ctx.event_rx,
                ctx.dashboard_tx.clone(),
                compute_handle,
            );

            let control_handle = tokio::spawn(async move { autonomous_loop.run().await; });
            info!("[RUNTIME] ESS Backbone Protocol is ALIVE and Autonomous.");

            let network_config = NetworkConfig::default();

            tracing::info!("[DEBUG] About to call run (runner) .await");
            let runner_fut = run(
                ctx.ess,
                ctx.ghost_runtime_handle,
                ctx.dashboard_tx,
                ctx.authority,
                ctx.world_state,
                ctx.security,
                Some(ctx.crdt_world),
                network_config,
            );

            tokio::select! {
                res = runner_fut => {
                    if let Err(e) = res {
                        error!("[RUNTIME] Fatal Crash: {}", e);
                        self.set_phase(LifecyclePhase::Recovery);
                    }
                    tracing::info!("[DEBUG] run (runner) completed.");
                }
                _ = shutdown_rx.recv() => {
                    warn!("[SHUTDOWN] Signal received, terminating runner...");
                    control_handle.abort();
                    shutdown_controller.shutdown_save().await;
                    self.set_phase(LifecyclePhase::Shutdown);
                    continue;
                }
            }

            let current_phase = { *self.phase.read().unwrap() };
            if current_phase == LifecyclePhase::Recovery {
                warn!("[RECOVERY] System resting for 15s before reboot...");
                sleep(Duration::from_secs(15)).await;
            }
        }
        Ok(())
    }
}

struct BootContext {
    ess: identity::EssIdentity,
    authority: AuthorityManager,
    world_state: Arc<RwLock<WorldState>>,
    security: Arc<SecurityRuntime>,
    dashboard_tx: mpsc::Sender<DashboardBridgeInput>,
    ghost_runtime_handle: GhostRuntimeHandle,
    ghost_bridge: GhostBridgeHandle,
    world_store: Arc<WorldStateStore>,
    controller: Arc<NetworkController>,
    event_rx: mpsc::Receiver<SystemEvent>,
    crdt_world: Arc<TokioRwLock<crdt_state::CrdtWorldState>>,
    compute_handle: Option<ComputeSchedulerHandle>,   // NEW
}

struct ShutdownController {
    controller: Arc<NetworkController>,
    world_store: Arc<WorldStateStore>,
    hmac_key: Vec<u8>,
}

impl ShutdownController {
    async fn shutdown_save(&self) {
        info!("[SHUTDOWN] Saving world state…");
        if let Some(state) = self.controller.world_state() {
            let world_guard = state.read().unwrap();
            if let Err(e) = self.world_store.persist(&world_guard, None) {
                error!("[SHUTDOWN] Failed to persist world state: {}", e);
            }
        }
        crate::governance::store::save_governance(
            &self.controller.governance_engine.read().unwrap(),
            &self.hmac_key,
        );
        info!("[SHUTDOWN] Governance state saved.");
        info!("[SHUTDOWN] State flushed.");
    }
}

pub async fn sync_policy_with_supernode(
    controller: &NetworkController,
    security: &Arc<SecurityRuntime>,
    authority: &AuthorityManager,
    cached_addrs: &[libp2p::Multiaddr],
) {
    if cached_addrs.is_empty() {
        warn!("[BOOT] No cached bootstrap addrs, policy sync skipped.");
        return;
    }

    let local_peer_id = controller.local_peer_id;
    for addr in cached_addrs {
        let remote_peer_id = match addr.iter().find_map(|p| {
            if let Protocol::P2p(peer_id) = p { Some(peer_id) } else { None }
        }) {
            Some(pid) => pid,
            None => continue,
        };

        info!("[BOOT] Attempting policy sync from {}", remote_peer_id);
        let request = match security.build_config_request(local_peer_id, remote_peer_id, "client") {
            Ok(r) => r,
            Err(e) => {
                warn!("[BOOT] Failed to build config request for {}: {}", remote_peer_id, e);
                continue;
            }
        };

        let body = match bincode::serialize(&request) {
            Ok(b) => b,
            Err(e) => {
                warn!("[BOOT] Serialize config request failed for {}: {}", remote_peer_id, e);
                continue;
            }
        };

        let send_future = controller.send_direct_message(remote_peer_id, body);
        let response_data = match timeout(Duration::from_secs(8), send_future).await {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => {
                warn!("[BOOT] Direct message to {} failed: {}", remote_peer_id, e);
                continue;
            }
            Err(_) => {
                warn!("[BOOT] Policy sync timed out for {}", remote_peer_id);
                continue;
            }
        };

        let resp = match bincode::deserialize::<ConfigResponse>(&response_data) {
            Ok(r) => r,
            Err(e) => {
                warn!("[BOOT] Failed to parse ConfigResponse from {}: {}", remote_peer_id, e);
                continue;
            }
        };

        match security.verify_config_response(local_peer_id, remote_peer_id, &resp) {
            Ok(bundle) => {
                info!("[BOOT] Config verified from {}, applying...", remote_peer_id);
                if let Err(e) = security.apply_bundle(&bundle) {
                    warn!("[BOOT] Failed to apply bundle to security: {}", e);
                    continue;
                }
                if let Err(e) = authority.apply_config_bundle(&bundle) {
                    warn!("[BOOT] Failed to sync authority with config bundle: {}", e);
                } else {
                    info!("[BOOT] Authority policy synchronized with supernode.");
                }
                info!("[BOOT] Policy sync completed successfully from {}", remote_peer_id);
                return;
            }
            Err(e) => {
                warn!("[BOOT] Config response verification failed for {}: {}", remote_peer_id, e);
            }
        }
    }
    warn!("[BOOT] Policy sync unsuccessful with any known supernode.");
}

async fn bootstrap_runtime(
    keypair: Keypair,
    profile: LocalProfile,
) -> Result<(BootContext, ShutdownController), Box<dyn Error>> {
    let ess = identity::EssIdentity::from_keypair(keypair.clone());
    let peer_id = ess.peer_id();

    let keystore = keystore::SoftwareKeystore::load_or_create()?;
    let master_seed = keystore.master_key();

    {
        let shard_dir = "data/identity";
        if let Some(parent) = Path::new(shard_dir).parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::create_dir_all(shard_dir).ok();

        match sss::split_key_to_files(&master_seed, 2, 3, shard_dir) {
            Ok(paths) => {
                tracing::info!(
                    "[SSS] Identity seed split into {} shards at: {:?}",
                    paths.len(),
                    paths
                );
            }
            Err(e) => tracing::warn!("[SSS] Failed to create identity shards: {}", e),
        }
    }

    let crdt_state_path = "data/crdt_state.json";
    let mut crdt_world = if Path::new(crdt_state_path).exists() {
        match fs::read(crdt_state_path) {
            Ok(bytes) => crdt_state::CrdtWorldState::from_sync_payload(&bytes)
                .unwrap_or_else(|_| crdt_state::CrdtWorldState::new(peer_id.to_string())),
            Err(_) => crdt_state::CrdtWorldState::new(peer_id.to_string()),
        }
    } else {
        crdt_state::CrdtWorldState::new(peer_id.to_string())
    };
    crdt_world.tick();
    tracing::info!("[CRDT] World state loaded. Vector clock: {:?}", crdt_world.vector_clock);
    let crdt_world_arc = Arc::new(TokioRwLock::new(crdt_world));

    let security = SecurityRuntime::new(ess.keypair().clone())?;
    let policy_cfg_path = env::var("POLICY_INNER_CONFIG")
        .unwrap_or_else(|_| "data/policy_inner.toml".into());
    security.load_policy_from_file(&policy_cfg_path)?;

    let auth_path = PathBuf::from(
        env::var("AUTHORITY_FILE").unwrap_or_else(|_| "data/authority.bin".into()),
    );
    let (mut authority_state, _) = bootstrap_authority(&auth_path)?;

    if !auth_path.exists() {
        if let Ok(env_supernodes) = env::var("AUTHORITY_SUPERNODES") {
            tracing::info!(
                "[AUTH] Genesis bootstrap: loading initial supernodes from AUTHORITY_SUPERNODES env var."
            );
            let incoming: Vec<String> = env_supernodes
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            for sn in incoming {
                if !authority_state.supernodes.contains(&sn) {
                    authority_state.supernodes.push(sn);
                }
            }
            authority_state.canonicalize();
            if let Err(e) = authority_state.save_to_file(auth_path.to_str().unwrap_or("data/authority.bin")) {
                tracing::warn!("Failed to save genesis authority: {}", e);
            }
            tracing::info!(
                "[AUTH] Genesis authority created with supernodes: {:?}",
                authority_state.supernodes
            );
        }
    } else if env::var("AUTHORITY_SUPERNODES").is_ok() {
        tracing::warn!(
            "[AUTH] AUTHORITY_SUPERNODES env var is set but authority.bin already exists — \
             env var IGNORED to prevent privilege escalation. Use signed bundle sync instead."
        );
    }

    let authority = AuthorityManager::new(authority_state);
    security.attach_authority(authority.clone());

    match security.verify_bundle_config() {
        Ok(()) => tracing::info!("[SECURITY] Bundle config verified against trusted hash."),
        Err(e) => tracing::warn!("[SECURITY] Bundle config verification skipped: {} — continuing boot.", e),
    }

    let world_store = Arc::new(WorldStateStore::new("data/world_state".to_string()));
    let recovery = world_store.recover_bundle(authority.get())?;
    let world_state = Arc::new(RwLock::new(recovery.world));

    {
        let mut ws = world_state.write().unwrap();
        ws.set_local_profile(profile);
        ws.mark_peer_activated(&peer_id.to_string());
    }
    tracing::info!("[BOOT] Onboarding profile stored and self marked as activated.");

    tracing::info!("[BOOT] Integrating peer discovery from persistent cache...");
    let cached_addrs = crate::bootstrap_cache::load_bootstrap_addrs();
    tracing::info!("[BOOT] Found {} peers in local cache.", cached_addrs.len());

    let (event_tx, event_rx) = mpsc::channel::<SystemEvent>(2048);

    let controller = NetworkController::new(
        peer_id,
        world_state.clone(),
        Some(event_tx.clone()),
    );
    let controller_arc = Arc::new(controller);
    let security_arc = Arc::new(security);

    let gov_hmac_key = keystore.derive_key("ess-governance-hmac-v1").to_vec();
    {
        let mut gov = controller_arc.governance_engine.write().unwrap();
        gov.set_hmac_key(gov_hmac_key.clone());
    }

    if let Some(loaded_gov) = crate::governance::store::load_governance(&gov_hmac_key) {
        *controller_arc.governance_engine.write().unwrap_or_else(|e| e.into_inner()) = loaded_gov;
        tracing::info!("[GOVERNANCE] Restored previous governance state from data/governance.json");
    }

    controller_arc.attach_security(security_arc.clone());

    let onion_key = keystore.derive_key("ess-onion-static-key-v1");
    controller_arc.set_onion_static_secret(onion_key);
    tracing::info!("[ONION] Static X25519 key derived from keystore and stored in controller.");

    let rotation_seed = keystore.derive_key("ess-id-rotation-seed-v1");
    {
        let controller = controller_arc.clone();
        tokio::spawn(id_rotation::rotation_task(
            rotation_seed,
            move |new_seed| {
                tracing::info!(
                    "[ID-ROTATION] Epoch changed, updating internal keys for peer {}",
                    controller.local_peer_id
                );
                controller.update_epoch_keys(new_seed);
            },
        ));
        tracing::info!("[ID-ROTATION] Internal key rotation task spawned.");
    }

    let node_role_str = env::var("NODE_ROLE").unwrap_or_else(|_| "client".to_string());
    let claimed_role = node_role_str.to_ascii_lowercase();
    tracing::info!("[BOOT] NODE_ROLE claimed: {}", claimed_role);

    let local_peer_id_str = ess.peer_id().to_string();
    let authority_guard = authority.get();
    let mut ess = ess;

    let resolved_role = match claimed_role.as_str() {
        "supernode" => {
            if authority_guard.supernodes.contains(&local_peer_id_str) {
                tracing::info!("[BOOT] Peer {} confirmed as Supernode in authority state.", local_peer_id_str);
                NodeRole::Supernode
            } else {
                tracing::warn!(
                    "[BOOT] NODE_ROLE=supernode requested but peer {} is NOT in authority_state.supernodes — \
                     downgrading to Client to prevent unauthorized privilege escalation.",
                    local_peer_id_str
                );
                NodeRole::Client
            }
        }
        "gateway" => {
            if authority_guard.allowed_peers.get(&local_peer_id_str)
                .map(|r| matches!(r, NodeRole::Gateway))
                .unwrap_or(false)
            {
                tracing::info!("[BOOT] Peer {} confirmed as Gateway in authority state.", local_peer_id_str);
                NodeRole::Gateway
            } else {
                tracing::warn!(
                    "[BOOT] NODE_ROLE=gateway requested but peer {} is NOT authorized as Gateway — \
                     downgrading to Client.",
                    local_peer_id_str
                );
                NodeRole::Client
            }
        }
        _ => NodeRole::Client,
    };

    tracing::info!("[BOOT] Resolved role: {:?}", resolved_role);
    ess.bind_role(resolved_role);

    let role = match resolved_role {
        NodeRole::Supernode => "supernode".to_string(),
        NodeRole::Gateway => "gateway".to_string(),
        _ => "client".to_string(),
    };

    ess.save_keypair("data/identity/ess_identity.bin")?;
    ess.save_role("data/identity/ess_identity.bin")?;

    if let Ok(mut w) = world_state.write() {
        w.set_authority(authority.get());
        w.observe_signal("system_boot_complete");
        tracing::info!("[DEBUG] Authority written to world_state before Ghost Engine start.");
    }

    let (ghost_handle, ghost_events) = GhostEngine::spawn_with_world_state(
        ess.ess_id().to_string(),
        role.clone(),
        GhostConfig::default(),
        world_state.clone(),
    );

    let ghost_bridge = spawn_ghost_bridge(
        ghost_handle.clone(),
        ghost_events,
        GhostBridgeOutputs::default(),
        GhostBridgeConfig::default(),
    );

    let ghost_runtime_handle = spawn_ghost_runtime(
        ghost_handle,
        ess.ess_id().to_string(),
        role.clone(),
        GhostRuntimeConfig::default(),
        world_state.clone(),
    );

    let mut registry = crate::web::ServiceRegistry::new();
    let record = crate::web::ServiceRecord::new(
        "node",
        "backbone",
        format!("p2p://{}", peer_id),
        peer_id.to_string(),
        peer_id.to_string(),
    )
    .normalized();

    if let Err(e) = registry.publish(&authority, &peer_id, record) {
        warn!("[BOOT] Web Registry publication skipped: {}", e);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Inisialisasi Compute Layer (PATCH #8) – dipindahkan ke sini
    // ═══════════════════════════════════════════════════════════════
    let authority_arc = Arc::new(authority.clone());
    let mut compute_handle: Option<ComputeSchedulerHandle> = None;
    let mut compute_store_arc: Option<Arc<ComputeStore>> = None;

    if std::env::var("ESS_COMPUTE_ENABLED")
        .unwrap_or_else(|_| "false".into())
        .eq_ignore_ascii_case("true")
    {
        info!("[BOOT] Initializing Compute Layer (WASM Runtime)...");
        match ComputeStore::open() {
            Ok(store) => {
                let store = Arc::new(store);
                match WasmEngine::new() {
                    Ok(engine) => {
                        let sched_config = SchedulerConfig {
                            max_concurrent_jobs: std::env::var("ESS_COMPUTE_MAX_JOBS")
                                .ok()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(4),
                            poll_interval_ms: 500,
                            accept_remote_jobs: true,
                        };

                        let handle = spawn_scheduler(
                            sched_config,
                            store.clone(),
                            engine,
                            authority_arc.clone(),
                            ess.peer_id().to_string(),
                        );

                        // Simpan handle ke controller
                        controller_arc.set_compute_handle(handle.clone());
                        controller_arc.set_compute_store(store.clone());
                        compute_handle = Some(handle);
                        compute_store_arc = Some(store);
                        info!("[BOOT] Compute Layer OK — WASM runtime aktif");
                    }
                    Err(e) => {
                        error!("[BOOT] Gagal init WASM engine: {}. Compute layer dinonaktifkan.", e);
                    }
                }
            }
            Err(e) => {
                error!("[BOOT] Gagal buka compute store: {}. Compute layer dinonaktifkan.", e);
            }
        }
    } else {
        info!("[BOOT] Compute Layer dinonaktifkan (set ESS_COMPUTE_ENABLED=true untuk mengaktifkan)");
    }

    // ═══════════════════════════════════════════════════════════════
    //  Inisialisasi Storage Layer (DIPERBAIKI: tambahkan argumen ke-4 controller_arc)
    // ═══════════════════════════════════════════════════════════════
    let storage_layer = StorageLayer::new(
        StorageLayerConfig::default(),
        keystore.clone(),
        authority_arc.clone(),
        controller_arc.clone(),
    );
    controller_arc.set_storage_layer(storage_layer.clone());

    // Bangun DashboardService dengan compute layer jika tersedia
    let db_store = DashboardStore::new();
    let mut db_service_builder = DashboardService::new(db_store.clone())
        .with_security(Arc::clone(&security_arc))
        .with_world_state(world_state.clone())
        .with_authority(authority.clone())
        .with_controller(controller_arc.clone());

    if let (Some(handle), Some(store)) = (compute_handle.clone(), compute_store_arc.clone()) {
        db_service_builder = db_service_builder.with_compute(handle, store);
    }
    // Tambahkan storage layer ke dashboard service
    if let Some(storage) = Some(storage_layer.clone()) {
        db_service_builder = db_service_builder.with_storage(storage);
    }

    let db_service = db_service_builder;

    let db_bridge = spawn_dashboard_bridge(db_store, DashboardBridgeConfig::default());
    let sender = db_bridge.sender();

    let node_info = NodeInfo {
        peer_id: peer_id.to_string(),
        role: role.clone(),
        ..Default::default()
    };
    send_node_info(&sender, node_info).await.ok();

    let health = NodeHealth {
        peer_id: peer_id.to_string(),
        state: "active".into(),
        health_level: "healthy".into(),
        connected_peers: 0,
        ..Default::default()
    };
    send_node_health(&sender, health).await.ok();

    let route = RouteInfo {
        from_peer: peer_id.to_string(),
        to_peer: "self".into(),
        trusted: true,
        active: true,
        updated_at: chrono::Utc::now().to_rfc3339(),
        latency_ms: Some(0),
        hops: vec!["self".to_string()],
    };
    send_route(&sender, route).await.ok();

    let log = LogEvent {
        ts: chrono::Utc::now().to_rfc3339(),
        node_id: peer_id.to_string(),
        level: "info".to_string(),
        message: "System booted.".to_string(),
        event: "System booted.".into(),
    };
    send_log(&sender, log).await.ok();

    let telemetry = TelemetryUpdate {
        peer_id: peer_id.to_string(),
        connected_peers: 0,
        latency_ms: 0,
    };
    send_telemetry(&sender, telemetry).await.ok();

    // ================= PATCH 1: Dashboard Auth & Localhost Binding =================
    let server_service = db_service.clone();
    let dashboard_bind = std::env::var("ESS_DASHBOARD_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let dashboard_token = std::env::var("ESS_DASHBOARD_TOKEN").ok();

    tokio::spawn(async move {
        tracing::info!("[DASHBOARD] Igniting HTTP Telemetry Server on {}", dashboard_bind);
        if let Err(e) = serve_dashboard_http(server_service, &dashboard_bind, dashboard_token).await {
            error!("[DASHBOARD] Telemetry Server failed: {}", e);
        }
    });
    // ==============================================================================

    let shutdown_ctrl = ShutdownController {
        controller: controller_arc.clone(),
        world_store: world_store.clone(),
        hmac_key: gov_hmac_key,
    };

    Ok((
        BootContext {
            ess,
            authority,
            world_state,
            security: security_arc,
            dashboard_tx: sender,
            ghost_runtime_handle,
            ghost_bridge,
            world_store,
            controller: controller_arc,
            event_rx,
            crdt_world: crdt_world_arc,
            compute_handle,   // NEW
        },
        shutdown_ctrl,
    ))
}

fn bootstrap_authority(path: &Path) -> Result<(AuthorityState, bool), Box<dyn Error>> {
    if !path.exists() {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p)?;
        }
        let state = authority::default_authority();
        state.save_to_file(path.to_string_lossy().as_ref())?;
        Ok((state, true))
    } else {
        Ok((
            authority::load_authority(path.to_string_lossy().as_ref())?,
            false,
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let json_log = fmt::layer()
        .json()
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(true);
    let env_filter = EnvFilter::from_default_env();
    tracing_subscriber::registry()
        .with(env_filter)
        .with(json_log)
        .init();

    tracing::info!("================================================");
    tracing::info!("   ESS BACKBONE - AUTONOMOUS P2P PROTOCOL       ");
    tracing::info!("================================================");

    let identity_path = "data/identity/ess_identity.bin";
    let profile_path = "data/my_profile.json";

    if Path::new(profile_path).exists() && !Path::new(identity_path).exists() {
        tracing::error!("❌ CRITICAL: Profile ditemukan tapi kunci identitas (ess_identity.bin) hilang!");
        tracing::error!("Restore ess_identity.bin dulu, atau hapus my_profile.json buat reset.");
        tracing::error!("Ini mencegah mesh fragmentation dengan menjaga Peer ID tetap stabil.");
        std::process::exit(1);
    }

    if !Path::new(identity_path).exists() {
        let shard_paths = [
            "data/identity/shard_0.bin",
            "data/identity/shard_1.bin",
        ];
        let all_exist = shard_paths.iter().all(|p| Path::new(p).exists());
        if all_exist {
            tracing::info!("[SSS] Identity file missing but shards found. Reconstructing seed...");
            match sss::reconstruct_from_files(&shard_paths) {
                Ok(_seed) => {
                    tracing::info!("[SSS] Seed recovered, identity will be derived from keystore if needed.");
                }
                Err(e) => tracing::error!("[SSS] Reconstruction failed: {}", e),
            }
        }
    }

    tracing::info!("[DEBUG] Initializing identity...");
    let (keypair, peer_id) = identity::initialize_identity(identity_path).await?;
    tracing::info!("[DEBUG] Identity ready: {}", peer_id);

    let onboarding = OnboardingManager::new();
    tracing::info!("[DEBUG] Starting onboarding (potentially blocking) in spawn_blocking...");
    let profile = tokio::task::spawn_blocking(move || {
        onboarding.setup_identity(peer_id)
    })
    .await
    .map_err(|join_err| Box::new(io::Error::new(io::ErrorKind::Other, join_err.to_string())) as Box<dyn Error>)
    .and_then(|result| result.map_err(|e| Box::new(io::Error::new(io::ErrorKind::Other, e.to_string())) as Box<dyn Error>))?;
    tracing::info!("[DEBUG] Onboarding completed for peer {}", profile.peer_id);

    // ===================== BLOCKER FIX: Guard default secret =====================
    if let Ok(secret) = env::var("ESS_MASTER_SECRET") {
        let lower = secret.to_lowercase();
        if lower.contains("change-this") || lower.contains("syndicate") {
            tracing::error!(
                "❌ ESS_MASTER_SECRET is still using a default or weak value! \
                 Refusing to start. Change it in .env before launching."
            );
            std::process::exit(1);
        }
        tracing::info!("[SECURITY] Master secret strength check passed.");
    }
    // =============================================================================

    let lifecycle = Lifecycle::new(keypair, profile, None);
    tracing::info!("[DEBUG] Entering lifecycle execute...");
    lifecycle.execute().await
}
