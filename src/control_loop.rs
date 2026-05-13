// src/control_loop.rs
use crate::network_controller::NetworkController;
use crate::world_state::{SharedWorldState, WorldState};
use crate::ghost_runtime::GhostRuntimeHandle;
use crate::ghost_bridge::GhostBridgeHandle;
use crate::storage::WorldStateStore;
use crate::system_event::{SystemEvent, SystemEventKind};
use crate::dashboard_bridge::DashboardBridgeInput;
use crate::ghost_health::GhostHealthSnapshot;
use crate::authority::AuthorityState;
use crate::id_rotation;
use crate::crdt_state::CrdtSyncMessage;
use crate::pqc;

// ── Compute Layer (NEW) ──────────────────────────────────────────────────
use crate::compute::scheduler::{ComputeEvent, ComputeSchedulerHandle};

use std::sync::Arc;
use std::env;
use tokio::sync::mpsc;
use tokio::time::{self, Duration, Interval};
use log::{info, warn, debug, error};

pub struct ControlLoop {
    controller: Arc<NetworkController>,
    world_state: SharedWorldState,
    ghost: GhostRuntimeHandle,
    ghost_bridge: GhostBridgeHandle,
    world_store: Arc<WorldStateStore>,
    event_rx: mpsc::Receiver<SystemEvent>,
    dashboard_tx: mpsc::Sender<DashboardBridgeInput>,
    last_rotation_epoch: u64,

    /// Handle ke compute scheduler (None jika node tidak punya compute layer)
    compute_handle: Option<ComputeSchedulerHandle>,

    /// Interval publikasi kapasitas komputasi ke DHT
    capacity_publish_interval: Interval,
}

impl ControlLoop {
    pub fn new(
        controller: Arc<NetworkController>,
        world_state: SharedWorldState,
        ghost: GhostRuntimeHandle,
        ghost_bridge: GhostBridgeHandle,
        world_store: Arc<WorldStateStore>,
        event_rx: mpsc::Receiver<SystemEvent>,
        dashboard_tx: mpsc::Sender<DashboardBridgeInput>,
        compute_handle: Option<ComputeSchedulerHandle>,
    ) -> Self {
        // Interval publish kapasitas, bisa diatur lewat env var, default 120 detik
        let capacity_publish_secs: u64 = env::var("ESS_COMPUTE_CAPACITY_PUBLISH_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120);

        Self {
            controller,
            world_state,
            ghost,
            ghost_bridge,
            world_store,
            event_rx,
            dashboard_tx,
            last_rotation_epoch: id_rotation::current_epoch(),
            compute_handle,
            capacity_publish_interval: time::interval(Duration::from_secs(capacity_publish_secs)),
        }
    }

    pub async fn run(mut self) {
        info!("[CONTROL-LOOP] System Pulse started. Monitoring ESS Backbone...");

        let mut ticker = time::interval(Duration::from_secs(30));
        let mut persist_ticker = time::interval(Duration::from_secs(300));
        let mut crdt_sync_interval = time::interval(Duration::from_secs(120));
        let mut rotation_check_interval = time::interval(Duration::from_secs(3600));
        let mut pqc_handshake_interval = time::interval(Duration::from_secs(600));

        // ── Subscribe ke compute events jika ada ─────────────────────────
        let mut compute_events = self
            .compute_handle
            .as_ref()
            .map(|h| h.subscribe_events());

        loop {
            tokio::select! {
                Some(event) = self.event_rx.recv() => {
                    self.handle_system_event(event).await;
                }
                _ = ticker.tick() => {
                    self.on_ticker_tick().await;
                }
                _ = persist_ticker.tick() => {
                    self.on_persist_tick().await;
                }
                _ = crdt_sync_interval.tick() => {
                    self.on_crdt_sync_tick().await;
                }
                _ = rotation_check_interval.tick() => {
                    self.on_rotation_check_tick().await;
                }
                _ = pqc_handshake_interval.tick() => {
                    self.on_pqc_handshake_tick().await;
                }
                // ── Publish kapasitas komputasi secara berkala ────────────
                _ = self.capacity_publish_interval.tick() => {
                    if let Some(ref handle) = self.compute_handle {
                        let peer_id = self.controller.peer_id().to_string();
                        handle.publish_capacity(&peer_id, &self.controller).await;
                    }
                }
                Some(Ok(ce)) = async {
                    if let Some(rx) = &mut compute_events {
                        Some(rx.recv().await)
                    } else {
                        None
                    }
                } => {
                    self.handle_compute_event(ce).await;
                }
            }
        }
    }

    // -----------------------------------------------------------------
    //  Existing periodic tasks
    // -----------------------------------------------------------------
    async fn on_ticker_tick(&self) {
        Arc::clone(&self.controller).reconcile_now_arc();

        if let Some(auth) = self.controller.get_authority() {
            let local_peer = self.controller.peer_id();
            if auth.can_gateway(&local_peer) {
                debug!("[CONTROL-LOOP] Local identity verified as Gateway.");
            }
        }

        let world_data = {
            if let Ok(ws) = self.world_state.read() {
                let snap = ws.snapshot();
                Some((
                    snap.connected_peers,
                    snap.known_peers,
                    snap.route_peers,
                    snap.trusted_peers,
                    snap.revision,
                ))
            } else {
                None
            }
        };

        if let Some((conn, known, route, trusted, _rev)) = world_data {
            let local_peer_id = self.controller.peer_id().to_string();

            let _ = self.dashboard_tx.try_send(DashboardBridgeInput::Telemetry(
                crate::dashboard_bridge::TelemetryUpdate {
                    peer_id: local_peer_id.clone(),
                    connected_peers: conn,
                    latency_ms: 0,
                },
            ));

            let role = self
                .controller
                .get_security()
                .map(|s| s.current_role().as_str().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let health_snap = GhostHealthSnapshot {
                node_id: local_peer_id,
                role,
                connected_peers: conn,
                known_peers: known,
                route_peers: route,
                trusted_peers: trusted,
                ..Default::default()
            };

            let _ = self.ghost.assess().await;
            let _ = self.ghost.tick().await;
            let _ = self.ghost.health(health_snap).await;
            let _ = self.ghost_bridge.update_metrics(conn, known, route).await;
        }
    }

    async fn on_persist_tick(&self) {
        debug!("[CONTROL-LOOP] Archiving current WorldState...");
        if let Some(auth_manager) = self.controller.get_authority() {
            let auth_state: AuthorityState = auth_manager.get();
            crate::world_state::prime_control_center(
                &self.world_state,
                &auth_state,
                "local",
                "node",
                true,
                true,
            );

            if let Ok(ws) = self.world_state.read() {
                let _ = self.world_store.persist(&*ws, None);
            }
        }
    }

    async fn on_crdt_sync_tick(&self) {
        if let Some(crdt) = self.controller.crdt_world() {
            let state = crdt.read().await;

            let node_id = self.controller.peer_id().to_string();
            let sync_msg = CrdtSyncMessage::new(node_id, state.clone());

            let peers = state
                .peers
                .connected_peers()
                .iter()
                .map(|p| p.peer_id.clone())
                .collect::<Vec<_>>();
            drop(state);

            if let Ok(payload) = bincode::serialize(&sync_msg) {
                for peer_id_str in &peers {
                    if let Ok(peer_id) = peer_id_str.parse::<libp2p::PeerId>() {
                        let _ = self
                            .controller
                            .send_typed_message(peer_id, "crdt_sync", payload.clone())
                            .await;
                    }
                }
                debug!(
                    "[CRDT] Sync broadcast completed (msg_ts={}, peers_count={})",
                    sync_msg.ts,
                    peers.len()
                );
            }
        }
    }

    async fn on_rotation_check_tick(&mut self) {
        let secs_to_rotation = id_rotation::next_rotation_in_secs();
        let current_epoch = id_rotation::current_epoch();

        debug!(
            "[ID-ROTATION] Current epoch: {}, next rotation in {}s",
            current_epoch, secs_to_rotation
        );

        if id_rotation::should_rotate(self.last_rotation_epoch) {
            info!(
                "[ID-ROTATION] 🔄 New epoch {} detected (was {}). Triggering network readiness broadcast.",
                current_epoch, self.last_rotation_epoch
            );

            let _ = self.ghost.trigger_beacon().await;
            let _ = self.ghost.assess().await;

            self.last_rotation_epoch = current_epoch;

            let _ = self.dashboard_tx.try_send(
                crate::dashboard_bridge::DashboardBridgeInput::Log(
                    crate::dashboard::LogEvent {
                        ts: chrono::Utc::now().to_rfc3339(),
                        node_id: self.controller.peer_id().to_string(),
                        level: "info".to_string(),
                        message: format!("[ID-ROTATION] Rotated to epoch {}", current_epoch),
                        event: "id_rotation".into(),
                    },
                ),
            );
        } else if secs_to_rotation < 3600 {
            info!(
                "[ID-ROTATION] Rotation approaching in {}s — next epoch: {}",
                secs_to_rotation,
                current_epoch + 1
            );
        }
    }

    async fn on_pqc_handshake_tick(&self) {
        let peer_id_str = self.controller.peer_id().to_string();

        let our_keypair = pqc::HybridKeyPair::generate(&peer_id_str);
        let our_pubkey_bin = match bincode::serialize(&our_keypair.public_key) {
            Ok(v) => v,
            Err(e) => {
                warn!("[PQC] Failed to serialize public key: {}", e);
                return;
            }
        };

        let trusted_peers: Vec<String> = {
            if let Ok(ws) = self.world_state.read() {
                ws.peer_registry
                    .values()
                    .filter(|p| p.trusted && p.connected)
                    .map(|p| p.peer_id.clone())
                    .collect()
            } else {
                vec![]
            }
        };

        if trusted_peers.is_empty() {
            debug!("[PQC] No trusted peers for handshake this cycle.");
            return;
        }

        info!(
            "[PQC] Initiating handshake with {} trusted peer(s).",
            trusted_peers.len()
        );

        for peer_id_str in trusted_peers {
            if let Ok(peer_id) = peer_id_str.parse::<libp2p::PeerId>() {
                match self
                    .controller
                    .send_direct_message(peer_id, our_pubkey_bin.clone())
                    .await
                {
                    Ok(response_body) => {
                        match bincode::deserialize::<pqc::HybridCiphertext>(&response_body) {
                            Ok(ciphertext) => {
                                match our_keypair.decapsulate(&ciphertext) {
                                    Ok(session_key) => {
                                        info!(
                                            "[PQC] ✅ Session key established with peer {}. Key fingerprint: {}",
                                            peer_id,
                                            hex::encode(&session_key.as_bytes()[..8])
                                        );
                                    }
                                    Err(e) => {
                                        warn!("[PQC] Decapsulation failed for {}: {}", peer_id, e)
                                    }
                                }
                            }
                            Err(_) => {
                                debug!(
                                    "[PQC] Peer {} returned non-PQC response (may not support yet).",
                                    peer_id
                                );
                            }
                        }
                    }
                    Err(e) => debug!("[PQC] Handshake to {} failed: {}", peer_id, e),
                }
            }
        }
    }

    async fn handle_system_event(&self, event: SystemEvent) {
        self.controller.update_world_state(|w: &mut WorldState| {
            w.observe_signal(format!("loop:{:?}", event.kind));
        });

        match &event.kind {
            SystemEventKind::PeerConnected { peer_id } => {
                info!("[CONTROL-LOOP] Sovereign Link established: {}", peer_id);
                self.controller.update_peer_success(peer_id, 45.0);
                let _ = self
                    .ghost_bridge
                    .observe_peer_connected(peer_id.to_string())
                    .await;
            }
            SystemEventKind::PeerDisconnected { peer_id } => {
                warn!("[CONTROL-LOOP] Sovereign Link severed: {}", peer_id);
                let _ = self
                    .ghost_bridge
                    .observe_peer_disconnected(peer_id.to_string())
                    .await;
                let _ = self.ghost.trigger_beacon().await;
            }
            SystemEventKind::SecurityReject { peer_id, reason } => {
                error!("[SECURITY] Rejected {}: {}", peer_id, reason);
                self.controller.update_peer_failure(peer_id);
                let _ = self.ghost_bridge.observe_message_failed(reason).await;
                let _ = self.ghost.assess().await;
            }
            SystemEventKind::AuthorityViolation { peer_id, action } => {
                error!("[CRITICAL] Policy Violation by {}: {:?}", peer_id, action);
                self.controller.update_peer_failure(peer_id);
                let _ = self.ghost_bridge.panic("policy_violation").await;
                let _ = self.ghost.zeroize().await;
            }
            SystemEventKind::GhostRecommendation { signal } => {
                match signal.as_str() {
                    "reload_policy" => {
                        warn!("[CONTROL-LOOP] Reloading policy by ghost command...");
                        if let Some(sec) = self.controller.get_security() {
                            if let Err(e) = sec.reload_policy("data/policy_inner.toml") {
                                error!("Policy reload failed: {}", e);
                            } else {
                                info!("Policy reloaded successfully");
                            }
                        }
                    }
                    "sleep_ghost" => {
                        warn!("[CONTROL-LOOP] Ghost commanded to SLEEP.");
                        let _ = self.ghost.sleep().await;
                    }
                    "wake_ghost" => {
                        warn!("[CONTROL-LOOP] Ghost commanded to WAKE.");
                        let _ = self.ghost.wake().await;
                    }
                    "tamper_on" => {
                        warn!("[CONTROL-LOOP] Enabling TAMPER mode.");
                        let _ = self.ghost.set_tamper(true).await;
                    }
                    "tamper_off" => {
                        warn!("[CONTROL-LOOP] Disabling TAMPER mode.");
                        let _ = self.ghost.set_tamper(false).await;
                    }
                    "policy_update" => {
                        warn!("[CONTROL-LOOP] Updating Ghost policy from default.");
                        let new_policy = crate::ghost_policy::GhostPolicy::default();
                        let _ = self.ghost.policy_update(new_policy).await;
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        let _ = self.ghost.publish_event(&event.kind).await;
    }

    // ── Compute event handler ──────
    async fn handle_compute_event(&self, event: ComputeEvent) {
        match event {
            ComputeEvent::JobQueued(id) => {
                let id_str = id.0.clone();
                info!("[CONTROL-LOOP] Compute job queued: {}", id_str);
                if let Ok(mut ws) = self.world_state.write() {
                    ws.observe_signal(format!("compute:job_queued:{}", id_str));
                }
            }
            ComputeEvent::JobCompleted(id, result) => {
                info!(
                    "[CONTROL-LOOP] Compute job completed: {} in {}ms (fuel: {})",
                    id.0, result.exec_time_ms, result.fuel_consumed
                );

                let submitter = result.submitter_peer_id.clone();

                let _ = self
                    .dashboard_tx
                    .send(DashboardBridgeInput::ComputeJobResult(
                        id.0.clone(),
                        result.clone(),
                    ))
                    .await;

                // ========== PERBAIKAN ERROR E0599 ==========
                let ctrl = self.controller.clone();
                
                tokio::spawn(async move {
                    // Pemanggilan associated function langsung dari tipe enum-nya
                    if let Err(e) = crate::compute::network::ComputeMessage::send_result(&ctrl, &submitter, result).await {
                        warn!("Failed to send compute result to {}: {}", submitter, e);
                    } else {
                        debug!("Compute result sent back to submitter {}", submitter);
                    }
                });
                // ===========================================
            }
            ComputeEvent::JobFailed(id, reason) => {
                warn!("[CONTROL-LOOP] Compute job failed: {} — {}", id.0, reason);
                let kind = SystemEventKind::ComputeJobFailed {
                    job_id: id.0.clone(),
                    reason,
                };
                let _ = self.ghost.publish_event(&kind).await;
            }
            _ => {}
        }
    }
}

