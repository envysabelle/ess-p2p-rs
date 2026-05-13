use crate::authority::{Action, AuthorityManager};
use crate::crdt_state;
use crate::gateway::{
    validate_gateway_access, validate_gateway_route, GatewayAuditEntry, GatewayRateLimitConfig,
    GatewayRateLimitDecision, GatewayRateLimiter,
};
use crate::compute::scheduler::ComputeSchedulerHandle;
use crate::compute::store::ComputeStore;
use crate::ghost_runtime::{GhostActionSink, GhostRuntimeHandle};
use crate::message::DirectResponse;
use crate::message::DirectRequest;
use crate::governance::engine::GovernanceEngine;
use crate::governance::messages::ActivationCertificate;
use crate::network::runtime::types::{Behaviour, OnboardRequest, OnboardResponse};
use crate::security_runtime::SecurityRuntime;
use crate::storage_layer::StorageLayer; // NEW: Storage Layer
use crate::system_event::{SystemEvent, SystemEventKind};
use crate::world_state::SharedWorldState;
use crate::onion::OnionNodeKey;
use crate::id_rotation::next_epoch_seed;
use libp2p::{request_response::OutboundRequestId, swarm::Swarm, PeerId};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, timeout, Duration, Instant};
use dashmap::DashMap;
use x25519_dalek::PublicKey as X25519PublicKey;
use sha2::{Sha256, Digest};
use parking_lot::Mutex;
use crate::network::runtime::support::send_via_onion;
use crate::network::runtime::runner::RuntimeContext;

fn boxed_error(msg: impl Into<String>) -> Box<dyn Error + Send> {
    Box::new(std::io::Error::new(std::io::ErrorKind::Other, msg.into()))
}

pub struct NetworkController {
    pub local_peer_id: PeerId,
    swarm: Arc<Mutex<Option<Swarm<Behaviour>>>>,
    authority: Arc<RwLock<Option<AuthorityManager>>>,
    ghost: Arc<RwLock<Option<GhostRuntimeHandle>>>,
    security: Arc<RwLock<Option<Arc<SecurityRuntime>>>>,
    world_state: Arc<RwLock<Option<SharedWorldState>>>,
    reputation: Arc<RwLock<HashMap<PeerId, PeerReputation>>>,
    gateway_limiter: Arc<Mutex<GatewayRateLimiter>>,
    authority_path: Arc<RwLock<Option<PathBuf>>>,
    authority_public_key: Arc<RwLock<Option<ed25519_dalek::PublicKey>>>,
    event_tx: Option<mpsc::Sender<SystemEvent>>,
    pending_direct: Arc<
        Mutex<HashMap<OutboundRequestId, oneshot::Sender<Result<Vec<u8>, Box<dyn Error + Send>>>>>,
    >,
    pending_onboard: Arc<
        Mutex<
            HashMap<
                OutboundRequestId,
                oneshot::Sender<Result<OnboardResponse, Box<dyn Error + Send>>>,
            >,
        >,
    >,
    pub governance_engine: Arc<RwLock<GovernanceEngine>>,
    crdt_world: Arc<RwLock<Option<Arc<tokio::sync::RwLock<crdt_state::CrdtWorldState>>>>>,
    onion_static_secret: Arc<RwLock<Option<[u8; 32]>>>,
    onion_config: Arc<RwLock<Option<(usize, Arc<DashMap<PeerId, X25519PublicKey>>)>>>,
    compute_handle: Arc<RwLock<Option<ComputeSchedulerHandle>>>,
    compute_store: Arc<RwLock<Option<Arc<ComputeStore>>>>,
    storage_layer: Arc<RwLock<Option<StorageLayer>>>, // NEW
    current_rotation_seed: Arc<Mutex<Option<[u8; 32]>>>,
}

impl fmt::Debug for NetworkController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkController")
            .field("local_peer_id", &self.local_peer_id)
            .field("swarm", &"<Swarm<Behaviour>>")
            .field("authority", &self.authority)
            .field("ghost", &self.ghost)
            .field("security", &self.security)
            .field("world_state", &self.world_state)
            .field("reputation", &self.reputation)
            .field("gateway_limiter", &self.gateway_limiter)
            .field("authority_path", &self.authority_path)
            .field("authority_public_key", &self.authority_public_key)
            .field("event_tx", &self.event_tx)
            .field("governance_engine", &"<GovernanceEngine>")
            .field("crdt_world", &self.crdt_world)
            .field("onion_static_secret", &"<OnionNodeKey>")
            .field("onion_config", &self.onion_config)
            .field("current_rotation_seed", &self.current_rotation_seed)
            .finish()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerReputation {
    pub score: f64,
    pub is_quarantined: bool,
    pub successful_ops: u64,
    pub last_latency: f64,
}

impl Default for PeerReputation {
    fn default() -> Self {
        Self {
            score: 0.5,
            is_quarantined: false,
            successful_ops: 0,
            last_latency: 200.0,
        }
    }
}

impl NetworkController {
    pub fn new(
        peer_id: PeerId,
        world: SharedWorldState,
        event_tx: Option<mpsc::Sender<SystemEvent>>,
    ) -> Self {
        Self {
            local_peer_id: peer_id,
            swarm: Arc::new(Mutex::new(None)),
            authority: Arc::new(RwLock::new(None)),
            ghost: Arc::new(RwLock::new(None)),
            security: Arc::new(RwLock::new(None)),
            world_state: Arc::new(RwLock::new(Some(world))),
            reputation: Arc::new(RwLock::new(HashMap::new())),
            gateway_limiter: Arc::new(Mutex::new(GatewayRateLimiter::new(
                GatewayRateLimitConfig::default(),
            ))),
            authority_path: Arc::new(RwLock::new(None)),
            authority_public_key: Arc::new(RwLock::new(None)),
            event_tx,
            pending_direct: Arc::new(Mutex::new(HashMap::new())),
            pending_onboard: Arc::new(Mutex::new(HashMap::new())),
            governance_engine: Arc::new(RwLock::new(GovernanceEngine::new(vec![], 0.66))),
            crdt_world: Arc::new(RwLock::new(None)),
            onion_static_secret: Arc::new(RwLock::new(None)),
            onion_config: Arc::new(RwLock::new(None)),
            compute_handle: Arc::new(RwLock::new(None)),
            compute_store: Arc::new(RwLock::new(None)),
            storage_layer: Arc::new(RwLock::new(None)), // NEW
            current_rotation_seed: Arc::new(Mutex::new(None)),
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub fn world_state(&self) -> Option<SharedWorldState> {
        self.world_state.read().ok()?.as_ref().cloned()
    }

    pub fn set_crdt_world(&self, crdt: Arc<tokio::sync::RwLock<crdt_state::CrdtWorldState>>) {
        if let Ok(mut guard) = self.crdt_world.write() {
            *guard = Some(crdt);
        }
    }

    pub fn crdt_world(&self) -> Option<Arc<tokio::sync::RwLock<crdt_state::CrdtWorldState>>> {
        self.crdt_world.read().ok()?.clone()
    }

    pub fn set_onion_static_secret(&self, secret_bytes: [u8; 32]) {
        if let Ok(mut guard) = self.onion_static_secret.write() {
            *guard = Some(secret_bytes);
            tracing::info!("[ONION] Static X25519 secret key stored in controller.");
        }
    }

    pub fn get_onion_static_secret(&self) -> Option<OnionNodeKey> {
        let guard = self.onion_static_secret.read().ok()?;
        guard.as_ref().map(|bytes| OnionNodeKey::from_bytes(*bytes))
    }

    pub fn set_onion_config(&self, hops: usize, store: Arc<DashMap<PeerId, X25519PublicKey>>) {
        *self.onion_config.write().expect("onion_config lock failed") = Some((hops, store));
    }

    // --- Rotasi kunci internal berbasis hash chain ---
    pub fn update_epoch_keys(&self, new_seed: [u8; 32]) {
        let onion_key = derive_static_secret_from_seed(&new_seed, b"onion-key");
        self.set_onion_static_secret(onion_key);
        tracing::info!("[ID-ROTATION] Onion static secret rotated to new epoch");
    }

    /// Lakukan rotasi ID dengan hash chain: ambil current seed, hitung next, simpan, lalu update kunci.
    pub fn rotate_id_seed(&self) {
        let mut current = self.current_rotation_seed.lock();
        if let Some(seed) = *current {
            let next = next_epoch_seed(&seed);
            *current = Some(next);
            tracing::info!("[ID-ROTATION] Seed rotated to next epoch: {:?}", next);
            self.update_epoch_keys(next);
        } else {
            tracing::warn!("[ID-ROTATION] No rotation seed set; cannot rotate");
        }
    }

    /// Set seed awal (dari luar, misal dari governance atau genesis)
    pub fn set_rotation_seed(&self, seed: [u8; 32]) {
        *self.current_rotation_seed.lock() = Some(seed);
    }

    // ── Compute handle management ─────────────────────────────
    pub fn set_compute_handle(&self, handle: ComputeSchedulerHandle) {
        *self.compute_handle.write().unwrap() = Some(handle);
    }

    pub fn get_compute_handle(&self) -> Option<ComputeSchedulerHandle> {
        self.compute_handle.read().unwrap().clone()
    }

    // ── Compute store management ──────────────────────────────
    pub fn set_compute_store(&self, store: Arc<ComputeStore>) {
        *self.compute_store.write().unwrap() = Some(store);
    }

    pub fn get_compute_store(&self) -> Option<Arc<ComputeStore>> {
        self.compute_store.read().unwrap().clone()
    }

    // ── Storage Layer management ──────────────────────────────
    pub fn set_storage_layer(&self, storage: StorageLayer) {
        *self.storage_layer.write().unwrap() = Some(storage);
    }

    pub fn get_storage_layer(&self) -> Option<StorageLayer> {
        self.storage_layer.read().unwrap().clone()
    }

    // --- Kirim pesan melalui onion routing (fire-and-forget) ---
    pub async fn send_onion_message(
        &self,
        payload: Vec<u8>,
        destination: PeerId,
    ) -> Result<(), Box<dyn Error + Send>> {
        let onion_info = {
            let guard = self.onion_config.read()
                .map_err(|e| boxed_error(format!("Lock error: {e}")))?;
            guard.clone()
        };

        let (hops, store) = match onion_info {
            Some((hops, store)) if hops > 0 => (hops, store),
            _ => return Err(boxed_error("Onion routing is disabled or not configured")),
        };

        let known_peers: Vec<PeerId> = {
            if let Some(ws) = self.world_state() {
                let ws = ws.read()
                    .map_err(|e| boxed_error(format!("Lock error: {e}")))?;
                ws.peer_registry
                    .keys()
                    .filter_map(|s| s.parse::<PeerId>().ok())
                    .collect()
            } else {
                vec![]
            }
        };

        let local_x25519_sk = self
            .get_onion_static_secret()
            .map(|k| k.static_secret)
            .ok_or_else(|| boxed_error("Onion static secret is not initialized"))?;

        let ctx = RuntimeContext {
            onion_hops: hops,
            onion_payload_size: 1400,
            local_x25519_sk,
            peer_pubkey_store: store,
            authority_pubkey: None,
        };

        self.wait_for_swarm_ready(Duration::from_secs(10)).await?;

        let mut guard = self.swarm.lock();
        let swarm = guard
            .as_mut()
            .ok_or_else(|| boxed_error("Swarm not initialized"))?;

        send_via_onion(swarm, &ctx, &destination, payload, &known_peers);
        Ok(())
    }

    async fn wait_for_swarm_ready(
        &self,
        timeout_duration: Duration,
    ) -> Result<(), Box<dyn Error + Send>> {
        let start = Instant::now();
        loop {
            {
                let guard = self.swarm.lock();
                if guard.is_some() {
                    return Ok(());
                }
            }
            if start.elapsed() >= timeout_duration {
                return Err(boxed_error("Timed out waiting for swarm initialization"));
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn enforce(&self, peer: &PeerId, action: Action) -> bool {
        if let Ok(repo) = self.reputation.read() {
            if let Some(meta) = repo.get(peer) {
                if meta.is_quarantined {
                    warn!(
                        "[SECURITY] Action {:?} blocked: Peer {} is quarantined.",
                        action, peer
                    );
                    return false;
                }
            }
        }
        if let Ok(guard) = self.security.read() {
            if let Some(sec) = guard.as_ref() {
                let action_str = format!("{:?}", action).to_lowercase();
                if sec.verify_access(&action_str).is_err() {
                    warn!(
                        "[SECURITY] Action '{}' not allowed by policy for peer {}",
                        action_str, peer
                    );
                    return false;
                }
            }
        }
        if let Ok(guard) = self.security.read() {
            if let Some(sec) = guard.as_ref() {
                if !sec.is_allowed(peer, action) {
                    warn!(
                        "[SECURITY] Policy rejection (SecurityRuntime) for {} on {:?}",
                        peer, action
                    );
                    self.consume_event(SystemEvent::new(
                        "controller",
                        SystemEventKind::AuthorityViolation {
                            peer_id: *peer,
                            action,
                        },
                    ))
                    .await;
                    return false;
                }
            }
        }
        if let Ok(guard) = self.authority.read() {
            if let Some(auth) = guard.as_ref() {
                if !auth.is_allowed(peer, action) {
                    debug!(
                        "[SECURITY] Authority rejection for {} on {:?}",
                        peer, action
                    );
                    self.consume_event(SystemEvent::new(
                        "controller",
                        SystemEventKind::AuthorityViolation {
                            peer_id: *peer,
                            action,
                        },
                    ))
                    .await;
                    return false;
                }
            }
        }
        true
    }

    pub async fn enforce_peer(&self, peer: &PeerId) -> bool {
        if !self.enforce(peer, Action::Connect).await {
            return false;
        }
        if let Ok(guard) = self.security.read() {
            if let Some(sec) = guard.as_ref() {
                if sec.verify_peer(peer).is_err() {
                    warn!("[SECURITY] Peer {} rejected by verify_peer policy", peer);
                    return false;
                }
            }
        }
        true
    }

    pub async fn enforce_gateway_peer(&self, peer: &PeerId) -> bool {
        if let Ok(guard) = self.authority.read() {
            if let Some(auth) = guard.as_ref() {
                if let Err(e) = validate_gateway_access(peer, auth) {
                    warn!("[SECURITY] Gateway access denied for {}: {}", peer, e);
                    return false;
                }
                if let Err(e) = validate_gateway_route(peer, auth) {
                    warn!("[SECURITY] Gateway Route rejected for {}: {}", peer, e);
                    return false;
                }
            }
        }
        self.enforce(peer, Action::GatewayAccess).await
    }

    pub async fn consume_event(&self, event: SystemEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event).await;
        }
    }

    pub fn update_peer_success(&self, peer: &PeerId, latency: f64) {
        if let Ok(mut repo) = self.reputation.write() {
            let e = repo.entry(*peer).or_default();
            e.score = (e.score + 0.01).min(1.0);
            e.last_latency = latency;
            e.successful_ops += 1;
        }
    }

    pub fn update_peer_failure(&self, peer: &PeerId) {
        if let Ok(mut repo) = self.reputation.write() {
            let e = repo.entry(*peer).or_default();
            e.score = (e.score - 0.1).max(0.0);
            if e.score < 0.1 {
                e.is_quarantined = true;
                warn!(
                    "[REPUTATION] Peer {} has been quarantined (Score: {:.2})",
                    peer, e.score
                );
            }
        }
    }

    pub fn set_peer_quarantine(&self, peer: &PeerId, reason: &str) {
        if let Ok(mut repo) = self.reputation.write() {
            let e = repo.entry(*peer).or_default();
            e.is_quarantined = true;
            e.score = 0.05;
            warn!("[GHOST] Peer {} quarantined: {}", peer, reason);
        }
    }

    pub fn adjust_reputation(&self, peer: &PeerId, delta: f64) {
        if let Ok(mut repo) = self.reputation.write() {
            let e = repo.entry(*peer).or_default();
            e.score = (e.score + delta).clamp(0.0, 1.0);
            debug!(
                "[GHOST] Reputation of {} changed by {:.2}, now {:.2}",
                peer, delta, e.score
            );
        }
    }

    pub fn reroute_traffic(&self, _peer: &PeerId, alt_nodes: &[String]) {
        warn!(
            "[GHOST] Reroute requested. Alternative nodes: {:?}",
            alt_nodes
        );
    }

    pub fn check_gateway_rate_limit(&self, peer: &PeerId) -> GatewayRateLimitDecision {
        let mut l = self.gateway_limiter.lock();
        l.allow(peer, 1)
    }

    pub async fn record_gateway_audit(&self, entry: GatewayAuditEntry) {
        if let Ok(pid) = entry.peer_id.parse::<PeerId>() {
            self.consume_event(SystemEvent::new(
                "gateway",
                SystemEventKind::GatewayAudit {
                    peer_id: pid,
                    method: entry.method,
                    allowed: entry.allowed,
                },
            ))
            .await;
        }
    }

    pub fn push_ghost_sync(&self) {
        if let Some(tx) = &self.event_tx {
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = tx
                    .send(SystemEvent::new("controller", SystemEventKind::SyncCompleted))
                    .await;
            });
        }
    }

    pub async fn push_ghost_signal(&self, signal: String) {
        self.consume_event(SystemEvent::new(
            "ghost",
            SystemEventKind::GhostRecommendation { signal },
        ))
        .await;
    }

    pub async fn send_onboard_request(
        &self,
        to_peer: PeerId,
        request: OnboardRequest,
    ) -> Result<OnboardResponse, Box<dyn Error + Send>> {
        self.wait_for_swarm_ready(Duration::from_secs(10)).await?;
        let request_id = {
            let mut guard = self.swarm.lock();
            let swarm = guard
                .as_mut()
                .ok_or_else(|| boxed_error("Swarm not initialized"))?;
            swarm
                .behaviour_mut()
                .onboard
                .send_request(&to_peer, request)
        };
        let (tx, rx) = oneshot::channel::<Result<OnboardResponse, Box<dyn Error + Send>>>();
        self.pending_onboard.lock().insert(request_id, tx);
        let response = timeout(Duration::from_secs(15), rx)
            .await
            .map_err(|_| boxed_error("Onboard request timed out"))?
            .map_err(|_| boxed_error("Onboard request cancelled"))??;
        Ok(response)
    }

    pub fn complete_onboard_response(
        &self,
        request_id: OutboundRequestId,
        response: OnboardResponse,
    ) {
        let mut pending = self.pending_onboard.lock();
        if let Some(tx) = pending.remove(&request_id) {
            if tx.send(Ok(response)).is_err() {
                warn!("[ONBOARD] Failed to send onboard response to pending request");
            }
        }
    }

    pub async fn publish_verified_peer(&self, peer_id: PeerId, signed_cert: Vec<u8>) {
        let mut guard = self.swarm.lock();
        if let Some(swarm) = guard.as_mut() {
            let key = format!("verified_peer_{}", peer_id);
            let record = libp2p::kad::Record::new(libp2p::kad::RecordKey::new(&key), signed_cert);
            if let Err(e) = swarm
                .behaviour_mut()
                .kademlia
                .put_record(record, libp2p::kad::Quorum::One)
            {
                warn!(
                    "Failed to put Kademlia record for verified peer {}: {:?}",
                    peer_id, e
                );
            } else {
                info!("Published verified peer {} to Kademlia", peer_id);
            }
        } else {
            warn!("Swarm not available for Kademlia publishing");
        }
    }

    pub async fn send_activation_notification(&self, peer_id: PeerId, cert: ActivationCertificate) {
        let body = bincode::serialize(&cert).unwrap_or_default();
        let _ = self.send_typed_message(
            peer_id,
            "governance.activation_notify",
            body,
        ).await;
    }

    pub fn world_snapshot(&self) -> Option<crate::world_state::WorldStateSnapshot> {
        let ws_outer = self.world_state.read().ok()?;
        let ws_inner = ws_outer.as_ref()?;
        let guard = ws_inner.read().ok()?;
        Some(guard.snapshot())
    }

    pub fn get_authority(&self) -> Option<AuthorityManager> {
        self.authority.read().ok()?.as_ref().cloned()
    }

    pub fn get_security(&self) -> Option<Arc<SecurityRuntime>> {
        self.security.read().ok()?.clone()
    }

    pub fn reconcile_now_arc(self: Arc<Self>) {
        tokio::spawn(async move {
            self.reconcile_governance_once().await;
        });
    }

    async fn reconcile_governance_once(&self) {
        let auth_data = {
            if let Ok(guard) = self.authority.read() {
                if let (Some(a), Some(p), Some(k)) = (
                    guard.as_ref().cloned(),
                    self.authority_path.read().ok().and_then(|p| p.clone()),
                    self.authority_public_key
                        .read()
                        .ok()
                        .and_then(|k| k.clone()),
                ) {
                    Some((a, p, k))
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some((auth, path, pk)) = auth_data {
            debug!("[GOVERNANCE] Checking for authority updates at {:?}", path);
            let _ = auth.refresh_from_file(path.to_string_lossy().as_ref(), &pk);
        }
    }

    pub async fn send_direct_message(
        &self,
        to_peer: PeerId,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error + Send>> {
        info!(
            "[SEND_DIRECT] Starting direct message to {}",
            to_peer
        );
        self.wait_for_swarm_ready(Duration::from_secs(10)).await?;
        let security = {
            let guard = self
                .security
                .read()
                .map_err(|e| boxed_error(format!("Lock error: {e}")))?;
            guard
                .clone()
                .ok_or_else(|| boxed_error("SecurityRuntime not attached"))?
        };
        let request = security
            .build_direct_request_bytes(self.local_peer_id, to_peer, body)
            .map_err(|e| boxed_error(format!("{e}")))?;
        let request_id = {
            let mut guard = self.swarm.lock();
            let swarm = guard
                .as_mut()
                .ok_or_else(|| boxed_error("Swarm not initialized"))?;
            swarm
                .behaviour_mut()
                .direct
                .send_request(&to_peer, request)
        };
        let (tx, rx) = oneshot::channel::<Result<Vec<u8>, Box<dyn Error + Send>>>();
        self.pending_direct.lock().insert(request_id, tx);
        info!("[SEND_DIRECT] Waiting for response (timeout 10s)...");
        let response_bytes = timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| boxed_error("Direct request timed out"))?
            .map_err(|_| boxed_error("Direct request cancelled"))??;
        info!(
            "[SEND_DIRECT] Response received ({} bytes)",
            response_bytes.len()
        );
        Ok(response_bytes)
    }

    pub async fn send_typed_message(
        &self,
        to_peer: PeerId,
        kind: &str,
        body: Vec<u8>,
    ) -> Result<(), Box<dyn Error + Send>> {
        let request = DirectRequest {
            kind: kind.to_string(),
            ..DirectRequest::plain_bytes(
                self.local_peer_id.to_string(),
                to_peer.to_string(),
                body,
            )
        };
        let request_bytes =
            bincode::serialize(&request).map_err(|e| boxed_error(e.to_string()))?;
        self.send_direct_message(to_peer, request_bytes)
            .await
            .map(|_| ())
    }

    pub fn complete_pending_direct_request(
        &self,
        request_id: OutboundRequestId,
        response: DirectResponse,
    ) {
        fn make_err(msg: String) -> Box<dyn Error + Send> {
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, msg))
        }
        let security = match self.security.read().ok().and_then(|g| g.clone()) {
            Some(sec) => sec,
            None => {
                if let Some(tx) = self.pending_direct.lock().remove(&request_id) {
                    let _ = tx.send(Err(make_err("Security not attached".to_string())));
                }
                return;
            }
        };
        let from_peer = match response.from.parse::<PeerId>() {
            Ok(p) => p,
            Err(e) => {
                warn!("Invalid sender peer id in direct response: {}", e);
                if let Some(tx) = self.pending_direct.lock().remove(&request_id) {
                    let _ = tx.send(Err(make_err(format!("Invalid from peer id: {}", e))));
                }
                return;
            }
        };
        let verified_bytes =
            match security.verify_direct_response_bytes(self.local_peer_id, from_peer, &response) {
                Ok(body) => body,
                Err(e) => {
                    warn!(
                        "Direct response verification failed for request {}: {:?}",
                        request_id, e
                    );
                    if let Some(tx) = self.pending_direct.lock().remove(&request_id) {
                        let _ = tx.send(Err(make_err(format!("Verification error: {}", e))));
                    }
                    return;
                }
            };
        self.update_peer_success(&from_peer, response.ts as f64);
        if let Some(tx) = self.pending_direct.lock().remove(&request_id) {
            let _ = tx.send(Ok(verified_bytes));
        }
    }

    pub fn swarm_handle(&self) -> Arc<Mutex<Option<Swarm<Behaviour>>>> {
        Arc::clone(&self.swarm)
    }

    pub fn attach_governance(
        self: &Arc<Self>,
        a: AuthorityManager,
        g: GhostRuntimeHandle,
        w: SharedWorldState,
        authority_path: Option<PathBuf>,
        authority_public_key: Option<ed25519_dalek::PublicKey>,
    ) {
        if let Ok(mut guard) = self.authority.write() {
            *guard = Some(a);
        }
        if let Ok(mut guard) = self.ghost.write() {
            *guard = Some(g.clone());
        }
        if let Ok(mut guard) = self.world_state.write() {
            *guard = Some(w);
        }
        if let Ok(mut guard) = self.authority_path.write() {
            *guard = authority_path;
        }
        if let Ok(mut guard) = self.authority_public_key.write() {
            *guard = authority_public_key;
        }
        g.set_action_sink(Arc::clone(self) as Arc<dyn GhostActionSink>);
        info!("[SYSTEM] Autonomous Governance attached to Controller.");
    }

    pub fn attach_security(&self, s: Arc<SecurityRuntime>) {
        if let Ok(mut guard) = self.security.write() {
            *guard = Some(s);
        }
    }

    pub fn update_world_state<F>(&self, f: F)
    where
        F: FnOnce(&mut crate::world_state::WorldState),
    {
        if let Ok(guard) = self.world_state.read() {
            if let Some(ws_arc) = guard.as_ref() {
                if let Ok(mut ws) = ws_arc.write() {
                    f(&mut *ws);
                }
            }
        }
    }

    pub fn dial_peer_addr(&self, addr_str: &str) {
        if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
            let handle = self.swarm_handle();
            let mut guard = handle.lock();
            if let Some(swarm) = guard.as_mut() {
                match swarm.dial(addr.clone()) {
                    Ok(()) => info!("[PEER-EXCHANGE] Auto-dialing discovered peer: {}", addr),
                    Err(e) => warn!("[PEER-EXCHANGE] Failed to dial {}: {}", addr, e),
                }
            }
        }
    }
}

fn derive_static_secret_from_seed(seed: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ESS-EPOCH-DERIVE-V1");
    hasher.update(seed);
    hasher.update(label);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

impl GhostActionSink for NetworkController {
    fn drop_peer(&self, peer_id: &str) {
        if let Ok(pid) = peer_id.parse::<PeerId>() {
            let handle = self.swarm_handle();
            let mut guard = handle.lock();
            if let Some(swarm) = guard.as_mut() {
                if swarm.disconnect_peer_id(pid).is_err() {
                    warn!("[AUTONOMOUS] Failed to drop peer {}", pid);
                } else {
                    warn!("[AUTONOMOUS] Malicious peer {} dropped by Ghost Engine.", pid);
                }
            }
        }
    }

    fn limit_peer(&self, peer_id: &str) {
        if let Ok(pid) = peer_id.parse::<PeerId>() {
            self.update_peer_failure(&pid);
            debug!(
                "[AUTONOMOUS] Peer {} restricted due to policy warning.",
                pid
            );
        }
    }

    fn quarantine_peer(&self, peer_id: &str) {
        if let Ok(pid) = peer_id.parse::<PeerId>() {
            self.set_peer_quarantine(&pid, "Ghost-ordered quarantine");
            self.drop_peer(peer_id);
        }
    }

    fn reroute_traffic(&self, peer_id: &str, alt_nodes: &[String]) {
        if let Ok(pid) = peer_id.parse::<PeerId>() {
            self.reroute_traffic(&pid, alt_nodes);
        }
    }

    fn adjust_reputation_score(&self, peer_id: &str, delta: f64) {
        if let Ok(pid) = peer_id.parse::<PeerId>() {
            self.adjust_reputation(&pid, delta);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::default_authority;
    use crate::world_state::WorldState;
    use libp2p::PeerId;
    use std::sync::{Arc, RwLock};

    fn dummy_world() -> Arc<RwLock<WorldState>> {
        Arc::new(RwLock::new(WorldState::new(default_authority())))
    }

    #[tokio::test]
    async fn test_enforce_blocks_quarantined_peer() {
        let world = dummy_world();
        let ctrl = NetworkController::new(PeerId::random(), world, None);
        let peer = PeerId::random();
        ctrl.set_peer_quarantine(&peer, "test");
        assert!(!ctrl.enforce(&peer, Action::Connect).await);
    }

    #[tokio::test]
    async fn test_adjust_reputation_changes_score() {
        let world = dummy_world();
        let ctrl = NetworkController::new(PeerId::random(), world, None);
        let peer = PeerId::random();
        ctrl.adjust_reputation(&peer, -0.3);
        let repo = ctrl.reputation.read().expect("reputation lock failed");
        let rep = repo.get(&peer).unwrap();
        assert!((rep.score - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_ghost_action_sink_quarantine_calls_set_quarantine() {
        let world = dummy_world();
        let ctrl = NetworkController::new(PeerId::random(), world, None);
        let peer_id_str = PeerId::random().to_string();
        ctrl.quarantine_peer(&peer_id_str);
        let pid: PeerId = peer_id_str.parse().unwrap();
        let repo = ctrl.reputation.read().expect("reputation lock failed");
        assert!(repo.get(&pid).unwrap().is_quarantined);
    }
}
