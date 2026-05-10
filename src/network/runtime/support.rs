use crate::dashboard::{
    LogEvent as DashboardLogEvent, NodeHealth as DashboardNodeHealth,
    NodeInfo as DashboardNodeInfo, RouteInfo as DashboardRouteInfo,
};
use crate::dashboard_bridge::DashboardBridgeInput;
use crate::ghost_health::GhostHealthSnapshot;
use crate::ghost_runtime::GhostRuntimeHandle;
use chrono::Local;
use libp2p::PeerId;
use tokio::sync::mpsc;

// Impor tambahan untuk onion routing
use crate::message::{DirectRequest, EssRequest, OnionRelayRequest};
use crate::onion::{self, HopInfo};
use crate::network::runtime::runner::RuntimeContext;
use crate::network::runtime::types::Behaviour;
use libp2p::Swarm;
use rand::seq::SliceRandom;
use x25519_dalek::PublicKey as X25519PublicKey;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use tracing;

// ====================
// Dashboard Helpers
// ====================

pub(super) fn ts() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

pub(super) fn ping_average_ms(total_ms: u64, samples: usize) -> Option<u64> {
    if samples == 0 {
        None
    } else {
        Some(total_ms / samples as u64)
    }
}

pub(super) fn dashboard_health_level(
    bootstrap_ok: bool,
    config_ok: bool,
    failure_count: usize,
    connected_peers: usize,
) -> (String, String, String) {
    let (level, reason) = if failure_count >= 5 {
        ("critical", "failure_threshold_reached")
    } else if !bootstrap_ok {
        ("degraded", "bootstrap_not_ready")
    } else if !config_ok {
        ("degraded", "config_not_ready")
    } else if connected_peers == 0 {
        ("degraded", "no_connected_peers")
    } else if failure_count > 0 {
        ("degraded", "degraded_but_operational")
    } else {
        ("healthy", "healthy")
    };
    let state = if bootstrap_ok && config_ok && connected_peers > 0 {
        "Idle"
    } else {
        "Wake"
    };
    (level.to_string(), state.to_string(), reason.to_string())
}

pub(super) fn build_dashboard_health_snapshot(
    node_id: &str,
    peer_id: &PeerId,
    role: &str,
    connected_peers: usize,
    known_peers: usize,
    route_peers: usize,
    trusted_peers: usize,
    ping_ms_avg: Option<u64>,
    bootstrap_ok: bool,
    gateway_ok: bool,
    web_ok: bool,
    config_ok: bool,
    failure_count: usize,
    last_failure_reason: Option<String>,
    public_listen: Option<String>,
    location: Option<String>,
) -> DashboardNodeHealth {
    let (health_level, state, reason) =
        dashboard_health_level(bootstrap_ok, config_ok, failure_count, connected_peers);
    DashboardNodeHealth {
        node_id: node_id.to_string(),
        peer_id: peer_id.to_string(),
        role: role.to_string(),
        state,
        health_level,
        decision: "Noop".to_string(),
        reason,
        connected_peers,
        known_peers,
        route_peers,
        trusted_peers,
        ping_ms_avg,
        bootstrap_ok,
        gateway_ok,
        web_ok,
        config_ok,
        tamper_detected: false,
        failure_count,
        last_failure_reason,
        updated_at: ts(),
        public_listen,
        location,
    }
}

pub(super) fn build_dashboard_node_info(
    node_id: &str,
    peer_id: &PeerId,
    role: &str,
    state: &str,
    health_level: Option<&str>,
    public_listen: Option<String>,
    location: Option<String>,
) -> DashboardNodeInfo {
    DashboardNodeInfo {
        node_id: node_id.to_string(),
        peer_id: peer_id.to_string(),
        role: role.to_string(),
        state: state.to_string(),
        health_level: health_level.map(ToString::to_string),
        public_listen,
        location,
        last_seen: Some(ts()),
    }
}

pub(super) fn build_dashboard_route(
    from_peer: &PeerId,
    to_peer: &PeerId,
    hops: Vec<String>,
    trusted: bool,
    active: bool,
    latency_ms: Option<u64>,
) -> DashboardRouteInfo {
    DashboardRouteInfo {
        from_peer: from_peer.to_string(),
        to_peer: to_peer.to_string(),
        hops,
        latency_ms,
        trusted,
        active,
        updated_at: ts(),
    }
}

pub(super) fn build_dashboard_log(
    node_id: &str,
    level: &str,
    category: &str,
    message: String,
) -> DashboardLogEvent {
    DashboardLogEvent {
        ts: ts(),
        node_id: node_id.to_string(),
        level: level.to_string(),
        message: message.clone(),
        event: format!("[{}][{}] {} | node={}", level, category, message, node_id),
    }
}

pub(super) async fn dashboard_emit(
    dashboard_tx: Option<&mpsc::Sender<DashboardBridgeInput>>,
    input: DashboardBridgeInput,
) {
    if let Some(tx) = dashboard_tx {
        let _ = tx.send(input).await;
    }
}

pub(super) async fn publish_dashboard_log(
    dashboard_tx: Option<&mpsc::Sender<DashboardBridgeInput>>,
    node_id: &str,
    level: &str,
    category: &str,
    message: String,
) {
    let log = build_dashboard_log(node_id, level, category, message);
    dashboard_emit(dashboard_tx, DashboardBridgeInput::Log(log)).await;
}

pub(super) async fn publish_dashboard_health(
    dashboard_tx: Option<&mpsc::Sender<DashboardBridgeInput>>,
    health: DashboardNodeHealth,
) {
    dashboard_emit(dashboard_tx, DashboardBridgeInput::NodeHealth(health)).await;
}

pub(super) async fn publish_dashboard_node(
    dashboard_tx: Option<&mpsc::Sender<DashboardBridgeInput>>,
    info: DashboardNodeInfo,
) {
    dashboard_emit(dashboard_tx, DashboardBridgeInput::NodeInfo(info)).await;
}

pub(super) async fn publish_dashboard_route(
    dashboard_tx: Option<&mpsc::Sender<DashboardBridgeInput>>,
    route: DashboardRouteInfo,
) {
    dashboard_emit(dashboard_tx, DashboardBridgeInput::Route(route)).await;
}

pub(super) fn build_health_snapshot(
    node_id: &str,
    role: &str,
    connected_peers: usize,
    known_peers: usize,
    route_peers: usize,
    trusted_peers: usize,
    bootstrap_ok: bool,
    gateway_ok: bool,
    web_ok: bool,
    config_ok: bool,
    last_failure_reason: Option<String>,
) -> GhostHealthSnapshot {
    GhostHealthSnapshot {
        node_id: node_id.to_string(),
        role: role.to_string(),
        connected_peers,
        known_peers,
        route_peers,
        trusted_peers,
        bootstrap_ok,
        gateway_ok,
        web_ok,
        config_ok,
        tamper_detected: false,
        last_failure_reason,
    }
}

pub(super) async fn publish_health(
    ghost_runtime: Option<&GhostRuntimeHandle>,
    snapshot: GhostHealthSnapshot,
) {
    if let Some(rt) = ghost_runtime {
        let _ = rt.health(snapshot).await;
    }
}

pub(super) async fn publish_current_health(
    ghost_runtime: Option<&GhostRuntimeHandle>,
    dashboard_tx: Option<&mpsc::Sender<DashboardBridgeInput>>,
    node_id: &str,
    role: &str,
    connected_peers: usize,
    known_peers: usize,
    route_peers: usize,
    trusted_peers: usize,
    bootstrap_ok: bool,
    gateway_ok: bool,
    web_ok: bool,
    config_ok: bool,
    failure_count: usize,
    last_failure_reason: Option<String>,
    ping_total_ms: u64,
    ping_samples: usize,
    local_peer: &PeerId,
    public_listen: Option<String>,
    location: Option<String>,
) {
    let ghost_snapshot = build_health_snapshot(
        node_id,
        role,
        connected_peers,
        known_peers,
        route_peers,
        trusted_peers,
        bootstrap_ok,
        gateway_ok,
        web_ok,
        config_ok,
        last_failure_reason.clone(),
    );

    publish_health(ghost_runtime, ghost_snapshot).await;

    let dashboard_snapshot = build_dashboard_health_snapshot(
        node_id,
        local_peer,
        role,
        connected_peers,
        known_peers,
        route_peers,
        trusted_peers,
        ping_average_ms(ping_total_ms, ping_samples),
        bootstrap_ok,
        gateway_ok,
        web_ok,
        config_ok,
        failure_count,
        last_failure_reason,
        public_listen.clone(),
        location.clone(),
    );
    publish_dashboard_health(dashboard_tx, dashboard_snapshot.clone()).await;

    let node_state = if bootstrap_ok && config_ok && connected_peers > 0 {
        "Idle"
    } else {
        "Wake"
    };

    let node_info = build_dashboard_node_info(
        node_id,
        local_peer,
        role,
        node_state,
        Some(dashboard_snapshot.health_level.as_str()),
        public_listen,
        location,
    );
    publish_dashboard_node(dashboard_tx, node_info).await;
}

// ===========================================
// Onion Routing Helpers
// ===========================================

pub const ONION_MIN_PADDING: usize = 256;
pub const ONION_DEFAULT_PADDING: usize = 1400;

pub fn pad_onion_payload(payload: Vec<u8>, target_size: usize) -> Vec<u8> {
    let effective_target = if target_size == 0 {
        ONION_DEFAULT_PADDING
    } else {
        target_size.max(ONION_MIN_PADDING)
    };
    onion::pad_payload(&payload, effective_target)
}

pub fn select_onion_hops(
    known_peers: &[PeerId],
    local_id: &PeerId,
    destination: &PeerId,
    n: usize,
) -> Option<Vec<PeerId>> {
    let mut candidates: Vec<PeerId> = known_peers
        .iter()
        .filter(|p| *p != local_id && *p != destination)
        .cloned()
        .collect();
    if candidates.len() < n {
        return None;
    }
    let mut rng = rand::thread_rng();
    candidates.shuffle(&mut rng);
    let mut selected = candidates[..n].to_vec();
    selected.push(*destination);
    Some(selected)
}

pub(crate) fn send_via_onion(
    swarm: &mut Swarm<Behaviour>,
    ctx: &RuntimeContext,
    destination: &PeerId,
    plaintext_payload: Vec<u8>,
    known_peers: &[PeerId],
) {
    if ctx.onion_hops == 0 {
        let direct_req = DirectRequest::plain_bytes(
            swarm.local_peer_id().to_string(),
            destination.to_string(),
            plaintext_payload,
        );
        swarm.behaviour_mut().direct.send_request(destination, direct_req);
        return;
    }

    let padded = pad_onion_payload(plaintext_payload, ctx.onion_payload_size);
    let local_id = *swarm.local_peer_id();

    let hops = match select_onion_hops(known_peers, &local_id, destination, ctx.onion_hops) {
        Some(h) => h,
        None => {
            tracing::warn!("onion: not enough peers, falling back to direct");
            let direct_req = DirectRequest::plain_bytes(
                local_id.to_string(),
                destination.to_string(),
                padded,
            );
            swarm.behaviour_mut().direct.send_request(destination, direct_req);
            return;
        }
    };

    let mut hop_pubkeys: Vec<X25519PublicKey> = Vec::new();
    for peer_id in &hops {
        if let Some(entry) = ctx.peer_pubkey_store.get(peer_id) {
            hop_pubkeys.push(*entry.value());
        } else {
            hop_pubkeys.clear();
            break;
        }
    }

    if hop_pubkeys.is_empty() {
        tracing::warn!("onion: missing pubkeys, falling back to direct");
        let direct_req = DirectRequest::plain_bytes(
            local_id.to_string(),
            destination.to_string(),
            padded,
        );
        swarm.behaviour_mut().direct.send_request(destination, direct_req);
        return;
    }

    // Konversi ke HopInfo untuk build_onion_packet
    let hop_infos: Vec<HopInfo> = hops
        .iter()
        .zip(hop_pubkeys.iter())
        .map(|(peer_id, pk)| HopInfo {
            peer_id: peer_id.to_string(),
            pubkey_b64: B64.encode(pk.as_bytes()),
            activation_cert: String::new(), // [FIX L-18] sementara kosong, verifikasi di‑skip jika authority key None
        })
        .collect();

    // [FIX L-18] Panggil build_onion_packet dengan authority_pubkey dari context
    match onion::build_onion_packet(
        &hop_infos,
        &padded,
        ctx.onion_payload_size,
        ctx.authority_pubkey.as_ref(),
    ) {
        Ok(outer_layer) => {
            let relay_req = OnionRelayRequest {
                layer: outer_layer,
                hop: 0,
            };
            let first_hop = &hops[0];
            let ess_req = EssRequest::OnionRelay(relay_req);
            let body = bincode::serialize(&ess_req).unwrap_or_default();
            let direct = DirectRequest::plain_bytes(
                local_id.to_string(),
                first_hop.to_string(),
                body,
            );
            swarm.behaviour_mut().direct.send_request(first_hop, direct);
            tracing::debug!("onion: message to {} routed via {} hops", destination, hops.len());
        }
        Err(e) => {
            tracing::error!("onion: wrap failed: {:?}, falling back", e);
            let direct_req = DirectRequest::plain_bytes(
                local_id.to_string(),
                destination.to_string(),
                padded,
            );
            swarm.behaviour_mut().direct.send_request(destination, direct_req);
        }
    }
}
