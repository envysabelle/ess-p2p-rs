// src/network/runtime/events.rs
use crate::gateway::GatewayResponse;
use crate::web::{WebResponse, ServiceRecord, ServiceRegistry, parse_ess_uri, can_publish_service};
use crate::config::{ConfigBundle, ConfigRequest, ConfigResponse};
use crate::message::{DirectRequest, DirectResponse};
use crate::network::runtime::types::{Event, OnboardResponse, PeerEntry, TelemetryEvent};
use crate::network::util::{inc_connection_count, dec_connection_count, is_public, register_peer_addr};
use crate::network_controller::NetworkController;
use crate::security_runtime::{self, SecurityRuntime};
use crate::system_event::{SystemEvent, SystemEventKind};
use crate::dashboard_bridge::DashboardBridgeInput;
use crate::dashboard::{NodeHealth, NodeInfo};
use crate::authority::Action;
use crate::network::runtime::governance;
use crate::crdt_state;
use crate::storage_layer::protocol::StorageResponse;   // sudah tidak unused karena dipakai di Storage handler

// Onion imports
use crate::onion::peel_onion_layer;
use crate::message::{EssRequest, EssResponse, OnionRelayRequest, OnionRelayResponse};
use super::runner::RuntimeContext;
use crate::pqc;
use crate::governance::messages::{
    ProposalType, ProposalAnnouncement, VoteMessage, ActivationCertificate,
};

// Compute imports (PATCH #2)
use crate::compute::network;

use chrono::Utc;
use futures::StreamExt;
use hex;
use libp2p::request_response::{self, Message as RequestResponseMessage};
use libp2p::swarm::SwarmEvent;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::mpsc;
use log::{info, warn, debug};
use x25519_dalek::PublicKey as X25519PublicKey;
use parking_lot::Mutex;

// Runtime State
#[derive(Default)]
struct RuntimeState {
    connected_counts: HashMap<PeerId, usize>,
    known_peers: HashSet<PeerId>,
    seen_addrs: HashMap<PeerId, HashSet<String>>,
    registry: Option<ServiceRegistry>,
}

static RUNTIME_STATE: OnceLock<Mutex<RuntimeState>> = OnceLock::new();
fn runtime_state() -> &'static Mutex<RuntimeState> {
    RUNTIME_STATE.get_or_init(|| Mutex::new(RuntimeState::default()))
}

fn _prime_internal_modules() {
    let _ = crate::network::runtime::support::ts;
    let _ = crate::network::runtime::support::ping_average_ms;
    let _ = crate::network::runtime::support::dashboard_health_level;
    let _ = crate::network::runtime::support::build_dashboard_health_snapshot;
    let _ = crate::network::runtime::support::build_dashboard_node_info;
    let _ = crate::network::runtime::support::build_dashboard_route;
    let _ = crate::network::runtime::support::build_dashboard_log;
    let _ = crate::network::runtime::support::publish_dashboard_log;
    let _ = crate::network::runtime::support::publish_dashboard_health;
    let _ = crate::network::runtime::support::publish_dashboard_node;
    let _ = crate::network::runtime::support::publish_dashboard_route;
    let _ = crate::network::runtime::support::build_health_snapshot;
    let _ = crate::network::runtime::support::publish_health;
    let _ = crate::network::runtime::support::publish_current_health;
    let _ = crate::network::runtime::PROTOCOL_VERSION;
    let _ = crate::network::runtime::DIRECT_PROTOCOL;
    let _ = crate::network::runtime::CONFIG_PROTOCOL;
    let _ = crate::network::runtime::GATEWAY_PROTOCOL;
    let _ = crate::network::runtime::WEB_PROTOCOL;
    let _ = TelemetryEvent::PeerConnected(());
    let _ = TelemetryEvent::PeerDisconnected(());
    let _ = TelemetryEvent::HighLatency { peer: PeerId::random(), latency: Duration::from_secs(1) };
    let _ = TelemetryEvent::RoutingFailed(PeerId::random());
}

// Event Loop
pub async fn run_event_loop(
    controller: Arc<NetworkController>,
    security: Arc<SecurityRuntime>,
    _telemetry_tx: mpsc::Sender<TelemetryEvent>,
    dashboard_tx: mpsc::Sender<DashboardBridgeInput>,
    ctx: RuntimeContext,
) -> Result<(), Box<dyn Error>> {
    info!("[PIPELINE] Autonomous Event Loop Active. All Perimeters Secured.");
    _prime_internal_modules();

    if let Some(ws_arc) = controller.world_state() {
        let ws = ws_arc.read().unwrap();
        for (peer_id, pk) in &ws.peer_x25519_pubkeys {
            ctx.peer_pubkey_store.insert(*peer_id, *pk);
        }
        info!("[ONION] Preloaded {} X25519 pubkeys into context", ctx.peer_pubkey_store.len());
    }

    loop {
        let swarm_opt = {
            let handle = controller.swarm_handle();
            let mut guard = handle.lock();
            guard.take()
        };

        match swarm_opt {
            Some(mut swarm) => {
                let event = swarm.select_next_some().await;
                {
                    let handle = controller.swarm_handle();
                    let mut guard = handle.lock();
                    guard.replace(swarm);
                }
                handle_event(&controller, &security, &dashboard_tx, event, &ctx).await;
            }
            None => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

// Handler Utama
async fn handle_event(
    controller: &Arc<NetworkController>,
    security: &Arc<SecurityRuntime>,
    dashboard_tx: &mpsc::Sender<DashboardBridgeInput>,
    event: SwarmEvent<Event>,
    ctx: &RuntimeContext,
) {
    match event {
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            let peer_id_str = peer_id.to_string();
            {
                let mut state = runtime_state().lock();
                state.known_peers.insert(peer_id);
                inc_connection_count(&mut state.connected_counts, peer_id);
            }
            controller.consume_event(SystemEvent::new("network", SystemEventKind::PeerConnected { peer_id })).await;

            let ws_arc = match controller.world_state() {
                Some(ws) => ws,
                None => {
                    warn!("[NETWORK] WorldState not attached for {}", peer_id_str);
                    sync_with_world(controller, dashboard_tx).await;
                    return;
                }
            };

            if let Some(pk) = {
                let ws = ws_arc.read().unwrap();
                ws.peer_x25519_pubkeys.get(&peer_id).copied()
            } {
                ctx.peer_pubkey_store.insert(peer_id, pk);
            }

            let (role_str, current_trusted) = {
                let ws = ws_arc.read().unwrap();
                let role = if ws.authority.supernodes.iter().any(|p| p == &peer_id_str) {
                    "supernode".to_string()
                } else {
                    "peer".to_string()
                };
                let trusted = ws.peer_registry.get(&peer_id_str).map(|p| p.trusted);
                (role, trusted)
            };

            controller.update_world_state(|ws| {
                ws.upsert_peer_state(peer_id_str.clone(), Some(role_str.clone()), true, current_trusted.or(Some(false)));
            });

            if let Some(crdt) = controller.crdt_world() {
                let mut crdt_guard = crdt.write().await;
                crdt_guard.update_peer(peer_id_str.clone(), role_str.clone(), true, false);
            }

            if !controller.enforce_peer(&peer_id).await {
                {
                    let mut state = runtime_state().lock();
                    dec_connection_count(&mut state.connected_counts, peer_id);
                }
                controller.update_world_state(|ws| {
                    ws.set_peer_connected(&peer_id_str, false);
                });
                return;
            }

            {
                let peer_id_str_clone = peer_id_str.clone();
                controller.update_world_state(move |ws| {
                    ws.add_route(&peer_id_str_clone, &peer_id_str_clone);
                });
            }

            let snap = controller.world_snapshot();
            let (connected, known, route, trusted) = snap
                .as_ref()
                .map(|s| (s.connected_peers, s.known_peers, s.route_peers, s.trusted_peers))
                .unwrap_or((0, 0, 0, 0));

            let _ = dashboard_tx.send(DashboardBridgeInput::NodeInfo(NodeInfo {
                node_id: peer_id_str.clone(),
                peer_id: peer_id_str.clone(),
                role: role_str.clone(),
                state: "online".to_string(),
                health_level: Some("healthy".to_string()),
                last_seen: Some(Utc::now().to_rfc3339()),
                ..Default::default()
            })).await;

            let _ = dashboard_tx.send(DashboardBridgeInput::NodeHealth(NodeHealth {
                node_id: peer_id_str.clone(),
                peer_id: peer_id_str.clone(),
                role: role_str,
                state: "online".to_string(),
                health_level: "healthy".to_string(),
                connected_peers: connected,
                known_peers: known,
                route_peers: route,
                trusted_peers: trusted,
                updated_at: Utc::now().to_rfc3339(),
                ..Default::default()
            })).await;

            sync_with_world(controller, dashboard_tx).await;

            if let Some(ws_arc) = controller.world_state() {
                let activated = ws_arc.read().unwrap().is_peer_activated(&peer_id_str);
                if !activated {
                    let ctrl = controller.clone();
                    let target = peer_id;
                    tokio::spawn(async move {
                        if let Err(e) = crate::onboarding::send_onboarding_request(&ctrl, target).await {
                            tracing::warn!("[AUTO-ONBOARD] Gagal onboarding {}: {}", target, e);
                        } else {
                            tracing::info!("[AUTO-ONBOARD] Sukses onboarding peer {}", target);
                        }
                    });
                }
            }
        }

        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            let peer_id_str = peer_id.to_string();
            {
                let mut state = runtime_state().lock();
                dec_connection_count(&mut state.connected_counts, peer_id);
            }
            controller.consume_event(SystemEvent::new("network", SystemEventKind::PeerDisconnected { peer_id })).await;

            let ws_arc = match controller.world_state() {
                Some(ws) => ws,
                None => {
                    warn!("[NETWORK] WorldState not attached for {}", peer_id_str);
                    sync_with_world(controller, dashboard_tx).await;
                    return;
                }
            };

            let role_str = {
                let ws = ws_arc.read().unwrap();
                if ws.authority.supernodes.iter().any(|p| p == &peer_id_str) {
                    "supernode".to_string()
                } else {
                    "peer".to_string()
                }
            };

            controller.update_world_state(|ws| {
                ws.set_peer_connected(&peer_id_str, false);
                ws.set_peer_trusted(&peer_id_str, false);
                ws.remove_route(&peer_id_str, &peer_id_str);
            });

            let snap = controller.world_snapshot();
            let (connected, known, route, trusted) = snap
                .as_ref()
                .map(|s| (s.connected_peers, s.known_peers, s.route_peers, s.trusted_peers))
                .unwrap_or((0, 0, 0, 0));

            let _ = dashboard_tx.send(DashboardBridgeInput::NodeHealth(NodeHealth {
                node_id: peer_id_str.clone(),
                peer_id: peer_id_str.clone(),
                role: role_str,
                state: "offline".to_string(),
                health_level: "degraded".to_string(),
                connected_peers: connected,
                known_peers: known,
                route_peers: route,
                trusted_peers: trusted,
                updated_at: Utc::now().to_rfc3339(),
                ..Default::default()
            })).await;

            sync_with_world(controller, dashboard_tx).await;
        }

        SwarmEvent::Behaviour(Event::Identify(ev)) => {
            if let libp2p::identify::Event::Received { peer_id, info, .. } = ev {
                let public_key = info.public_key.clone();
                governance::register_peer_on_discovery(security, &peer_id, public_key);
                let peer_id_str = peer_id.to_string();

                if let Some(ws) = controller.world_state() {
                    let role = {
                        let ws_guard = ws.read().unwrap();
                        if ws_guard.authority.supernodes.iter().any(|p| p == &peer_id_str) {
                            Some("supernode".to_string())
                        } else {
                            Some("peer".to_string())
                        }
                    };

                    controller.update_world_state(|ws| {
                        ws.upsert_peer_state(peer_id_str.clone(), role.clone(), true, None);
                    });

                    let snap = controller.world_snapshot();
                    let (connected, known, route, trusted) = snap
                        .as_ref()
                        .map(|s| (s.connected_peers, s.known_peers, s.route_peers, s.trusted_peers))
                        .unwrap_or((0, 0, 0, 0));

                    let _ = dashboard_tx.send(DashboardBridgeInput::NodeInfo(NodeInfo {
                        node_id: peer_id_str.clone(),
                        peer_id: peer_id_str.clone(),
                        role: role.clone().unwrap_or_else(|| "peer".into()),
                        state: "online".to_string(),
                        health_level: Some("healthy".to_string()),
                        last_seen: Some(Utc::now().to_rfc3339()),
                        ..Default::default()
                    })).await;

                    let _ = dashboard_tx.send(DashboardBridgeInput::NodeHealth(NodeHealth {
                        node_id: peer_id_str.clone(),
                        peer_id: peer_id_str.clone(),
                        role: role.unwrap_or_else(|| "peer".into()),
                        state: "online".to_string(),
                        health_level: "healthy".to_string(),
                        connected_peers: connected,
                        known_peers: known,
                        route_peers: route,
                        trusted_peers: trusted,
                        updated_at: Utc::now().to_rfc3339(),
                        ..Default::default()
                    })).await;
                } else {
                    warn!("[IDENTIFY] WorldState not attached for {}", peer_id_str);
                }

                let handle = controller.swarm_handle();
                let mut guard = handle.lock();
                if let Some(swarm) = guard.as_mut() {
                    let mut state = runtime_state().lock();
                    let mut touched = false;
                    for addr in info.listen_addrs {
                        if is_public(&addr) {
                            register_peer_addr(swarm, &mut state.seen_addrs, peer_id, &addr);
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                            touched = true;
                        }
                    }
                    if touched {
                        let result = swarm.behaviour_mut().kademlia.bootstrap();
                        info!("[KAD] Bootstrap triggered for peer {}. Result: {:?}", peer_id, result);
                    }
                }
                drop(guard);

                info!("[IDENTIFY] Sending config sync to peer {}", peer_id);
                send_config_sync(controller, security, peer_id).await;
            }
        }

        SwarmEvent::Behaviour(Event::Gateway(ev)) => {
            if let request_response::Event::Message { peer, message, .. } = ev {
                let local = controller.local_peer_id;
                match message {
                    RequestResponseMessage::Request { request, channel, .. } => {
                        if let Err(e) = security.verify_signature_format(&request.signature) {
                            warn!("[GATEWAY] Bad signature format from {}: {}", peer, e);
                            let resp = GatewayResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "bad_signature_format");
                            let handle = controller.swarm_handle();
                            let mut guard = handle.lock();
                            if let Some(swarm) = guard.as_mut() {
                                let _ = swarm.behaviour_mut().gateway.send_response(channel, resp);
                            }
                            return;
                        }

                        if !controller.enforce(&peer, Action::GatewayAccess).await {
                            warn!("[GATEWAY] Authority denied access to {}", peer);
                            let resp = GatewayResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "access_denied_by_authority");
                            let handle = controller.swarm_handle();
                            let mut guard = handle.lock();
                            if let Some(swarm) = guard.as_mut() {
                                let _ = swarm.behaviour_mut().gateway.send_response(channel, resp);
                            }
                            return;
                        }

                        let mut is_allowed = false;
                        let mut status = 403;
                        let mut msg = "denied";

                        if security.verify_gateway_request(local, peer, &request).is_ok() {
                            let rate_limit = controller.check_gateway_rate_limit(&peer);
                            if rate_limit.allowed {
                                if controller.enforce_gateway_peer(&peer).await {
                                    is_allowed = true; status = 200; msg = "gateway_ok";
                                }
                            } else { status = 429; msg = "rate_limited"; }
                        } else { status = 401; msg = "invalid_signature"; }

                        let audit = request.audit_entry(peer.to_string(), is_allowed, Some(status), msg.to_string());
                        controller.record_gateway_audit(audit).await;

                        let resp = if is_allowed {
                            security.build_gateway_response_ok(local, peer, &request.message_id, status, vec![], msg).unwrap_or_else(|_| GatewayResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "internal_error"))
                        } else {
                            security.build_gateway_response_error(local, peer, &request.message_id, status, msg).unwrap_or_else(|_| GatewayResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "internal_error"))
                        };

                        let handle = controller.swarm_handle();
                        let mut guard = handle.lock();
                        if let Some(swarm) = guard.as_mut() {
                            let _ = swarm.behaviour_mut().gateway.send_response(channel, resp);
                        }
                    }
                    RequestResponseMessage::Response { response, .. } => {
                        match security.verify_gateway_response(local, peer, &response) {
                            Ok(verified) => info!("[GATEWAY] Verified response from {}: status={}", peer, verified.status),
                            Err(e) => warn!("[GATEWAY] Response verification failed for {}: {:?}", peer, e),
                        }
                    }
                }
            }
        }

        SwarmEvent::Behaviour(Event::Web(ev)) => {
            if let request_response::Event::Message { peer, message, .. } = ev {
                let local = controller.local_peer_id;
                match message {
                    RequestResponseMessage::Request { request, channel, .. } => {
                        if let Err(e) = security.verify_signature_format(&request.signature) {
                            warn!("[WEB] Bad signature format from {}: {}", peer, e);
                            let resp = WebResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), 400, "bad_signature_format");
                            let handle = controller.swarm_handle();
                            let mut guard = handle.lock();
                            if let Some(swarm) = guard.as_mut() {
                                let _ = swarm.behaviour_mut().web.send_response(channel, resp);
                            }
                            return;
                        }

                        let _uri = parse_ess_uri(&request.url);

                        if let Some(auth_mgr) = controller.get_authority() {
                            let namespace = _uri.as_ref().map(|u| u.namespace.as_str()).unwrap_or("core");
                            if !crate::web::is_supported_namespace(namespace) {
                                warn!("[WEB] Unsupported namespace '{}' from peer {}", namespace, peer);
                                let resp = crate::web::WebResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), 400, "unsupported_namespace");
                                let handle = controller.swarm_handle();
                                let mut guard = handle.lock();
                                if let Some(swarm) = guard.as_mut() {
                                    let _ = swarm.behaviour_mut().web.send_response(channel, resp);
                                }
                                return;
                            }
                            if !can_publish_service(&auth_mgr, &peer, namespace) {
                                warn!("[WEB] Peer {} not authorized to publish in namespace '{}'", peer, namespace);
                            }
                        }

                        let resp = if security.verify_web_request(local, peer, &request).is_ok() && controller.enforce(&peer, Action::WebTraffic).await {
                            security.build_web_response_ok(local, peer, &request.message_id, 200, "text/plain", vec![], "web_ok").unwrap_or_else(|_| WebResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), 500, "error"))
                        } else {
                            security.build_web_response_error(local, peer, &request.message_id, 401, "unauthorized").unwrap_or_else(|_| WebResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), 401, "unauthorized"))
                        };

                        let handle = controller.swarm_handle();
                        let mut guard = handle.lock();
                        if let Some(swarm) = guard.as_mut() {
                            let _ = swarm.behaviour_mut().web.send_response(channel, resp);
                        }
                    }
                    RequestResponseMessage::Response { response, .. } => {
                        match security.verify_web_response(local, peer, &response) {
                            Ok(verified) => info!("[WEB] Verified response from {}: status={}, content-type={}", peer, verified.status, verified.content_type),
                            Err(e) => warn!("[WEB] Response verification failed for {}: {:?}", peer, e),
                        }
                    }
                }
            }
        }

        SwarmEvent::Behaviour(Event::Config(ev)) => {
            if let request_response::Event::Message { peer, message, .. } = ev {
                let local = controller.local_peer_id;
                match message {
                    RequestResponseMessage::Request { request, channel, .. } => {
                        if let Err(e) = security.verify_signature_format(&request.signature) {
                            warn!("[CONFIG] Bad signature format from {}: {}", peer, e);
                            let resp = ConfigResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "bad_signature_format");
                            let handle = controller.swarm_handle();
                            let mut guard = handle.lock();
                            if let Some(swarm) = guard.as_mut() {
                                let _ = swarm.behaviour_mut().config.send_response(channel, resp);
                            }
                            return;
                        }

                        if !controller.enforce(&peer, Action::Connect).await {
                            warn!("[CONFIG] Authority denied config request from {}", peer);
                            let resp = ConfigResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "unauthorized");
                            let handle = controller.swarm_handle();
                            let mut guard = handle.lock();
                            if let Some(swarm) = guard.as_mut() {
                                let _ = swarm.behaviour_mut().config.send_response(channel, resp);
                            }
                            return;
                        }

                        let (allowed, bootstrap) = {
                            if let Some(ws_arc) = controller.world_state() {
                                let ws = ws_arc.read().unwrap();
                                let allowed = ws.peer_registry.keys().cloned().collect::<Vec<_>>();
                                let bootstrap = ws.authority.supernodes.clone();
                                (allowed, bootstrap)
                            } else {
                                (vec![], vec![])
                            }
                        };

                        let bundle = ConfigBundle {
                            role: security.current_role().as_str().to_string(),
                            policy_version: 1,
                            allowed_peers: allowed,
                            bootstrap_addrs: bootstrap,
                            issued_at: security_runtime::now_secs(),
                        }.normalized();

                        let resp = if security.verify_config_request(local, peer, &request).is_ok() {
                            security.build_config_response_ok(local, peer, &request.message_id, bundle)
                                .unwrap_or_else(|_| ConfigResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "error"))
                        } else {
                            security.build_config_response_error(local, peer, &request.message_id, "verification_failed")
                                .unwrap_or_else(|_| ConfigResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "error"))
                        };

                        let handle = controller.swarm_handle();
                        let mut guard = handle.lock();
                        if let Some(swarm) = guard.as_mut() {
                            let _ = swarm.behaviour_mut().config.send_response(channel, resp);
                        }
                    }
                    RequestResponseMessage::Response { response, .. } => {
                        match security.verify_config_response(local, peer, &response) {
                            Ok(bundle) => {
                                info!("[CONFIG] Config sync response verified from {}: policy_version={}", peer, bundle.policy_version);
                                if let Err(e) = security.apply_bundle(&bundle) {
                                    warn!("[CONFIG] Failed to apply config bundle: {}", e);
                                }
                            }
                            Err(e) => warn!("[CONFIG] Config response verification failed for {}: {:?}", peer, e),
                        }
                    }
                }
            }
        }

        // Direct (Governance, CRDT, Onion relay)
        SwarmEvent::Behaviour(Event::Direct(ev)) => {
            match ev {
                request_response::Event::Message { peer, message, .. } => {
                    let local = controller.local_peer_id;
                    match message {
                        RequestResponseMessage::Request { request, channel, .. } => {
                            if let Ok(ess_req) = bincode::deserialize::<EssRequest>(&request.body) {
                                match ess_req {
                                    EssRequest::DirectRequest(direct) => {
                                        let body = direct.body;
                                        handle_direct_request(controller, security, dashboard_tx, &peer, &request, channel, &body).await;
                                    }
                                    EssRequest::OnionRelay(relay) => {
                                        handle_onion_relay(controller, security, &relay, channel, ctx).await;
                                    }
                                }
                            } else {
                                if let Err(e) = security.verify_signature_format(&request.signature) {
                                    warn!("[DIRECT] Bad signature format from {}: {}", peer, e);
                                    let resp = DirectResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "bad_signature_format");
                                    let handle = controller.swarm_handle();
                                    let mut guard = handle.lock();
                                    if let Some(swarm) = guard.as_mut() {
                                        let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
                                    }
                                    return;
                                }

                                if !controller.enforce(&peer, Action::Connect).await {
                                    warn!("[DIRECT] Authority denied direct message from {}", peer);
                                    let resp = DirectResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "access_denied_by_authority");
                                    let handle = controller.swarm_handle();
                                    let mut guard = handle.lock();
                                    if let Some(swarm) = guard.as_mut() {
                                        let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
                                    }
                                    return;
                                }

                                handle_direct_request(controller, security, dashboard_tx, &peer, &request, channel, &request.body).await;
                            }
                        }
                        RequestResponseMessage::Response { request_id, response } => {
                            controller.complete_pending_direct_request(request_id, response);
                        }
                    }
                }
                _ => {}
            }
        }

        // Onboard
        SwarmEvent::Behaviour(Event::Onboard(ev)) => {
            if let request_response::Event::Message { peer, message, .. } = ev {
                match message {
                    RequestResponseMessage::Request { request, channel, .. } => {
                        let ws_arc = match controller.world_state() {
                            Some(ws) => ws,
                            None => {
                                warn!("[ONBOARD] WorldState not attached to controller, cannot verify onboarding.");
                                let response = OnboardResponse {
                                    accepted: false,
                                    reason: Some("WorldState not available".into()),
                                    known_peers: vec![],
                                };
                                let handle = controller.swarm_handle();
                                let mut guard = handle.lock();
                                if let Some(swarm) = guard.as_mut() {
                                    let _ = swarm.behaviour_mut().onboard.send_response(channel, response);
                                }
                                return;
                            }
                        };

                        // Patch 10d: Gunakan write lock untuk handle_peer_identified
                        let mut world_state_guard = ws_arc.write().unwrap();
                        let accepted = governance::handle_peer_identified(
                            security,
                            &mut world_state_guard,
                            &peer,
                            request.serial_number,
                            request.signature,
                            request.public_key,
                            request.nonce,
                            request.timestamp,
                            request.x25519_pubkey.clone(),
                        );
                        drop(world_state_guard); // write lock dilepas setelah selesai

                        if let Some(pk_hex) = &request.x25519_pubkey {
                            if let Ok(pk_bytes) = hex::decode(pk_hex) {
                                if pk_bytes.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&pk_bytes);
                                    let pk = X25519PublicKey::from(arr);
                                    if let Some(ws_arc) = controller.world_state() {
                                        ws_arc.write().unwrap().register_peer_pubkey(peer, pk);
                                    }
                                    ctx.peer_pubkey_store.insert(peer, pk);
                                    info!("[ONBOARD] X25519 pubkey stored for peer {}", peer);
                                }
                            }
                        }

                        if accepted {
                            let peer_str = peer.to_string();
                            let proposal_id = {
                                let mut gov = controller.governance_engine.write().unwrap();
                                gov.create_proposal(
                                    ProposalType::ActivatePeer(peer_str.clone()),
                                    &peer_str,
                                )
                            };

                            let announce = ProposalAnnouncement {
                                proposal_id: proposal_id.clone(),
                                proposer: controller.local_peer_id.to_string(),
                                proposal_type: ProposalType::ActivatePeer(peer_str.clone()),
                                target: peer_str.clone(),
                                supernode_count_at_creation: controller.governance_engine.read().unwrap().supernode_count(),
                                timestamp: security_runtime::now_secs(),
                            };
                            let announce_bytes = bincode::serialize(&announce).unwrap_or_default();
                            let local_id = controller.local_peer_id.to_string();
                            if let Some(auth) = controller.get_authority() {
                                for sn in &auth.get().supernodes {
                                    if *sn == local_id { continue; }
                                    if let Ok(sn_peer) = sn.parse::<PeerId>() {
                                        let mut req = DirectRequest::plain_bytes(
                                            local_id.clone(),
                                            sn.to_string(),
                                            announce_bytes.clone(),
                                        );
                                        req.kind = "governance.announce".to_string();
                                        let req_bytes = bincode::serialize(&req).unwrap_or_default();
                                        let _ = controller.send_direct_message(sn_peer, req_bytes).await;
                                    }
                                }
                            }

                            let vote = VoteMessage {
                                proposal_id: proposal_id.clone(),
                                voter: controller.local_peer_id.to_string(),
                                approve: true,
                                nonce: security_runtime::random_nonce(),
                                timestamp: security_runtime::now_secs(),
                                signature: String::new(),
                            };
                            let sig = controller.get_security().unwrap().sign_governance_payload(
                                &format!("{}:{}:{}:{}:{}", vote.proposal_id, vote.voter, vote.approve, vote.nonce, vote.timestamp)
                            ).unwrap();
                            let signed_vote = VoteMessage { signature: sig, ..vote };
                            let vote_bytes = bincode::serialize(&signed_vote).unwrap_or_default();

                            {
                                let mut gov = controller.governance_engine.write().unwrap();
                                let _ = gov.record_vote(&proposal_id, &signed_vote.voter, signed_vote.approve);
                            }

                            if let Some(auth) = controller.get_authority() {
                                for sn in &auth.get().supernodes {
                                    if *sn == local_id { continue; }
                                    if let Ok(sn_peer) = sn.parse::<PeerId>() {
                                        let mut req = DirectRequest::plain_bytes(
                                            local_id.clone(),
                                            sn.to_string(),
                                            vote_bytes.clone(),
                                        );
                                        req.kind = "governance.vote".to_string();
                                        let req_bytes = bincode::serialize(&req).unwrap_or_default();
                                        let _ = controller.send_direct_message(sn_peer, req_bytes).await;
                                    }
                                }
                            }

                            {
                                let gov = controller.governance_engine.read().unwrap();
                                if let Some(approved) = gov.check_quorum(&proposal_id, 600) {
                                    if approved {
                                        let signers: Vec<String> = if let Some(prop) = gov.get_proposal(&proposal_id) {
                                            prop.votes.iter().filter(|(_, &v)| v).map(|(pid, _)| pid.clone()).collect()
                                        } else {
                                            vec![]
                                        };

                                        let cert = ActivationCertificate {
                                            proposal_id: proposal_id.clone(),
                                            target: peer_str.clone(),
                                            approved: true,
                                            signers: signers.clone(),
                                        };
                                        let cert_data = serde_json::to_vec(&cert).unwrap_or_default();

                                        // 🔥 PATCH 5: Simpan sertifikat aktivasi ke world state
                                        controller.update_world_state(|ws| {
                                            ws.mark_peer_activated(&peer_str);
                                            if let Some(peer_entry) = ws.peer_registry.get_mut(&peer_str) {
                                                peer_entry.activation_cert = Some(cert_data.clone());
                                            }
                                        });

                                        info!("[GOVERNANCE] Peer {} activated by consensus. Signers: {:?}", peer_str, signers);
                                        let ctrl = controller.clone();
                                        let target_peer = peer;

                                        // ✅ Patch 4: Kirim notifikasi aktivasi langsung ke peer target
                                        let notif_cert = cert.clone();
                                        tokio::spawn(async move {
                                            ctrl.send_activation_notification(target_peer, notif_cert).await;
                                            ctrl.publish_verified_peer(target_peer, cert_data).await;
                                        });
                                    }
                                    drop(gov);
                                    controller.governance_engine.write().unwrap().mark_executed(&proposal_id);
                                }
                            }
                        }

                        let known_peers_list: Vec<PeerEntry> = {
                            let state = runtime_state().lock();
                            state.seen_addrs.iter()
                                .filter(|(pid, _)| **pid != peer)
                                .flat_map(|(pid, addrs)| {
                                    addrs.iter().take(1).map(move |addr| PeerEntry {
                                        peer_id: pid.to_string(),
                                        addr: addr.clone(),
                                    })
                                })
                                .collect()
                        };

                        let response = if accepted {
                            OnboardResponse {
                                accepted: true,
                                reason: Some("Awaiting governance consensus".into()),
                                known_peers: known_peers_list,
                            }
                        } else {
                            OnboardResponse {
                                accepted: false,
                                reason: Some("Onboarding verification failed".into()),
                                known_peers: vec![],
                            }
                        };

                        let handle = controller.swarm_handle();
                        let mut guard = handle.lock();
                        if let Some(swarm) = guard.as_mut() {
                            let _ = swarm.behaviour_mut().onboard.send_response(channel, response);
                        }
                    }
                    RequestResponseMessage::Response { request_id, response } => {
                        if !response.known_peers.is_empty() {
                            let peers = response.known_peers.clone();
                            let ctrl = controller.clone();
                            info!("[PEER-EXCHANGE] Received {} peers, scheduling auto-connect with 300ms delay...", peers.len());
                            tokio::spawn(async move {
                                for entry in peers {
                                    ctrl.dial_peer_addr(&entry.addr);
                                    tokio::time::sleep(Duration::from_millis(300)).await;
                                }
                            });
                        }
                        controller.complete_onboard_response(request_id, response);
                    }
                }
            }
        }

        // ── Storage handler (DIPERBAIKI) ──
        SwarmEvent::Behaviour(Event::Storage(ev)) => {
            if let request_response::Event::Message { peer, message, .. } = ev {
                match message {
                    RequestResponseMessage::Request { request, channel, .. } => {
                        if !controller.enforce(&peer, Action::Connect).await {
                            let resp = StorageResponse::Error { message: "access denied".into() };
                            let handle = controller.swarm_handle();
                            let mut guard = handle.lock();
                            if let Some(swarm) = guard.as_mut() {
                                let _ = swarm.behaviour_mut().storage.send_response(channel, resp);
                            }
                            return;
                        }

                        if let Some(storage) = controller.get_storage_layer() {
                            let response = storage.handle_request(request, &peer.to_string()).await;
                            let handle = controller.swarm_handle();
                            let mut guard = handle.lock();
                            if let Some(swarm) = guard.as_mut() {
                                let _ = swarm.behaviour_mut().storage.send_response(channel, response);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Kademlia
        SwarmEvent::Behaviour(Event::Kademlia(kad_event)) => {
            use libp2p::kad::{Event as KadEvent, InboundRequest};
            use crate::kad_store::KadPersistence;
            use std::env;

            match kad_event {
                KadEvent::InboundRequest { request: InboundRequest::PutRecord { record, .. } } => {
                    if let Some(rec) = record {
                        let store_path = env::var("KAD_STORE_PATH").unwrap_or_else(|_| "data/kad_store".to_string());
                        match KadPersistence::open(&store_path) {
                            Ok(persist) => {
                                persist.save_record(&rec);
                                debug!("[KAD] Record persisted: key={}", hex::encode(rec.key.as_ref()));
                            }
                            Err(e) => warn!("[KAD] Failed to open KadPersistence for save: {}", e),
                        }
                    }
                }
                KadEvent::InboundRequest { request: InboundRequest::GetRecord { .. } } => {
                    debug!("[KAD] Incoming GetRecord request processed by MemoryStore.");
                }
                KadEvent::RoutingUpdated { peer, .. } => {
                    debug!("[KAD] Routing table updated for peer: {}", peer);
                }
                KadEvent::OutboundQueryProgressed { result, .. } => {
                    use libp2p::kad::QueryResult;
                    match result {
                        QueryResult::Bootstrap(Ok(boot)) => {
                            info!("[KAD] Bootstrap progress: peer={:?}", boot.peer);
                        }
                        QueryResult::Bootstrap(Err(e)) => {
                            warn!("[KAD] Bootstrap failed: {:?}", e);
                        }
                        QueryResult::PutRecord(Err(e)) => {
                            warn!("[KAD] PutRecord failed: {:?}. Removing stale key from persistence.", e);
                            let store_path = std::env::var("KAD_STORE_PATH").unwrap_or_else(|_| "data/kad_store".to_string());
                            if let Ok(persist) = KadPersistence::open(&store_path) {
                                persist.remove_record(&e.key());
                                debug!("[KAD] Stale key removed: {}", hex::encode(e.key().as_ref()));
                            }
                        }
                        QueryResult::PutRecord(Ok(ok)) => {
                            debug!("[KAD] PutRecord success: key={}", hex::encode(ok.key.as_ref()));
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        _ => {}
    }
}

// == Fungsi direct request (dengan binary body) ==
async fn handle_direct_request(
    controller: &Arc<NetworkController>,
    security: &Arc<SecurityRuntime>,
    _dashboard_tx: &mpsc::Sender<DashboardBridgeInput>,
    peer: &PeerId,
    request: &DirectRequest,
    channel: libp2p::request_response::ResponseChannel<DirectResponse>,
    body: &[u8],
) {
    let local = controller.local_peer_id;

    if request.kind == "crdt_sync" {
        if let Some(crdt) = controller.crdt_world() {
            let remote_state_result = bincode::deserialize::<crdt_state::CrdtSyncMessage>(body)
                .map(|msg| {
                    tracing::debug!("[CRDT] Received sync from node={} ts={}", msg.from_node, msg.ts);
                    msg.state
                })
                .or_else(|_| crdt_state::CrdtWorldState::from_sync_payload(body));

            match remote_state_result {
                Ok(remote_state) => {
                    let our_payload = {
                        let mut our_state = crdt.write().await;
                        our_state.merge(&remote_state);
                        tracing::info!("[CRDT] Merged state from {}", peer);
                        let payload = our_state.to_sync_payload();
                        if let Ok(json) = serde_json::to_vec(&*our_state) {
                            let _ = std::fs::write("data/crdt_state.json", &json);
                        }
                        payload
                    };

                    let resp = DirectResponse::plain_ok_bytes(&request.message_id, &local.to_string(), &peer.to_string(), our_payload);
                    let handle = controller.swarm_handle();
                    let mut guard = handle.lock();
                    if let Some(swarm) = guard.as_mut() {
                        let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
                    }
                }
                Err(e) => {
                    warn!("[CRDT] Failed to parse sync payload: {}", e);
                    let resp = DirectResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "crdt_sync_parse_failed");
                    let handle = controller.swarm_handle();
                    let mut guard = handle.lock();
                    if let Some(swarm) = guard.as_mut() {
                        let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
                    }
                }
            }
        }
        return;
    }

    if request.kind == "governance.vote" {
        if let Ok(vote) = bincode::deserialize::<VoteMessage>(body) {
            if security.verify_governance_vote(&vote, peer).is_ok() {
                let is_supernode = controller.get_authority()
                    .map(|auth| auth.get().supernodes.contains(&vote.voter))
                    .unwrap_or(false);
                if !is_supernode {
                    warn!("[GOVERNANCE] Vote from non-supernode {} rejected", vote.voter);
                } else {
                    let mut gov = controller.governance_engine.write().unwrap();
                    if gov.record_vote(&vote.proposal_id, &vote.voter, vote.approve).is_ok() {
                        if let Some(approved) = gov.check_quorum(&vote.proposal_id, 600) {
                            gov.mark_executed(&vote.proposal_id);
                            if approved {
                                let (target, signers) = if let Some(prop) = gov.get_proposal(&vote.proposal_id) {
                                    let signers: Vec<String> = prop.votes.iter().filter(|(_, &v)| v).map(|(pid, _)| pid.clone()).collect();
                                    (prop.target.clone(), signers)
                                } else {
                                    (String::new(), vec![])
                                };
                                if !target.is_empty() {
                                    let cert = ActivationCertificate {
                                        proposal_id: vote.proposal_id.clone(),
                                        target: target.clone(),
                                        approved: true,
                                        signers: signers.clone(),
                                    };
                                    let cert_data = serde_json::to_vec(&cert).unwrap_or_default();

                                    // 🔥 PATCH 5: Simpan sertifikat aktivasi ke world state
                                    controller.update_world_state(|ws| {
                                        ws.mark_peer_activated(&target);
                                        if let Some(peer_entry) = ws.peer_registry.get_mut(&target) {
                                            peer_entry.activation_cert = Some(cert_data.clone());
                                        }
                                    });

                                    info!("[GOVERNANCE] Peer {} activated by consensus. Signers: {:?}", target, signers);
                                    let ctrl = controller.clone();
                                    if let Ok(pid) = target.parse::<PeerId>() {
                                        let notif_cert = cert.clone();
                                        tokio::spawn(async move {
                                            ctrl.send_activation_notification(pid, notif_cert).await;
                                            ctrl.publish_verified_peer(pid, cert_data).await;
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                warn!("[GOVERNANCE] Invalid vote signature from {}", peer);
            }
        }
        let ack_resp = DirectResponse::plain_ok(&request.message_id, &local.to_string(), &peer.to_string(), "ack");
        let handle = controller.swarm_handle();
        let mut guard = handle.lock();
        if let Some(swarm) = guard.as_mut() {
            let _ = swarm.behaviour_mut().direct.send_response(channel, ack_resp);
        }
        return;
    }

    // ✅ Handler untuk governance.activation_notify
    if request.kind == "governance.activation_notify" {
        if let Ok(cert) = bincode::deserialize::<ActivationCertificate>(body) {
            info!("[GOVERNANCE] Received activation notification: {:?}", cert);
            // Perbarui state lokal
            controller.update_world_state(|ws| {
                ws.mark_peer_activated(&cert.target);
                ws.set_peer_role(&cert.target, "client");
            });
        }
        let ack = DirectResponse::plain_ok(&request.message_id, &local.to_string(), &peer.to_string(), "activated");
        let handle = controller.swarm_handle();
        let mut guard = handle.lock();
        if let Some(swarm) = guard.as_mut() {
            let _ = swarm.behaviour_mut().direct.send_response(channel, ack);
        }
        return;
    }

    if request.kind == "governance.announce" {
        if let Ok(announce) = bincode::deserialize::<ProposalAnnouncement>(body) {
            let mut gov = controller.governance_engine.write().unwrap();
            if gov.get_proposal(&announce.proposal_id).is_none() {
                gov.create_proposal(announce.proposal_type, &announce.target);
            }
        }
        let ack_resp = DirectResponse::plain_ok(&request.message_id, &local.to_string(), &peer.to_string(), "ack");
        let handle = controller.swarm_handle();
        let mut guard = handle.lock();
        if let Some(swarm) = guard.as_mut() {
            let _ = swarm.behaviour_mut().direct.send_response(channel, ack_resp);
        }
        return;
    }

    if request.kind == "pqc_handshake" {
        if let Ok(their_pubkey) = bincode::deserialize::<pqc::HybridPublicKey>(body) {
            match pqc::encapsulate(&their_pubkey, &peer.to_string()) {
                Ok((ciphertext, _session_key)) => {
                    info!("[PQC] Handshake encapsulated for peer {}", peer);
                    let ct_bin = bincode::serialize(&ciphertext).unwrap_or_default();
                    let resp = DirectResponse::plain_ok_bytes(&request.message_id, &local.to_string(), &peer.to_string(), ct_bin);
                    let handle = controller.swarm_handle();
                    let mut guard = handle.lock();
                    if let Some(swarm) = guard.as_mut() {
                        let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
                    }
                }
                Err(e) => {
                    warn!("[PQC] Encapsulation failed for {}: {}", peer, e);
                    let resp = DirectResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "pqc_encap_failed");
                    let handle = controller.swarm_handle();
                    let mut guard = handle.lock();
                    if let Some(swarm) = guard.as_mut() {
                        let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
                    }
                }
            }
        } else {
            warn!("[PQC] Invalid HybridPublicKey from {}", peer);
        }
        return;
    }

    // ── Compute message handler (PATCH #2 – updated untuk parameter store) ─
    if request.kind == "compute" {
        let handle_opt = controller.get_compute_handle();
        if let Some(scheduler) = handle_opt {
            let store_opt = controller.get_compute_store();
            let reply = network::handle_incoming_compute_message(
                body,
                &peer.to_string(),
                &scheduler,
                store_opt.as_deref(),
            ).await;

            let reply_bytes = match reply {
                Some(msg) => serde_json::to_vec(&msg).unwrap_or_default(),
                None => b"{\"status\":\"processed\"}".to_vec(),
            };
            let resp = DirectResponse::plain_ok_bytes(
                &request.message_id,
                &local.to_string(),
                &peer.to_string(),
                reply_bytes,
            );
            let handle = controller.swarm_handle();
            let mut guard = handle.lock();
            if let Some(swarm) = guard.as_mut() {
                let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
            }
            return;
        } else {
            let resp = DirectResponse::plain_error(
                &request.message_id,
                &local.to_string(),
                &peer.to_string(),
                "compute_not_available",
            );
            let handle = controller.swarm_handle();
            let mut guard = handle.lock();
            if let Some(swarm) = guard.as_mut() {
                let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
            }
            return;
        }
    }

    // fallback direct request
    let resp = if security.verify_direct_request(local, *peer, request).is_ok() {
        if let Ok(config_req) = bincode::deserialize::<ConfigRequest>(body) {
            if let Err(e) = security.verify_config_request(local, *peer, &config_req) {
                warn!("[DIRECT] Embedded ConfigRequest verification failed: {}", e);
                DirectResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "invalid_config_request")
            } else {
                let (allowed, bootstrap) = if let Some(ws_arc) = controller.world_state() {
                    let ws = ws_arc.read().unwrap();
                    (ws.peer_registry.keys().cloned().collect::<Vec<_>>(), ws.authority.supernodes.clone())
                } else {
                    (vec![], vec![])
                };
                let role = security.current_role().as_str().to_string();
                let bundle = ConfigBundle {
                    role,
                    policy_version: 1,
                    allowed_peers: allowed,
                    bootstrap_addrs: bootstrap,
                    issued_at: security_runtime::now_secs(),
                }.normalized();
                let config_resp = security.build_config_response_ok(local, *peer, &config_req.message_id, bundle)
                    .unwrap_or_else(|_| ConfigResponse::plain_error(&config_req.message_id, &local.to_string(), &peer.to_string(), "error"));
                DirectResponse::plain_ok_bytes(&request.message_id, &local.to_string(), &peer.to_string(), bincode::serialize(&config_resp).unwrap_or_default())
            }
        } else {
            security.build_direct_response_ok(local, *peer, &request.message_id, "ack")
                .unwrap_or_else(|_| DirectResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "error"))
        }
    } else {
        security.build_direct_response_error(local, *peer, &request.message_id, "unauthorized")
            .unwrap_or_else(|_| DirectResponse::plain_error(&request.message_id, &local.to_string(), &peer.to_string(), "error"))
    };
    let handle = controller.swarm_handle();
    let mut guard = handle.lock();
    if let Some(swarm) = guard.as_mut() {
        let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
    }
}

// == Fungsi onion relay handler ==
async fn handle_onion_relay(
    controller: &Arc<NetworkController>,
    _security: &Arc<SecurityRuntime>,
    relay: &OnionRelayRequest,
    channel: libp2p::request_response::ResponseChannel<DirectResponse>,
    ctx: &RuntimeContext,
) {
    let local = controller.local_peer_id;

    match peel_onion_layer(&relay.layer, &ctx.local_x25519_sk) {
        Ok((next_hop, inner_payload)) => {
            let relay_resp = OnionRelayResponse {
                success: true,
                error: None,
            };
            let ess_resp = EssResponse::OnionRelay(relay_resp);
            let resp_body = bincode::serialize(&ess_resp).unwrap_or_default();
            let resp = DirectResponse::plain_ok_bytes("", &local.to_string(), "", resp_body);
            {
                let handle = controller.swarm_handle();
                let mut guard = handle.lock();
                if let Some(swarm) = guard.as_mut() {
                    let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
                }
            }

            if next_hop.is_empty() {
                match crate::onion::unpad_payload(&inner_payload) {
                    Ok(original_payload) => {
                        let msg = String::from_utf8_lossy(&original_payload).to_string();
                        tracing::info!("onion: final destination reached, payload: {}", msg);
                    }
                    Err(e) => {
                        tracing::error!("onion: unpad failed at final destination: {:?}", e);
                    }
                }
            } else {
                if let Ok(next_peer) = next_hop.parse::<PeerId>() {
                    let forward_req = OnionRelayRequest {
                        layer: bincode::deserialize(&inner_payload)
                            .expect("onion: invalid layer deserialization"),
                        hop: relay.hop + 1,
                    };
                    let ess_req = EssRequest::OnionRelay(forward_req);
                    let body = bincode::serialize(&ess_req).unwrap_or_default();
                    let direct = DirectRequest::plain_bytes(
                        local.to_string(),
                        next_peer.to_string(),
                        body,
                    );
                    let handle = controller.swarm_handle();
                    let mut guard = handle.lock();
                    if let Some(swarm) = guard.as_mut() {
                        swarm.behaviour_mut().direct.send_request(&next_peer, direct);
                    }
                } else {
                    tracing::error!("onion: invalid next_hop PeerId: {}", next_hop);
                }
            }
        }
        Err(e) => {
            tracing::error!("onion: peel failed: {:?}", e);
            let relay_resp = OnionRelayResponse {
                success: false,
                error: Some(format!("{:?}", e)),
            };
            let ess_resp = EssResponse::OnionRelay(relay_resp);
            let body = bincode::serialize(&ess_resp).unwrap_or_default();
            let resp = DirectResponse::plain_ok_bytes("", &local.to_string(), "", body);
            let handle = controller.swarm_handle();
            let mut guard = handle.lock();
            if let Some(swarm) = guard.as_mut() {
                let _ = swarm.behaviour_mut().direct.send_response(channel, resp);
            }
        }
    }
}

// == Helpers ==
async fn sync_with_world(controller: &Arc<NetworkController>, _dashboard_tx: &mpsc::Sender<DashboardBridgeInput>) {
    let mut state = runtime_state().lock();
    let rec = ServiceRecord::new(
        "ess",
        "node",
        "core",
        controller.local_peer_id.to_string(),
        "system".to_string(),
    ).normalized();

    if let Some(ref mut registry) = state.registry {
        registry.insert_raw(rec);
    } else {
        let mut registry = ServiceRegistry::new();
        registry.insert_raw(rec);
        state.registry = Some(registry);
    }

    if let Some(_ws) = controller.world_snapshot() {
        state.known_peers.insert(controller.local_peer_id);
    }
    controller.push_ghost_sync();
}

async fn send_config_sync(controller: &Arc<NetworkController>, security: &Arc<SecurityRuntime>, peer: PeerId) {
    info!("[CONFIG-SYNC] Entry for peer {}", peer);
    let local = controller.local_peer_id;

    let my_role = security.current_role().as_str();
    let request = match security.build_config_request(local, peer, my_role) {
        Ok(r) => r,
        Err(e) => {
            warn!("[CONFIG-SYNC] Failed to build config request: {}", e);
            return;
        }
    };
    let body = bincode::serialize(&request).unwrap_or_default();
    info!("[CONFIG-SYNC] Sending direct message to {} (body size: {})", peer, body.len());

    match controller.send_direct_message(peer, body).await {
        Ok(response_bytes) => {
            info!("[CONFIG-SYNC] Got response from {} ({} bytes)", peer, response_bytes.len());
            match bincode::deserialize::<ConfigResponse>(&response_bytes) {
                Ok(resp) => match security.verify_config_response(local, peer, &resp) {
                    Ok(bundle) => {
                        info!("[CONFIG-SYNC] Config sync successful with {}", peer);
                        if let Err(e) = security.apply_bundle(&bundle) {
                            warn!("[CONFIG-SYNC] Apply bundle failed: {}", e);
                        } else {
                            info!("[CONFIG-SYNC] Config bundle applied successfully.");
                        }
                    }
                    Err(e) => warn!("[CONFIG-SYNC] Config response verification failed: {}", e),
                },
                Err(e) => warn!("[CONFIG-SYNC] Failed to deserialize ConfigResponse: {}", e),
            }
        }
        Err(e) => warn!("[CONFIG-SYNC] send_direct_message failed: {}", e),
    }
}
