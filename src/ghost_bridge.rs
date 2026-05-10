use crate::ghost::{GhostEvent, GhostHandle, GhostState};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use crate::network::runtime::types::TelemetryEvent;

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone)]
pub struct GhostBeaconPacket {
    pub node_id: String,
    pub role: String,
    pub state: GhostState,
    pub fingerprint: String,
    pub connected_peers: usize,
    pub known_peers: usize,
    pub route_peers: usize,
    pub ts: u64,
}

#[derive(Debug, Clone)]
pub struct GhostSyncPacket {
    pub node_id: String,
    pub batch: Vec<String>,
    pub ts: u64,
}

#[derive(Debug, Clone)]
pub struct GhostStatePacket {
    pub node_id: String,
    pub from: GhostState,
    pub to: GhostState,
    pub ts: u64,
}

#[derive(Debug, Clone)]
pub struct GhostPanicPacket {
    pub node_id: String,
    pub reason: String,
    pub ts: u64,
}

#[derive(Debug, Clone)]
pub struct GhostZeroizePacket {
    pub node_id: String,
    pub ts: u64,
}

#[derive(Debug, Clone)]
pub struct GhostLogPacket {
    pub node_id: String,
    pub message: String,
    pub ts: u64,
}

#[derive(Debug, Clone)]
pub struct GhostNetworkPacket {
    pub node_id: String,
    pub event: String,
    pub peer_id: String,
    pub detail: String,
    pub ts: u64,
}

#[derive(Debug, Clone)]
pub struct GhostGatewayPacket {
    pub node_id: String,
    pub kind: String,
    pub detail: String,
    pub ts: u64,
}

#[derive(Debug, Clone)]
pub struct GhostWorldPacket {
    pub node_id: String,
    pub ghost_state: String,
    pub health_level: String,
    pub connected_peers: usize,
    pub known_peers: usize,
    pub route_peers: usize,
    pub ts: u64,
}

#[derive(Debug, Clone)]
pub struct GhostSensorPacket {
    pub node_id: String,
    pub domain: String,
    pub kind: String,
    pub peer_id: Option<String>,
    pub detail: String,
    pub ts: u64,
}

#[derive(Debug)]
pub struct GhostBridgeOutputs {
    pub beacon_tx: Option<mpsc::Sender<GhostBeaconPacket>>,
    pub sync_tx: Option<mpsc::Sender<GhostSyncPacket>>,
    pub state_tx: Option<mpsc::Sender<GhostStatePacket>>,
    pub panic_tx: Option<mpsc::Sender<GhostPanicPacket>>,
    pub zeroize_tx: Option<mpsc::Sender<GhostZeroizePacket>>,
    pub log_tx: Option<mpsc::Sender<GhostLogPacket>>,
    pub network_tx: Option<mpsc::Sender<GhostNetworkPacket>>,
    pub gateway_tx: Option<mpsc::Sender<GhostGatewayPacket>>,
    pub world_tx: Option<mpsc::Sender<GhostWorldPacket>>,
    pub sensor_tx: Option<mpsc::Sender<GhostSensorPacket>>,
    pub telemetry_rx: Option<mpsc::Receiver<TelemetryEvent>>, 
}

impl Default for GhostBridgeOutputs {
    fn default() -> Self {
        Self {
            beacon_tx: None,
            sync_tx: None,
            state_tx: None,
            panic_tx: None,
            zeroize_tx: None,
            log_tx: None,
            network_tx: None,
            gateway_tx: None,
            world_tx: None,
            sensor_tx: None,
            telemetry_rx: None, 
        }
    }
}

#[derive(Debug, Clone)]
pub struct GhostBridgeConfig {
    pub verbose: bool,
    pub forward_state_changes: bool,
    pub forward_logs: bool,
    pub forward_beacons: bool,
    pub forward_sync_batches: bool,
    pub forward_panic: bool,
    pub forward_zeroize: bool,
    pub forward_network_events: bool,
}

impl Default for GhostBridgeConfig {
    fn default() -> Self {
        Self {
            verbose: true,
            forward_state_changes: true,
            forward_logs: true,
            forward_beacons: true,
            forward_sync_batches: true,
            forward_panic: true,
            forward_zeroize: true,
            forward_network_events: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GhostBridgeHandle {
    ghost: GhostHandle,
}

impl GhostBridgeHandle {
    pub async fn wake(&self) -> Result<(), String> { self.ghost.wake().await }
    pub async fn sleep(&self) -> Result<(), String> { self.ghost.sleep().await }
    pub async fn trigger_sync(&self) -> Result<(), String> { self.ghost.trigger_sync().await }
    pub async fn trigger_beacon(&self) -> Result<(), String> { self.ghost.trigger_beacon().await }
    pub async fn panic<S: Into<String>>(&self, reason: S) -> Result<(), String> { self.ghost.panic(reason).await }
    pub async fn zeroize(&self) -> Result<(), String> { self.ghost.zeroize().await }
    pub async fn enqueue_sync<S: Into<String>>(&self, item: S) -> Result<(), String> { self.ghost.enqueue_sync(item).await }
    pub async fn update_metrics(&self, connected_peers: usize, known_peers: usize, route_peers: usize) -> Result<(), String> {
        self.ghost.update_metrics(connected_peers, known_peers, route_peers).await
    }
    pub async fn set_tamper(&self, tamper: bool) -> Result<(), String> { self.ghost.set_tamper(tamper).await }

    pub async fn observe_peer_connected<S: Into<String>>(&self, peer_id: S) -> Result<(), String> {
        let peer_id = peer_id.into();
        self.ghost.observe_signal(format!("bridge:network:peer_connected:{peer_id}")).await?;
        self.ghost.enqueue_sync(format!("network:peer_connected:{peer_id}")).await?;
        self.ghost.trigger_sync().await?;
        Ok(())
    }

    pub async fn observe_peer_disconnected<S: Into<String>>(&self, peer_id: S) -> Result<(), String> {
        let peer_id = peer_id.into();
        self.ghost.observe_signal(format!("bridge:network:peer_disconnected:{peer_id}")).await?;
        self.ghost.enqueue_sync(format!("network:peer_disconnected:{peer_id}")).await?;
        self.ghost.trigger_sync().await?;
        Ok(())
    }

    pub async fn observe_message_failed<S: Into<String>>(&self, reason: S) -> Result<(), String> {
        let reason = reason.into();
        self.ghost.observe_signal(format!("bridge:network:message_failed:{reason}")).await?;
        self.ghost.enqueue_sync(format!("network:message_failed:{reason}")).await?;
        self.ghost.trigger_sync().await?;
        Ok(())
    }

    pub async fn observe_gateway_traffic<S: Into<String>>(&self, detail: S) -> Result<(), String> {
        let detail = detail.into();
        self.ghost.observe_signal(format!("bridge:gateway:{detail}")).await?;
        self.ghost.enqueue_sync(format!("gateway:traffic:{detail}")).await?;
        self.ghost.trigger_beacon().await?;
        Ok(())
    }

    pub async fn observe_world_state<S: Into<String>>(&self, detail: S) -> Result<(), String> {
        let detail = detail.into();
        self.ghost.observe_signal(format!("bridge:world:{detail}")).await?;
        Ok(())
    }

    pub async fn execute_dashboard_command(&self, cmd: &str) -> Result<(), String> {
        match cmd {
            "wake" => self.wake().await,
            "sleep" => self.sleep().await,
            "sync" => self.trigger_sync().await,
            "beacon" => self.trigger_beacon().await,
            "zeroize" => self.zeroize().await,
            _ if cmd.starts_with("panic:") => self.panic(&cmd[6..]).await,
            _ if cmd.starts_with("tamper:") => self.set_tamper(cmd.ends_with("true")).await,
            _ if cmd.starts_with("observe_peer:") => self.observe_peer_connected(&cmd[13..]).await,
            _ if cmd.starts_with("drop_peer:") => self.observe_peer_disconnected(&cmd[10..]).await,
            _ if cmd.starts_with("fail_msg:") => self.observe_message_failed(&cmd[9..]).await,
            _ if cmd.starts_with("gateway:") => self.observe_gateway_traffic(&cmd[8..]).await,
            _ if cmd.starts_with("world:") => self.observe_world_state(&cmd[6..]).await,
            _ if cmd.starts_with("enqueue:") => self.enqueue_sync(&cmd[8..]).await,
            _ if cmd.starts_with("metrics:") => self.update_metrics(0, 0, 0).await,
            _ => Ok(())
        }
    }
}

fn log_line(enabled: bool, level: &str, message: impl AsRef<str>) {
    if enabled {
        println!("[GHOST][{}] {}", level, message.as_ref());
    }
}

fn log_event(enabled: bool, level: &str, node_id: &str, message: impl AsRef<str>) {
    if enabled {
        println!("[GHOST][{}] node={} {}", level, node_id, message.as_ref());
    }
}

async fn send_if_some<T>(tx: &Option<mpsc::Sender<T>>, value: T) {
    if let Some(sender) = tx {
        let _ = sender.send(value).await;
    }
}

fn classify_signal(message: &str) -> (&'static str, &'static str, Option<String>) {
    if let Some(peer) = message.strip_prefix("network:peer_connected:") {
        return ("network_controller", "peer_connected", Some(peer.to_string()));
    }
    if let Some(peer) = message.strip_prefix("network:peer_disconnected:") {
        return ("network_controller", "peer_disconnected", Some(peer.to_string()));
    }
    if let Some(reason) = message.strip_prefix("network:message_failed:") {
        return ("network_controller", "message_failed", Some(reason.to_string()));
    }
    if let Some(detail) = message.strip_prefix("gateway:traffic:") {
        return ("gateway", "traffic", Some(detail.to_string()));
    }
    if message.starts_with("ghost:") || message.starts_with("bridge:world:") {
        return ("world_state", "state", None);
    }
    ("world_state", "signal", None)
}

async fn publish_state(outputs: &GhostBridgeOutputs, verbose: bool, node_id: String, from: GhostState, to: GhostState, ts: u64) {
    let packet = GhostStatePacket { node_id, from, to, ts };
    log_event(verbose, "STATE", &packet.node_id, format!("{} -> {} [ts:{}]", packet.from, packet.to, packet.ts));
    send_if_some(&outputs.state_tx, packet).await;
}

async fn publish_beacon(outputs: &GhostBridgeOutputs, verbose: bool, node_id: String, role: String, state: GhostState, fingerprint: String, connected_peers: usize, known_peers: usize, route_peers: usize, ts: u64) {
    let packet = GhostBeaconPacket { node_id: node_id.clone(), role, state, fingerprint, connected_peers, known_peers, route_peers, ts };
    log_event(verbose, "BEACON", &packet.node_id, format!("role={} state={} fp={} connected={} known={} route={} [ts:{}]", packet.role, packet.state, packet.fingerprint, packet.connected_peers, packet.known_peers, packet.route_peers, packet.ts));

    let world = GhostWorldPacket {
        node_id,
        ghost_state: packet.state.to_string(),
        health_level: if matches!(packet.state, GhostState::Panic) { "critical".to_string() } else if matches!(packet.state, GhostState::Sleep) { "sleeping".to_string() } else { "active".to_string() },
        connected_peers: packet.connected_peers,
        known_peers: packet.known_peers,
        route_peers: packet.route_peers,
        ts: packet.ts,
    };

    send_if_some(&outputs.beacon_tx, packet).await;
    send_if_some(&outputs.world_tx, world).await;
}

async fn publish_sync(outputs: &GhostBridgeOutputs, verbose: bool, node_id: String, batch: Vec<String>, ts: u64) {
    let packet = GhostSyncPacket { node_id, batch, ts };
    log_event(verbose, "SYNC", &packet.node_id, format!("items={} [ts:{}]", packet.batch.len(), packet.ts));
    send_if_some(&outputs.sync_tx, packet).await;
}

async fn publish_panic(outputs: &GhostBridgeOutputs, verbose: bool, node_id: String, reason: String, ts: u64) {
    let packet = GhostPanicPacket { node_id, reason, ts };
    log_event(verbose, "PANIC", &packet.node_id, format!("reason={} [ts:{}]", packet.reason, packet.ts));
    send_if_some(&outputs.panic_tx, packet).await;
}

async fn publish_zeroize(outputs: &GhostBridgeOutputs, verbose: bool, node_id: String, ts: u64) {
    let packet = GhostZeroizePacket { node_id, ts };
    log_event(verbose, "ZEROIZED", &packet.node_id, format!("done [ts:{}]", packet.ts));
    send_if_some(&outputs.zeroize_tx, packet).await;
}

async fn publish_log(outputs: &GhostBridgeOutputs, verbose: bool, node_id: String, message: String, ts: u64) {
    let packet = GhostLogPacket { node_id, message, ts };
    log_event(verbose, "LOG", &packet.node_id, format!("{} [ts:{}]", packet.message, packet.ts));
    send_if_some(&outputs.log_tx, packet).await;
}

async fn publish_network(outputs: &GhostBridgeOutputs, verbose: bool, node_id: String, event: String, peer_id: String, detail: String, ts: u64) {
    let packet = GhostNetworkPacket { node_id, event, peer_id, detail, ts };
    log_event(verbose, "NET", &packet.node_id, format!("event={} peer={} detail={} [ts:{}]", packet.event, packet.peer_id, packet.detail, packet.ts));
    send_if_some(&outputs.network_tx, packet).await;
}

async fn publish_gateway(outputs: &GhostBridgeOutputs, verbose: bool, node_id: String, kind: String, detail: String, ts: u64) {
    let packet = GhostGatewayPacket { node_id, kind, detail, ts };
    log_event(verbose, "GATEWAY", &packet.node_id, format!("kind={} detail={} [ts:{}]", packet.kind, packet.detail, packet.ts));
    send_if_some(&outputs.gateway_tx, packet).await;
}

async fn publish_world(outputs: &GhostBridgeOutputs, verbose: bool, node_id: String, state: String, health_level: String, connected_peers: usize, known_peers: usize, route_peers: usize, ts: u64) {
    let packet = GhostWorldPacket { node_id, ghost_state: state, health_level, connected_peers, known_peers, route_peers, ts };
    log_event(verbose, "WORLD", &packet.node_id, format!("state={} health={} connected={} known={} route={} [ts:{}]", packet.ghost_state, packet.health_level, packet.connected_peers, packet.known_peers, packet.route_peers, packet.ts));
    send_if_some(&outputs.world_tx, packet).await;
}

async fn publish_sensor(outputs: &GhostBridgeOutputs, verbose: bool, node_id: String, domain: &'static str, kind: &'static str, peer_id: Option<String>, detail: String, ts: u64) {
    let packet = GhostSensorPacket { node_id, domain: domain.to_string(), kind: kind.to_string(), peer_id, detail, ts };
    let peer_display = packet.peer_id.as_deref().unwrap_or("-");
    log_event(verbose, "SENSOR", &packet.node_id, format!("domain={} kind={} peer={} detail={} [ts:{}]", packet.domain, packet.kind, peer_display, packet.detail, packet.ts));
    send_if_some(&outputs.sensor_tx, packet).await;
}

pub fn spawn_ghost_bridge(
    ghost: GhostHandle,
    mut events: mpsc::Receiver<GhostEvent>,
    mut outputs: GhostBridgeOutputs,
    config: GhostBridgeConfig,
) -> GhostBridgeHandle {
    let handle = GhostBridgeHandle { ghost };
    
    let mut telemetry_rx = outputs.telemetry_rx.take();

    let boot_handle = handle.clone();
    tokio::spawn(async move {
        let _ = boot_handle.execute_dashboard_command("metrics:").await;
    });

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(event) = events.recv() => {
                    match event {
                        GhostEvent::StateChanged { node_id, from, to } => {
                            if config.forward_state_changes {
                                publish_state(&outputs, config.verbose, node_id.clone(), from, to, unix_ts()).await;
                            }
                            publish_sensor(&outputs, config.verbose, node_id, "world_state", "state_changed", None, format!("{from}->{to}"), unix_ts()).await;
                        }
                        GhostEvent::Beacon { node_id, role, state, fingerprint, connected_peers, known_peers, route_peers, ts } => {
                            if config.forward_beacons {
                                publish_beacon(&outputs, config.verbose, node_id.clone(), role.clone(), state, fingerprint.clone(), connected_peers, known_peers, route_peers, ts).await;
                            }
                            publish_sensor(&outputs, config.verbose, node_id, "world_state", "beacon", None, format!("role={role} fp={fingerprint}"), ts).await;
                        }
                        GhostEvent::SyncBatch { node_id, batch, ts } => {
                            if config.forward_sync_batches {
                                publish_sync(&outputs, config.verbose, node_id.clone(), batch.clone(), ts).await;
                            }
                            publish_sensor(&outputs, config.verbose, node_id, "world_state", "sync_batch", None, format!("items={}", batch.len()), ts).await;
                        }
                        GhostEvent::Panic { node_id, reason, ts } => {
                            if config.forward_panic {
                                publish_panic(&outputs, config.verbose, node_id.clone(), reason.clone(), ts).await;
                            }
                            publish_sensor(&outputs, config.verbose, node_id, "world_state", "panic", None, reason, ts).await;
                        }
                        GhostEvent::Zeroized { node_id, ts } => {
                            if config.forward_zeroize {
                                publish_zeroize(&outputs, config.verbose, node_id.clone(), ts).await;
                            }
                            publish_sensor(&outputs, config.verbose, node_id, "world_state", "zeroized", None, "zeroized".to_string(), ts).await;
                        }
                        GhostEvent::Log { node_id, message, ts } => {
                            if config.forward_logs {
                                publish_log(&outputs, config.verbose, node_id.clone(), message.clone(), ts).await;
                            }
                            let (domain, kind, peer_id) = classify_signal(&message);
                            match domain {
                                "network_controller" => {
                                    if config.forward_network_events {
                                        publish_network(&outputs, config.verbose, node_id.clone(), kind.to_string(), peer_id.clone().unwrap_or_default(), message.clone(), ts).await;
                                    }
                                }
                                "gateway" => {
                                    publish_gateway(&outputs, config.verbose, node_id.clone(), kind.to_string(), message.clone(), ts).await;
                                }
                                _ => {
                                    publish_world(&outputs, config.verbose, node_id.clone(), "observed".to_string(), "active".to_string(), 0, 0, 0, ts).await;
                                }
                            }
                            publish_sensor(&outputs, config.verbose, node_id, domain, kind, peer_id, message, ts).await;
                        }
                    }
                }

                Some(telemetry) = async {
                    if let Some(rx) = telemetry_rx.as_mut() {
                        rx.recv().await
                    } else {
                        futures::future::pending().await 
                    }
                } => {
                    match telemetry {
                        TelemetryEvent::HighLatency { peer, latency } => {
                            log_line(config.verbose, "TELEMETRY", format!("Peer {} latency is too high: {:?}", peer, latency));
                        }
                        TelemetryEvent::RoutingFailed(peer) => {
                            log_line(config.verbose, "TELEMETRY", format!("Route to peer {} dropped!", peer));
                        }
                        TelemetryEvent::PeerConnected(_) => {
                            log_line(config.verbose, "TELEMETRY", "Ghost sensor: Peer connected");
                        }
                        TelemetryEvent::PeerDisconnected(_) => {
                            log_line(config.verbose, "TELEMETRY", "Ghost sensor: Peer disconnected");
                        }
                    }
                }
            }
        }
    });

    handle
}

