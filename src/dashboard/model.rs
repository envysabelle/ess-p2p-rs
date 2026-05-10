use chrono::Utc;
use serde::{Deserialize, Serialize};

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DashboardSummary {
    pub total_nodes: usize,
    pub supernodes: usize,
    pub relays: usize,
    pub clients: usize,
    pub healthy_nodes: usize,
    pub degraded_nodes: usize,
    pub critical_nodes: usize,
    pub connected_peers: usize,
    pub known_peers: usize,
    pub route_peers: usize,
    pub trusted_peers: usize,
    pub updated_at: String,
    pub status: String,
}

impl DashboardSummary {
    pub fn empty() -> Self {
        Self {
            updated_at: now_rfc3339(),
            status: "unknown".to_string(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeInfo {
    pub node_id: String,
    pub peer_id: String,
    pub role: String,
    pub state: String,
    pub health_level: Option<String>,
    pub public_listen: Option<String>,
    pub location: Option<String>,
    pub last_seen: Option<String>,
}

impl NodeInfo {
    pub fn key(&self) -> String {
        if !self.node_id.trim().is_empty() {
            self.node_id.clone()
        } else {
            self.peer_id.clone()
        }
    }

    pub fn from_health(health: &NodeHealth) -> Self {
        Self {
            node_id: health.node_id.clone(),
            peer_id: health.peer_id.clone(),
            role: health.role.clone(),
            state: health.state.clone(),
            health_level: Some(health.health_level.clone()),
            public_listen: health.public_listen.clone(),
            location: health.location.clone(),
            last_seen: Some(health.updated_at.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeHealth {
    pub node_id: String,
    pub peer_id: String,
    pub role: String,
    pub state: String,
    pub health_level: String,
    pub decision: String,
    pub reason: String,
    pub connected_peers: usize,
    pub known_peers: usize,
    pub route_peers: usize,
    pub trusted_peers: usize,
    pub ping_ms_avg: Option<u64>,
    pub bootstrap_ok: bool,
    pub gateway_ok: bool,
    pub web_ok: bool,
    pub config_ok: bool,
    pub tamper_detected: bool,
    pub failure_count: usize,
    pub last_failure_reason: Option<String>,
    pub updated_at: String,
    pub public_listen: Option<String>,
    pub location: Option<String>,
}

impl NodeHealth {
    pub fn from_info(info: &NodeInfo) -> Self {
        Self {
            node_id: info.node_id.clone(),
            peer_id: info.peer_id.clone(),
            role: info.role.clone(),
            state: info.state.clone(),
            health_level: info
                .health_level
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            decision: "noop".to_string(),
            reason: "snapshot_only".to_string(),
            connected_peers: 0,
            known_peers: 0,
            route_peers: 0,
            trusted_peers: 0,
            ping_ms_avg: None,
            bootstrap_ok: false,
            gateway_ok: false,
            web_ok: false,
            config_ok: false,
            tamper_detected: false,
            failure_count: 0,
            last_failure_reason: None,
            updated_at: info.last_seen.clone().unwrap_or_else(now_rfc3339),
            public_listen: info.public_listen.clone(),
            location: info.location.clone(),
        }
    }

    pub fn key(&self) -> String {
        if !self.node_id.trim().is_empty() {
            self.node_id.clone()
        } else {
            self.peer_id.clone()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteInfo {
    pub from_peer: String,
    pub to_peer: String,
    pub hops: Vec<String>,
    pub latency_ms: Option<u64>,
    pub trusted: bool,
    pub active: bool,
    pub updated_at: String,
}

impl RouteInfo {
    pub fn new(from_peer: impl Into<String>, to_peer: impl Into<String>) -> Self {
        Self {
            from_peer: from_peer.into(),
            to_peer: to_peer.into(),
            hops: Vec::new(),
            latency_ms: None,
            trusted: false,
            active: true,
            updated_at: now_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogEvent {
    pub ts: String,
    pub node_id: String,
    pub level: String,
    pub event: String,
    pub message: String,
}
