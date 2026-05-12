use chrono::Utc;
use std::sync::Arc;

use crate::authority::{AuthorityManager, AuthorityState};
use crate::network_controller::NetworkController;
use crate::security_runtime::{PolicyConfig, SecurityRuntime};
use crate::world_state::{SharedWorldState, WorldStateSnapshot};

// ── Compute imports (PATCH #7) ────────────────────────────────────────
use crate::compute::scheduler::ComputeSchedulerHandle;
use crate::compute::store::ComputeStore;

use super::model::{DashboardSummary, LogEvent, NodeHealth, NodeInfo, RouteInfo};
use super::store::DashboardStore;

#[derive(Debug, Clone)]
pub struct DashboardService {
    store: DashboardStore,
    world_state: Option<SharedWorldState>,
    security: Option<Arc<SecurityRuntime>>,
    authority: Option<AuthorityManager>,
    controller: Option<Arc<NetworkController>>,
    compute_handle: Option<ComputeSchedulerHandle>,   // NEW
    compute_store: Option<Arc<ComputeStore>>,          // NEW
}

impl DashboardService {
    pub fn new(store: DashboardStore) -> Self {
        Self {
            store,
            world_state: None,
            security: None,
            authority: None,
            controller: None,
            compute_handle: None,   // NEW
            compute_store: None,    // NEW
        }
    }

    pub fn with_world_state(mut self, world_state: SharedWorldState) -> Self {
        self.world_state = Some(world_state);
        self
    }

    pub fn with_security(mut self, security: Arc<SecurityRuntime>) -> Self {
        self.security = Some(security);
        self
    }

    pub fn with_authority(mut self, authority: AuthorityManager) -> Self {
        self.authority = Some(authority);
        self
    }

    pub fn with_controller(mut self, controller: Arc<NetworkController>) -> Self {
        self.controller = Some(controller);
        self
    }

    // ── Setter untuk compute layer (PATCH #7) ─────────────────────────
    pub fn with_compute(
        mut self,
        handle: ComputeSchedulerHandle,
        store: Arc<ComputeStore>,
    ) -> Self {
        self.compute_handle = Some(handle);
        self.compute_store = Some(store);
        self
    }

    pub fn store(&self) -> DashboardStore {
        self.store.clone()
    }

    // ── Getter untuk compute layer (PATCH #7) ─────────────────────────
    pub fn compute_handle(&self) -> Result<&ComputeSchedulerHandle, String> {
        self.compute_handle
            .as_ref()
            .ok_or_else(|| "compute not available".to_string())
    }

    pub fn compute_store(&self) -> Result<&Arc<ComputeStore>, String> {
        self.compute_store
            .as_ref()
            .ok_or_else(|| "compute store not available".to_string())
    }

    // ── Compute capacity (untuk dashboard) ──────────────────────────
    pub fn compute_capacity(&self) -> Result<serde_json::Value, String> {
        let handle = self.compute_handle()?;
        let cap = crate::compute::network::NodeCapacity::current(
            &self
                .controller
                .as_ref()
                .ok_or("no controller")?
                .local_peer_id
                .to_string(),
            handle,
        );
        Ok(serde_json::to_value(cap).unwrap_or_default())
    }

    // ── Compute store stats ─────────────────────────────────────────
    pub fn compute_store_stats(&self) -> Result<serde_json::Value, String> {
        let store = self.compute_store()?;
        let queue_depth = store.queue_depth();
        let result_count = store.result_count();
        Ok(serde_json::json!({
            "queue_depth": queue_depth,
            "result_count": result_count
        }))
    }

    // ── Compute database stats ──────────────────────────────────────
    pub fn compute_db_stats(&self) -> Result<serde_json::Value, String> {
        let store = self.compute_store()?;
        Ok(store.db_stats())
    }

    pub fn world_snapshot(&self) -> Option<WorldStateSnapshot> {
        self.world_state
            .as_ref()
            .and_then(|ws| ws.read().ok().map(|guard| guard.snapshot()))
    }

    // --- policy info (untuk dashboard) ---
    pub fn policy_status(&self) -> Result<PolicyConfig, String> {
        self.security
            .as_ref()
            .map(|s| s.policy_status())
            .ok_or_else(|| "Security runtime not available".to_string())
    }

    pub fn export_policy_rules(&self) -> Result<String, String> {
        self.security
            .as_ref()
            .ok_or_else(|| "Security runtime not available".to_string())?
            .export_policy_rules()
            .map_err(|e| e.to_string())
    }

    pub fn reload_policy(&self) -> Result<(), String> {
        let path = "data/policy_inner.toml";
        self.security
            .as_ref()
            .ok_or_else(|| "Security runtime not available".to_string())?
            .reload_policy(path)
            .map_err(|e| e.to_string())
    }

    // 🔥 Authority Snapshot
    pub fn get_authority_state(&self) -> Result<AuthorityState, String> {
        self.authority
            .as_ref()
            .ok_or_else(|| "Authority manager not available".to_string())?
            .get_snapshot()
            .map_err(|e| e.to_string())
    }

    // 🔥 Kirim direct message – adaptor string‑to‑Vec<u8> untuk API HTTP
    pub async fn send_direct_message(
        &self,
        peer_id: libp2p::PeerId,
        message: String,
    ) -> Result<String, String> {
        let ctrl = self
            .controller
            .as_ref()
            .ok_or_else(|| "NetworkController not attached".to_string())?;
        ctrl.send_direct_message(peer_id, message.into_bytes())
            .await
            .map(|body| String::from_utf8_lossy(&body).to_string())
            .map_err(|e| e.to_string())
    }

    // ----------------------------------------------------------------
    // summary() – versi final yang defensif
    // ----------------------------------------------------------------
    pub async fn summary(&self) -> DashboardSummary {
        let nodes = self.store.all_nodes().await;

        let mut supernodes = 0usize;
        let mut relays = 0usize;
        let mut clients = 0usize;
        let mut healthy_nodes = 0usize;
        let mut degraded_nodes = 0usize;
        let mut critical_nodes = 0usize;
        let mut connected_peers = 0usize;
        let mut known_peers = 0usize;
        let mut route_peers = 0usize;
        let mut trusted_peers = 0usize;

        let mut from_world = false;

        // Sumber kebenaran utama: peer_registry pada WorldState
        if let Some(world_state) = &self.world_state {
            if let Ok(ws) = world_state.read() {
                // Hanya gunakan WorldState jika registry sudah terisi (tidak kosong)
                if !ws.peer_registry.is_empty() {
                    known_peers = ws.peer_registry.len();
                    connected_peers = ws.peer_registry.values().filter(|p| p.connected).count();
                    route_peers = ws
                        .peer_registry
                        .values()
                        .filter(|p| p.connected && !p.routes.is_empty())
                        .count();
                    trusted_peers = ws
                        .peer_registry
                        .values()
                        .filter(|p| p.connected && p.trusted)
                        .count();

                    // Hitung role per peer online, dengan normalisasi defensif
                    for peer in ws.peer_registry.values() {
                        if !peer.connected {
                            continue;
                        }
                        // Normalisasi role untuk mencocokkan: lowercase, tanpa spasi
                        let normalized = peer
                            .role
                            .as_deref()
                            .map(|r| r.trim().to_ascii_lowercase())
                            .unwrap_or_default();

                        match normalized.as_str() {
                            "supernode" => supernodes += 1,
                            "relay" => relays += 1,
                            "client" => clients += 1,
                            _ => {} // role lain diabaikan atau bisa ditambahkan di masa depan
                        }
                    }
                    from_world = true;
                }
            }
        }

        // Fallback ke DashboardStore hanya jika WorldState belum siap/registry kosong
        if !from_world {
            for node in &nodes {
                match node.role.trim().to_ascii_lowercase().as_str() {
                    "supernode" => supernodes += 1,
                    "relay" => relays += 1,
                    "client" => clients += 1,
                    _ => {}
                }
            }
        }

        // Health/status node selalu diambil dari projection store
        for node in &nodes {
            match node
                .health_level
                .as_deref()
                .unwrap_or("unknown")
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "healthy" => healthy_nodes += 1,
                "degraded" => degraded_nodes += 1,
                "critical" => critical_nodes += 1,
                _ => {}
            }

            // Metrik koneksi dari store hanya digunakan saat fallback (agar tidak overcount)
            if !from_world {
                if let Some(health) = self.store.node_health(&node.key()).await {
                    // Asumsi: metrik dalam NodeHealth adalah per-node, bukan agregat global
                    connected_peers += health.connected_peers;
                    known_peers += health.known_peers;
                    route_peers += health.route_peers;
                    trusted_peers += health.trusted_peers;
                }
            }
        }

        let status = if critical_nodes > 0 {
            "critical"
        } else if degraded_nodes > 0 {
            "degraded"
        } else if healthy_nodes > 0 {
            "healthy"
        } else {
            "unknown"
        };

        DashboardSummary {
            total_nodes: nodes.len(),
            supernodes,
            relays,
            clients,
            healthy_nodes,
            degraded_nodes,
            critical_nodes,
            connected_peers,
            known_peers,
            route_peers,
            trusted_peers,
            updated_at: Utc::now().to_rfc3339(),
            status: status.to_string(),
        }
    }

    pub async fn nodes(&self) -> Vec<NodeInfo> {
        self.store.all_nodes().await
    }

    pub async fn node_detail(&self, node_id: &str) -> Option<NodeHealth> {
        self.store.node_health(node_id).await
    }

    pub async fn routes(&self) -> Vec<RouteInfo> {
        self.store.routes().await
    }

    pub async fn logs(
        &self,
        limit: usize,
        level: Option<&str>,
        node_id: Option<&str>,
    ) -> Vec<LogEvent> {
        let mut items = self.store.logs().await;

        if let Some(level) = level {
            let wanted = level.trim().to_ascii_lowercase();
            if !wanted.is_empty() {
                items.retain(|log| log.level.trim().to_ascii_lowercase() == wanted);
            }
        }

        if let Some(node_id) = node_id {
            let wanted = node_id.trim();
            if !wanted.is_empty() {
                items.retain(|log| log.node_id == wanted);
            }
        }

        if items.len() > limit {
            items.drain(0..items.len() - limit);
        }

        items
    }
}
