use crate::dashboard::{DashboardStore, LogEvent, NodeHealth, NodeInfo, RouteInfo};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use serde::{Deserialize, Serialize};
use log::{debug, info};

// ── Compute Layer types (NEW) ────────────────────────────────────────────────
use crate::compute::types::ComputeResult;

// ==========================================
// 1. DATA MODELS
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryUpdate {
    pub peer_id: String,
    pub connected_peers: usize,
    pub latency_ms: u64,
}

#[derive(Debug, Clone)]
pub enum DashboardBridgeInput {
    NodeInfo(NodeInfo),
    NodeHealth(NodeHealth),
    Route(RouteInfo),
    Log(LogEvent),
    Telemetry(TelemetryUpdate),
    /// Hasil eksekusi komputasi (job_id, ComputeResult)
    ComputeJobResult(String, ComputeResult),
}

// ==========================================
// 2. BRIDGE HANDLE & CONFIG
// ==========================================

#[derive(Debug, Clone)]
pub struct DashboardBridgeConfig {
    pub channel_capacity: usize,
    pub idle_delay: Duration,
}

impl Default for DashboardBridgeConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 1024,
            idle_delay: Duration::from_millis(0),
        }
    }
}

/// Handle untuk mengendalikan bridge. Dapat di‑clone.
#[derive(Clone)]
pub struct DashboardBridgeHandle {
    tx: mpsc::Sender<DashboardBridgeInput>,
    _join: Arc<JoinHandle<()>>,
}

impl DashboardBridgeHandle {
    pub fn sender(&self) -> mpsc::Sender<DashboardBridgeInput> {
        self.tx.clone()
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    pub fn abort(&self) {
        self._join.abort();
    }
}

// ==========================================
// 3. CORE LOGIC (SPAWNER)
// ==========================================

pub fn spawn_dashboard_bridge(
    store: DashboardStore,
    config: DashboardBridgeConfig,
) -> DashboardBridgeHandle {
    let (tx, mut rx) = mpsc::channel::<DashboardBridgeInput>(config.channel_capacity);

    let _join = Arc::new(tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                DashboardBridgeInput::NodeInfo(info) => {
                    store.upsert_node_info(info).await;
                }
                DashboardBridgeInput::NodeHealth(health) => {
                    store.upsert_node_health(health).await;
                }
                DashboardBridgeInput::Route(route) => {
                    store.push_route(route).await;
                }
                DashboardBridgeInput::Log(log) => {
                    store.push_log(log).await;
                }
                DashboardBridgeInput::Telemetry(update) => {
                    debug!("[BRIDGE] Syncing telemetry for {}", update.peer_id);
                    let mut health = NodeHealth::default();
                    health.peer_id = update.peer_id;
                    health.connected_peers = update.connected_peers;
                    health.ping_ms_avg = Some(update.latency_ms);
                    health.state = "active".to_string();
                    health.health_level = "healthy".to_string();
                    store.upsert_node_health(health).await;
                }
                DashboardBridgeInput::ComputeJobResult(job_id, result) => {
                    info!(
                        "[BRIDGE] Compute job completed: {} in {}ms (fuel: {})",
                        job_id, result.exec_time_ms, result.fuel_consumed
                    );
                }
            }

            if !config.idle_delay.is_zero() {
                tokio::time::sleep(config.idle_delay).await;
            }
        }
    }));

    DashboardBridgeHandle { tx, _join }
}

// ==========================================
// 4. HELPER FUNCTIONS
// ==========================================

pub async fn send_telemetry(
    tx: &mpsc::Sender<DashboardBridgeInput>,
    update: TelemetryUpdate,
) -> Result<(), mpsc::error::SendError<DashboardBridgeInput>> {
    tx.send(DashboardBridgeInput::Telemetry(update)).await
}

pub async fn send_node_info(
    tx: &mpsc::Sender<DashboardBridgeInput>,
    info: NodeInfo,
) -> Result<(), mpsc::error::SendError<DashboardBridgeInput>> {
    tx.send(DashboardBridgeInput::NodeInfo(info)).await
}

pub async fn send_node_health(
    tx: &mpsc::Sender<DashboardBridgeInput>,
    health: NodeHealth,
) -> Result<(), mpsc::error::SendError<DashboardBridgeInput>> {
    tx.send(DashboardBridgeInput::NodeHealth(health)).await
}

pub async fn send_route(
    tx: &mpsc::Sender<DashboardBridgeInput>,
    route: RouteInfo,
) -> Result<(), mpsc::error::SendError<DashboardBridgeInput>> {
    tx.send(DashboardBridgeInput::Route(route)).await
}

pub async fn send_log(
    tx: &mpsc::Sender<DashboardBridgeInput>,
    log: LogEvent,
) -> Result<(), mpsc::error::SendError<DashboardBridgeInput>> {
    tx.send(DashboardBridgeInput::Log(log)).await
}
