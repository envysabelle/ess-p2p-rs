use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;

use super::model::{LogEvent, NodeHealth, NodeInfo, RouteInfo};

#[derive(Debug, Clone, Default)]
pub struct DashboardStore {
    inner: Arc<RwLock<DashboardInner>>,
}

#[derive(Debug, Default)]
struct DashboardInner {
    nodes: HashMap<String, NodeSnapshot>,
    routes: Vec<RouteInfo>,
    logs: Vec<LogEvent>,
}

#[derive(Debug, Clone)]
struct NodeSnapshot {
    info: NodeInfo,
    health: Option<NodeHealth>,
}

impl NodeSnapshot {
    fn merged_info(&self) -> NodeInfo {
        let mut info = self.info.clone();

        if info.node_id.trim().is_empty()
            && !self
                .health
                .as_ref()
                .map(|h| h.node_id.trim().is_empty())
                .unwrap_or(true)
        {
            info.node_id = self.health.as_ref().unwrap().node_id.clone();
        }

        if info.peer_id.trim().is_empty()
            && !self
                .health
                .as_ref()
                .map(|h| h.peer_id.trim().is_empty())
                .unwrap_or(true)
        {
            info.peer_id = self.health.as_ref().unwrap().peer_id.clone();
        }

        if info.role.trim().is_empty()
            && !self
                .health
                .as_ref()
                .map(|h| h.role.trim().is_empty())
                .unwrap_or(true)
        {
            info.role = self.health.as_ref().unwrap().role.clone();
        }

        if info.state.trim().is_empty()
            && !self
                .health
                .as_ref()
                .map(|h| h.state.trim().is_empty())
                .unwrap_or(true)
        {
            info.state = self.health.as_ref().unwrap().state.clone();
        }

        if info.health_level.is_none() {
            info.health_level = self.health.as_ref().map(|h| h.health_level.clone());
        }

        if info.public_listen.is_none() {
            info.public_listen = self.health.as_ref().and_then(|h| h.public_listen.clone());
        }

        if info.location.is_none() {
            info.location = self.health.as_ref().and_then(|h| h.location.clone());
        }

        if info.last_seen.is_none() {
            info.last_seen = self.health.as_ref().map(|h| h.updated_at.clone());
        }

        info
    }

    fn merged_health(&self) -> NodeHealth {
        match &self.health {
            Some(health) => health.clone(),
            None => NodeHealth::from_info(&self.info),
        }
    }
}

impl DashboardStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn key_for(info: &NodeInfo) -> String {
        if !info.node_id.trim().is_empty() {
            info.node_id.clone()
        } else {
            info.peer_id.clone()
        }
    }

    pub async fn upsert_node_info(&self, info: NodeInfo) {
        let key = Self::key_for(&info);
        let mut inner = self.inner.write().await;

        inner
            .nodes
            .entry(key)
            .and_modify(|snap| snap.info = info.clone())
            .or_insert_with(|| NodeSnapshot { info, health: None });
    }

    pub async fn upsert_node_health(&self, health: NodeHealth) {
        let key = if !health.node_id.trim().is_empty() {
            health.node_id.clone()
        } else {
            health.peer_id.clone()
        };

        let mut inner = self.inner.write().await;

        inner
            .nodes
            .entry(key)
            .and_modify(|snap| snap.health = Some(health.clone()))
            .or_insert_with(|| NodeSnapshot {
                info: NodeInfo::from_health(&health),
                health: Some(health),
            });
    }

    pub async fn push_route(&self, route: RouteInfo) {
        let mut inner = self.inner.write().await;
        inner.routes.push(route);
        if inner.routes.len() > 500 {
            let drain = inner.routes.len().saturating_sub(500);
            inner.routes.drain(0..drain);
        }
    }

    pub async fn push_log(&self, log: LogEvent) {
        let mut inner = self.inner.write().await;
        inner.logs.push(log);
        if inner.logs.len() > 2000 {
            let drain = inner.logs.len().saturating_sub(2000);
            inner.logs.drain(0..drain);
        }
    }

    pub async fn all_nodes(&self) -> Vec<NodeInfo> {
        let inner = self.inner.read().await;
        let mut nodes: Vec<NodeInfo> = inner
            .nodes
            .values()
            .map(NodeSnapshot::merged_info)
            .collect();
        nodes.sort_by(|a, b| a.key().cmp(&b.key()));
        nodes
    }

    pub async fn node_health(&self, node_id: &str) -> Option<NodeHealth> {
        let inner = self.inner.read().await;
        inner.nodes.values().find_map(|snap| {
            let info = snap.merged_info();
            let key = info.key();
            if key == node_id || info.peer_id == node_id {
                Some(snap.merged_health())
            } else {
                None
            }
        })
    }

    pub async fn routes(&self) -> Vec<RouteInfo> {
        let inner = self.inner.read().await;
        inner.routes.clone()
    }

    pub async fn logs(&self) -> Vec<LogEvent> {
        let inner = self.inner.read().await;
        inner.logs.clone()
    }
}
