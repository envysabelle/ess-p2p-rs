use crate::ghost::GhostState;
use log::{debug, info};

#[derive(Debug, Clone)]
pub struct GhostHealthSnapshot {
    pub node_id: String,
    pub role: String,
    pub connected_peers: usize,
    pub known_peers: usize,
    pub route_peers: usize,
    pub trusted_peers: usize,
    pub bootstrap_ok: bool,
    pub gateway_ok: bool,
    pub web_ok: bool,
    pub config_ok: bool,
    pub tamper_detected: bool,
    pub last_failure_reason: Option<String>,
}

impl Default for GhostHealthSnapshot {
    fn default() -> Self {
        Self {
            node_id: "unknown".to_string(),
            role: "client".to_string(),
            connected_peers: 0,
            known_peers: 0,
            route_peers: 0,
            trusted_peers: 0,
            bootstrap_ok: false,
            gateway_ok: false,
            web_ok: false,
            config_ok: false,
            tamper_detected: false,
            last_failure_reason: None,
        }
    }
}

impl GhostHealthSnapshot {
    fn role_norm(&self) -> String {
        self.role.trim().to_ascii_lowercase()
    }

    pub fn is_supernode(&self) -> bool { self.role_norm() == "supernode" }
    pub fn is_relay(&self) -> bool { self.role_norm() == "relay" }
    pub fn is_config_ready(&self) -> bool { self.config_ok }
    pub fn has_trusted_path(&self) -> bool { self.bootstrap_ok || self.gateway_ok || self.web_ok || self.trusted_peers > 0 }
    pub fn is_network_reachable(&self) -> bool { self.connected_peers > 0 || self.has_trusted_path() }

    pub fn is_operational(&self) -> bool {
        self.is_config_ready() && self.is_network_reachable() && !self.tamper_detected
    }

    fn looks_like_disconnect_reason(&self) -> bool {
        self.last_failure_reason.as_deref()
            .map(|r| {
                let r = r.to_ascii_lowercase();
                r.contains("disconnect") || r.contains("closed") || r.contains("transport")
            }).unwrap_or(false)
    }

    pub fn health_score(&self) -> u8 {
        if self.tamper_detected { return 0; }
        let mut score: i32 = 40;
        if self.is_operational() { score += 30; }
        if self.is_supernode() && self.gateway_ok { score += 10; }
        if self.is_relay() && self.bootstrap_ok { score += 10; }
        if self.connected_peers >= 2 { score += 10; }
        if self.looks_like_disconnect_reason() { score -= 10; }

        score.clamp(0, 100) as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhostHealthLevel { Healthy, Degraded, Critical }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhostHealthRecommendation { StayAwake, Wake, Beacon, Sleep, Panic }

#[derive(Debug, Clone)]
pub struct GhostHealthAssessment {
    pub level: GhostHealthLevel,
    pub recommendation: GhostHealthRecommendation,
    pub reason: String,
}

pub fn assess(snapshot: &GhostHealthSnapshot, current_state: GhostState) -> GhostHealthAssessment {
    debug!("[GHOST-HEALTH] Node {} analysis starting.", snapshot.node_id);

    let score = snapshot.health_score();
    let level = if score >= 85 { GhostHealthLevel::Healthy }
                else if score >= 45 { GhostHealthLevel::Degraded }
                else { GhostHealthLevel::Critical };

    let reason = if snapshot.tamper_detected { "tamper_detected".into() }
                 else if snapshot.connected_peers == 0 { "isolated_node".into() }
                 else { "normal_operation".into() };

    let recommendation = match level {
        GhostHealthLevel::Critical => GhostHealthRecommendation::Panic,
        GhostHealthLevel::Degraded => GhostHealthRecommendation::Beacon,
        GhostHealthLevel::Healthy => {
            if snapshot.connected_peers > 0 { GhostHealthRecommendation::StayAwake }
            else {
                if current_state == GhostState::Sleep { GhostHealthRecommendation::Wake }
                else { GhostHealthRecommendation::Sleep }
            }
        }
    };

    info!("[GHOST-HEALTH] Assessment for {}: Score={}, Level={:?}, Recommendation={:?}",
          snapshot.node_id, score, level, recommendation);

    GhostHealthAssessment { level, recommendation, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_score_operational() {
        let snap = GhostHealthSnapshot {
            connected_peers: 3,
            bootstrap_ok: true,
            gateway_ok: true,
            config_ok: true,
            tamper_detected: false,
            ..Default::default()
        };
        let score = snap.health_score();
        assert!(score >= 70);
    }

    #[test]
    fn test_tamper_detected_zero_score() {
        let snap = GhostHealthSnapshot {
            tamper_detected: true,
            ..Default::default()
        };
        assert_eq!(snap.health_score(), 0);
    }
}
