use crate::ghost::GhostState;
use crate::ghost_health::{GhostHealthAssessment, GhostHealthLevel, GhostHealthRecommendation};
use crate::system_event::SystemEventKind;
use serde::{Deserialize, Serialize};

// ==========================================
// 1. GHOST POLICY CONFIGURATION
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostPolicy {
    // --- Lifecycle Logic ---
    pub allow_sleep_when_healthy: bool,
    pub wake_when_no_peers: bool,
    pub beacon_when_degraded: bool,
    pub sync_when_latency_high: bool,

    // --- Reputation Logic (Autonomous Brain) ---
    pub min_reputation_to_connect: f64,
    pub quarantine_threshold: f64,
    pub trust_score_boost_step: f64,

    // --- Enforcement Logic ---
    pub drop_on_policy_denial: bool,
    pub isolate_on_severe_failure: bool,
    pub retry_on_transient_failure: bool,
    pub max_retry_count: usize,

    // --- Traffic & Load Control ---
    pub throttle_connected_peer_threshold: usize,
    pub degrade_peer_threshold: usize,
    pub reroute_on_route_pressure: bool,

    // --- Self-Healing ---
    pub min_trusted_peers: usize,
    pub panic_on_critical: bool,
}

impl Default for GhostPolicy {
    fn default() -> Self {
        Self {
            allow_sleep_when_healthy: true,
            wake_when_no_peers: true,
            beacon_when_degraded: true,
            sync_when_latency_high: true,

            min_reputation_to_connect: 0.2,
            quarantine_threshold: 0.1,
            trust_score_boost_step: 0.05,

            drop_on_policy_denial: true,
            isolate_on_severe_failure: true,
            retry_on_transient_failure: true,
            max_retry_count: 3,

            throttle_connected_peer_threshold: 64,
            degrade_peer_threshold: 128,
            reroute_on_route_pressure: true,

            min_trusted_peers: 3,
            panic_on_critical: true,
        }
    }
}

// ==========================================
// 2. GHOST DECISION ENUM
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)] // 🔥 Eq dihapus karena f64 tidak Eq
pub enum GhostDecision {
    Noop,
    Wake,
    Sleep,
    Beacon,
    Sync,
    Panic,
    Degrade,
    // Peer-Specific Actions
    DropPeer(String),
    Throttle(String),
    IsolatePeer(String),
    Retry(String),
    Reroute(String),
    // 🔥 Langkah 3 – Penyesuaian reputasi langsung
    AdjustReputation(String, f64), // peer_id, delta
}

// ==========================================
// 3. CORE POLICY EVALUATOR
// ==========================================

impl GhostPolicy {
    /// Mengevaluasi kejadian sistem secara langsung menjadi keputusan otonom.
    pub fn evaluate_event(&self, kind: &SystemEventKind) -> GhostDecision {
        match kind {
            SystemEventKind::AuthorityViolation { peer_id, .. } => {
                GhostDecision::IsolatePeer(peer_id.to_string())
            }
            SystemEventKind::SecurityReject { peer_id, .. } => {
                if self.retry_on_transient_failure {
                    GhostDecision::Retry(peer_id.to_string())
                } else {
                    GhostDecision::DropPeer(peer_id.to_string())
                }
            }
            SystemEventKind::HighLatency { peer_id, latency } => {
                if *latency > 2000.0 {
                    GhostDecision::Throttle(peer_id.to_string())
                } else {
                    GhostDecision::Noop
                }
            }
            SystemEventKind::RoutePressure { namespace, .. } => {
                if self.reroute_on_route_pressure {
                    GhostDecision::Reroute(namespace.clone())
                } else {
                    GhostDecision::Beacon
                }
            }
            SystemEventKind::AnomalyDetected { .. } => GhostDecision::Sync,
            _ => GhostDecision::Noop,
        }
    }

    /// Mengevaluasi kesehatan node secara umum.
    pub fn decide_health(
        &self,
        current_state: GhostState,
        assessment: &GhostHealthAssessment,
    ) -> GhostDecision {
        match assessment.level {
            GhostHealthLevel::Critical => {
                if self.panic_on_critical { GhostDecision::Panic } else { GhostDecision::Degrade }
            }
            GhostHealthLevel::Degraded => {
                match assessment.recommendation {
                    GhostHealthRecommendation::Beacon => GhostDecision::Beacon,
                    GhostHealthRecommendation::Wake => GhostDecision::Wake,
                    _ => GhostDecision::Noop,
                }
            }
            GhostHealthLevel::Healthy => {
                if assessment.recommendation == GhostHealthRecommendation::Sleep && self.allow_sleep_when_healthy {
                    GhostDecision::Sleep
                } else if current_state == GhostState::Sleep && self.wake_when_no_peers {
                    GhostDecision::Wake
                } else {
                    GhostDecision::Noop
                }
            }
        }
    }

    /// Mengevaluasi tindakan terhadap peer berdasarkan skor reputasi.
    pub fn evaluate_reputation(&self, peer_id: &str, score: f64) -> GhostDecision {
        if score < self.quarantine_threshold {
            GhostDecision::IsolatePeer(peer_id.to_string())
        } else if score < self.min_reputation_to_connect {
            GhostDecision::Reroute(peer_id.to_string())
        } else {
            GhostDecision::Noop
        }
    }

    /// Mengevaluasi kapasitas jaringan untuk mencegah overloading.
    pub fn evaluate_load(&self, connected_count: usize) -> GhostDecision {
        if connected_count >= self.degrade_peer_threshold {
            GhostDecision::Degrade
        } else if connected_count >= self.throttle_connected_peer_threshold {
            GhostDecision::Sync
        } else {
            GhostDecision::Noop
        }
    }
}

// ==========================================
// 4. STANDALONE HELPERS (AKTIVASI)
// ==========================================

/// AKTIVASI: Fungsi ini sekarang dipanggil secara aktif oleh Ghost Runtime
pub fn decide(
    policy: &GhostPolicy,
    current_state: GhostState,
    assessment: &GhostHealthAssessment,
) -> GhostDecision {
    policy.decide_health(current_state, assessment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost_health::{GhostHealthAssessment, GhostHealthLevel, GhostHealthRecommendation};

    fn make_assessment(level: GhostHealthLevel, rec: GhostHealthRecommendation) -> GhostHealthAssessment {
        GhostHealthAssessment { level, recommendation: rec, reason: "test".into() }
    }

    #[test]
    fn test_decide_health_critical_panics() {
        let policy = GhostPolicy::default();
        let assess = make_assessment(GhostHealthLevel::Critical, GhostHealthRecommendation::Beacon);
        assert_eq!(policy.decide_health(GhostState::Idle, &assess), GhostDecision::Panic);
    }

    #[test]
    fn test_decide_health_degraded_beacon() {
        let policy = GhostPolicy::default();
        let assess = make_assessment(GhostHealthLevel::Degraded, GhostHealthRecommendation::Beacon);
        assert_eq!(policy.decide_health(GhostState::Idle, &assess), GhostDecision::Beacon);
    }

    #[test]
    fn test_evaluate_event_high_latency_throttle() {
        let policy = GhostPolicy::default();
        let kind = SystemEventKind::HighLatency { peer_id: make_peer(), latency: 3000.0 };
        assert!(matches!(policy.evaluate_event(&kind), GhostDecision::Throttle(..)));
    }

    // helper
    fn make_peer() -> libp2p::PeerId { libp2p::PeerId::random() }
}
