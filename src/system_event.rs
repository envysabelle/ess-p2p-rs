use libp2p::PeerId;
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::authority::Action;

mod peer_id_serde {
    use super::*;
    pub fn serialize<S>(peer_id: &PeerId, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(&peer_id.to_string())
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PeerId, D::Error> where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemEventKind {
    PeerConnected { #[serde(with = "peer_id_serde")] peer_id: PeerId },
    PeerDisconnected { #[serde(with = "peer_id_serde")] peer_id: PeerId },

    // 🔥 FIX E0026 & E0027: Nama field disesuaikan jadi 'latency' agar Ghost Policy happy
    HighLatency { #[serde(with = "peer_id_serde")] peer_id: PeerId, latency: f64 },

    // 🔥 FIX E0599: Tambahkan varian yang dicari Ghost Engine
    SecurityReject { #[serde(with = "peer_id_serde")] peer_id: PeerId, reason: String },
    AnomalyDetected { reason: String },
    RoutePressure { namespace: String },

    AuthorityViolation { #[serde(with = "peer_id_serde")] peer_id: PeerId, action: Action },
    GhostDecisionExecuted { decision: String, target: String },
    WorldStateSynced { revision: u64 },
    SyncCompleted,
    GhostRecommendation { signal: String },
    GatewayAudit { #[serde(with = "peer_id_serde")] peer_id: PeerId, method: String, allowed: bool },

    // ── Compute Layer Events (NEW) ──────────────────────────────────────────
    /// Job baru masuk ke antrian
    ComputeJobQueued { job_id: String, submitter: String },
    /// Job mulai dieksekusi
    ComputeJobStarted { job_id: String },
    /// Job selesai dengan sukses
    ComputeJobCompleted { job_id: String, exec_time_ms: u64 },
    /// Job gagal
    ComputeJobFailed { job_id: String, reason: String },
    /// Job dibatalkan
    ComputeJobCancelled { job_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    pub timestamp: u64,
    pub source: String,
    pub kind: SystemEventKind,
}

impl SystemEvent {
    pub fn new(source: impl Into<String>, kind: SystemEventKind) -> Self {
        Self {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            source: source.into(),
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_event_kind_peer_connected_serde() {
        let kind = SystemEventKind::PeerConnected { peer_id: PeerId::random() };
        let json = serde_json::to_string(&kind).unwrap();
        let de: SystemEventKind = serde_json::from_str(&json).unwrap();
        assert!(matches!(de, SystemEventKind::PeerConnected { .. }));
    }
}
