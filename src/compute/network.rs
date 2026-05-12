// src/compute/network.rs
//! Protocol P2P untuk distribusi compute jobs antar node.
//!
//! Message types yang ditambahkan ke ESS P2P protocol:
//!   ComputeSubmit   → kirim job ke node tertentu
//!   ComputeResult   → kirim balik hasil ke submitter
//!   ComputeCancel   → batalkan job yang sedang berjalan
//!   ComputeQuery    → tanya status sebuah job
//!   ComputeCapacity → broadcast kapasitas komputasi node ini

use crate::compute::scheduler::{ComputeSchedulerHandle};
use crate::compute::types::{ComputeJobSpec, ComputeResult, JobId};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Pesan compute yang bisa dikirim/diterima via P2P DirectRequest
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ComputeMessage {
    /// Submitter mengirim job ke executor node
    Submit(ComputeJobSpec),

    /// Executor mengirim hasil ke submitter
    Result(ComputeResult),

    /// Request untuk membatalkan sebuah job
    Cancel { job_id: String },

    /// Query status sebuah job
    StatusQuery { job_id: String },

    /// Jawaban status query
    StatusReply {
        job_id: String,
        status: String,    // "queued" | "running" | "completed" | "failed" | "not_found"
        exec_time_ms: Option<u64>,
    },

    /// Node mengumumkan kapasitas komputasinya (dikirim via Kademlia DHT)
    Capacity(NodeCapacity),
}

/// Kapasitas komputasi sebuah node (di-publish ke DHT)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub peer_id: String,
    /// Jumlah core CPU yang tersedia
    pub available_cores: u32,
    /// Memori yang tersedia dalam MB
    pub available_memory_mb: u64,
    /// Antrian jobs yang sedang diproses
    pub queue_depth: usize,
    /// Apakah node menerima job dari luar
    pub accepting_jobs: bool,
    /// Timestamp
    pub updated_at: u64,
}

impl NodeCapacity {
    pub fn current(peer_id: &str, scheduler: &ComputeSchedulerHandle) -> Self {
        let cores = num_cpus::get() as u32;
        Self {
            peer_id: peer_id.to_string(),
            available_cores: cores.saturating_sub(scheduler.running_count() as u32),
            available_memory_mb: 256, // TODO: baca dari /proc/meminfo di Linux
            queue_depth: scheduler.running_count(),
            accepting_jobs: scheduler.running_count() < cores as usize,
            updated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Handler untuk pesan compute yang masuk dari jaringan P2P.
/// Dipanggil dari network_controller saat ada DirectRequest dengan kind="compute"
pub async fn handle_incoming_compute_message(
    raw_payload: &[u8],
    sender_peer_id: &str,
    scheduler: &ComputeSchedulerHandle,
) -> Option<ComputeMessage> {
    let msg: ComputeMessage = match serde_json::from_slice(raw_payload) {
        Ok(m) => m,
        Err(e) => {
            warn!("[COMPUTE-NET] Gagal parse pesan compute dari {}: {}", sender_peer_id, e);
            return None;
        }
    };

    match &msg {
        ComputeMessage::Submit(spec) => {
            info!("[COMPUTE-NET] Terima job {} dari {}", spec.job_id.0, sender_peer_id);
            match scheduler.submit_job(spec.clone()).await {
                Ok(id) => {
                    debug!("[COMPUTE-NET] Job {} berhasil di-queue", id.0);
                    return Some(ComputeMessage::StatusReply {
                        job_id: id.0.clone(),
                        status: "queued".into(),
                        exec_time_ms: None,
                    });
                }
                Err(e) => {
                    warn!("[COMPUTE-NET] Gagal queue job dari {}: {}", sender_peer_id, e);
                    return Some(ComputeMessage::StatusReply {
                        job_id: spec.job_id.0.clone(),
                        status: format!("failed: {}", e),
                        exec_time_ms: None,
                    });
                }
            }
        }

        ComputeMessage::Cancel { job_id } => {
            info!("[COMPUTE-NET] Cancel job {} dari {}", job_id, sender_peer_id);
            let _ = scheduler.cancel_job(JobId(job_id.clone())).await;
        }

        ComputeMessage::StatusQuery { job_id } => {
            debug!("[COMPUTE-NET] Status query untuk {} dari {}", job_id, sender_peer_id);
            // TODO: query ke store dan kembalikan status
        }

        _ => {
            debug!("[COMPUTE-NET] Pesan compute diabaikan: {:?}", std::mem::discriminant(&msg));
        }
    }

    None
}
