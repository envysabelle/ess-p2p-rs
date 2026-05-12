// src/compute/network.rs
use crate::compute::scheduler::ComputeSchedulerHandle;
use crate::compute::store::ComputeStore;
use crate::compute::types::{ComputeJobSpec, ComputeResult, JobId};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Pesan compute yang bisa dikirim/diterima via P2P DirectRequest
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ComputeMessage {
    Submit(ComputeJobSpec),
    Result(ComputeResult),
    Cancel { job_id: String },
    StatusQuery { job_id: String },
    StatusReply { job_id: String, status: String, exec_time_ms: Option<u64> },
    Capacity(NodeCapacity),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub peer_id: String,
    pub available_cores: u32,
    pub available_memory_mb: u64,
    pub queue_depth: usize,
    pub accepting_jobs: bool,
    pub updated_at: u64,
}

impl NodeCapacity {
    pub fn current(peer_id: &str, scheduler: &ComputeSchedulerHandle) -> Self {
        let cores = num_cpus::get() as u32;
        Self {
            peer_id: peer_id.to_string(),
            available_cores: cores.saturating_sub(scheduler.running_count() as u32),
            available_memory_mb: 256,
            queue_depth: scheduler.running_count(),
            accepting_jobs: scheduler.running_count() < cores as usize,
            updated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Handler utama (digunakan oleh events.rs) – sekarang menerima store opsional.
pub async fn handle_incoming_compute_message(
    raw_payload: &[u8],
    sender_peer_id: &str,
    scheduler: &ComputeSchedulerHandle,
    store: Option<&ComputeStore>,
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
            if let Some(store) = store {
                return handle_status_query(store, job_id).await;
            }
        }
        _ => {}
    }
    None
}

/// Fungsi penanganan status query (tetap dipertahankan, dipanggil dari atas).
pub async fn handle_status_query(store: &ComputeStore, job_id: &str) -> Option<ComputeMessage> {
    match store.get_result(job_id) {
        Ok(Some(res)) => Some(ComputeMessage::StatusReply {
            job_id: job_id.to_string(),
            status: res.status.as_str().to_string(),
            exec_time_ms: Some(res.exec_time_ms),
        }),
        Ok(None) => Some(ComputeMessage::StatusReply {
            job_id: job_id.to_string(),
            status: "not_found".into(),
            exec_time_ms: None,
        }),
        Err(e) => Some(ComputeMessage::StatusReply {
            job_id: job_id.to_string(),
            status: format!("error: {}", e),
            exec_time_ms: None,
        }),
    }
}
