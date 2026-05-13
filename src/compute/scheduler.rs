// src/compute/scheduler.rs
//! ComputeScheduler: Orkestrasi job di node lokal dan jaringan.
//!
//! Tanggung jawab:
//! 1. Terima job submission dari API lokal atau P2P
//! 2. Validasi authority (hanya role yang berwenang yang bisa submit)
//! 3. Masukkan ke antrian persistent
//! 4. Worker loop: ambil dari antrian → execute → simpan hasil → broadcast
//! 5. Track job yang sedang berjalan (mencegah duplikasi)
//! 6. Handle cancellation dari governance                                              
use crate::authority::{Action, AuthorityManager};
use crate::compute::executor::WasmEngine;
use crate::compute::network::NodeCapacity;
use crate::compute::store::ComputeStore;                                                
use crate::compute::types::{ComputeError, ComputeJobSpec, ComputeResult, JobId};
use crate::network_controller::NetworkController;

use dashmap::DashMap;
use libp2p::PeerId;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Konfigurasi scheduler
#[derive(Debug, Clone)]                                                                 
pub struct SchedulerConfig {
    /// Maksimum job yang berjalan bersamaan
    pub max_concurrent_jobs: usize,                                                         
    /// Interval polling antrian (ms)
    pub poll_interval_ms: u64,
    /// Apakah node ini menerima job dari node lain
    pub accept_remote_jobs: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 4,
            poll_interval_ms: 500,
            accept_remote_jobs: true,
        }
    }
}

/// Event yang di-broadcast ke subscriber (misal: network layer, dashboard)
#[derive(Debug, Clone)]
pub enum ComputeEvent {
    JobQueued(JobId),
    JobStarted(JobId),
    JobCompleted(JobId, ComputeResult),
    JobFailed(JobId, String),
    JobCancelled(JobId),
}

/// Handle untuk berinteraksi dengan scheduler dari luar
#[derive(Debug, Clone)]
pub struct ComputeSchedulerHandle {
    submit_tx: mpsc::Sender<ComputeJobSpec>,
    cancel_tx: mpsc::Sender<JobId>,
    event_tx: broadcast::Sender<ComputeEvent>,
    running_jobs: Arc<DashMap<String, CancellationToken>>,
    authority: Arc<AuthorityManager>, // <-- FIX: Tambahkan authority manager
}

impl ComputeSchedulerHandle {
    /// Submit job baru. Validasi authority dilakukan di scheduler.
    pub async fn submit_job(&self, spec: ComputeJobSpec) -> Result<JobId, ComputeError> {
        let id = spec.job_id.clone();

        let peer_id = spec.submitter_peer_id
            .parse::<PeerId>()
            .map_err(|_| ComputeError::InvalidSpec("invalid submitter_peer_id".into()))?;

        // ========== FIX: Validasi Authority Role (RBAC) ==========
        if !self.authority.is_allowed(&peer_id, Action::ComputeSubmit) {
            return Err(ComputeError::AuthorityDenied("peer tidak diizinkan submit job komputasi".into()));
        }
        // =========================================================

        // Validasi job spec secara menyeluruh (akan mengeksekusi cek signature dari types.rs)
        spec.validate().map_err(|e| ComputeError::InvalidSpec(e.to_string()))?;

        // Kirim ke channel worker
        self.submit_tx
            .send(spec)
            .await
            .map_err(|_| ComputeError::ExecutionError("Scheduler channel closed".into()))?;
        Ok(id)
    }

    /// Batalkan job yang sedang berjalan atau masih di antrian.
    pub async fn cancel_job(&self, job_id: JobId) -> Result<(), ComputeError> {
        if let Some(token) = self.running_jobs.get(job_id.0.as_str()) {
            token.cancel();
        }
        self.cancel_tx
            .send(job_id)
            .await
            .map_err(|_| ComputeError::ExecutionError("Cancel channel closed".into()))?;
        Ok(())
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<ComputeEvent> {
        self.event_tx.subscribe()
    }

    pub fn running_count(&self) -> usize {
        self.running_jobs.len()
    }

    pub async fn publish_capacity(
        &self,
        peer_id: &str,
        controller: &NetworkController,
    ) {
        let capacity = NodeCapacity::current(peer_id, self);
        let msg = crate::compute::network::ComputeMessage::Capacity(capacity);
        let payload = serde_json::to_vec(&msg).unwrap_or_default();
        let handle = controller.swarm_handle();
        let mut guard = handle.lock();
        if let Some(swarm) = guard.as_mut() {
            let key = format!("compute_capacity:{}", peer_id);
            let record = libp2p::kad::Record::new(libp2p::kad::RecordKey::new(&key), payload);
            let _ = swarm.behaviour_mut().kademlia.put_record(record, libp2p::kad::Quorum::One);
        }
    }
}

/// Spawn scheduler sebagai background task.
pub fn spawn_scheduler(
    config: SchedulerConfig,
    store: Arc<ComputeStore>,
    engine: WasmEngine,
    authority: Arc<AuthorityManager>,  // <-- FIX: Variabel ini sekarang digunakan
    node_peer_id: String,
) -> ComputeSchedulerHandle {
    let (submit_tx, mut submit_rx) = mpsc::channel::<ComputeJobSpec>(256);
    let (cancel_tx, mut cancel_rx) = mpsc::channel::<JobId>(64);
    let (event_tx, _) = broadcast::channel::<ComputeEvent>(1024);
    let running_jobs: Arc<DashMap<String, CancellationToken>> = Arc::new(DashMap::new());

    let event_tx_clone = event_tx.clone();
    let running_jobs_clone = running_jobs.clone();
    let store_clone = store.clone();
    let engine = engine;
    let executor_peer_id = node_peer_id.clone();

    // Handle yang dikembalikan
    let handle = ComputeSchedulerHandle {
        submit_tx: submit_tx.clone(),
        cancel_tx: cancel_tx.clone(),
        event_tx: event_tx.clone(),
        running_jobs: running_jobs.clone(),
        authority, // <-- Injeksi instance authority ke handle
    };

    tokio::spawn(async move {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_jobs));
        let mut poll_ticker =
            tokio::time::interval(tokio::time::Duration::from_millis(config.poll_interval_ms));

        info!(
            "[COMPUTE-SCHED] Scheduler started. MaxConcurrent={}, AcceptRemote={}",
            config.max_concurrent_jobs, config.accept_remote_jobs
        );

        loop {
            tokio::select! {
                Some(spec) = submit_rx.recv() => {
                    // Validasi akhir tambahan jika diperlukan
                    if let Err(e) = spec.validate() {
                        warn!(
                            "[COMPUTE-SCHED] Job {} ditolak (signature/integrity failed): {}",
                            spec.job_id.0, e
                        );
                        let _ = event_tx_clone.send(ComputeEvent::JobFailed(
                            spec.job_id,
                            format!("invalid signature: {}", e),
                        ));
                        continue;
                    }

                    match store_clone.enqueue(&spec) {
                        Ok(()) => {
                            info!("[COMPUTE-SCHED] Job {} di-queue (depth={})", spec.job_id.0, store_clone.queue_depth());
                            let _ = event_tx_clone.send(ComputeEvent::JobQueued(spec.job_id));
                        }
                        Err(e) => {
                            error!("[COMPUTE-SCHED] Gagal enqueue job {}: {}", spec.job_id.0, e);
                        }
                    }
                }

                Some(job_id) = cancel_rx.recv() => {
                    if let Some((_, token)) = running_jobs_clone.remove(job_id.0.as_str()) {
                        token.cancel();
                        info!("[COMPUTE-SCHED] Job {} dibatalkan", job_id.0);
                        let _ = event_tx_clone.send(ComputeEvent::JobCancelled(job_id));
                    }
                }

                _ = poll_ticker.tick() => {
                    if running_jobs_clone.len() >= config.max_concurrent_jobs {
                        continue;
                    }

                    match store_clone.dequeue_next() {
                        Ok(Some(spec)) => {
                            let permit = semaphore.clone().acquire_owned().await.unwrap();
                            let cancel_token = CancellationToken::new();
                            running_jobs_clone.insert(
                                spec.job_id.0.clone(),
                                cancel_token.clone(),
                            );

                            let engine_for_job = engine.clone();
                            let store_task = store_clone.clone();
                            let events = event_tx_clone.clone();
                            let running = running_jobs_clone.clone();
                            let job_id = spec.job_id.clone();
                            let exec_peer = executor_peer_id.clone();

                            tokio::spawn(async move {
                                let _permit = permit;

                                info!("[COMPUTE-SCHED] Mulai eksekusi job {}", job_id.0);
                                let _ = events.send(ComputeEvent::JobStarted(job_id.clone()));

                                let result = engine_for_job.execute(spec, exec_peer).await;
                                running.remove(job_id.0.as_str());

                                match result {
                                    Ok(res) => {
                                        info!(
                                            "[COMPUTE-SCHED] Job {} selesai OK dalam {}ms",
                                            job_id.0, res.exec_time_ms
                                        );
                                        if let Err(e) = store_task.save_result(&res) {
                                            error!("[COMPUTE-SCHED] Gagal simpan hasil {}: {}", job_id.0, e);
                                        }
                                        let _ = events.send(ComputeEvent::JobCompleted(job_id, res));
                                    }
                                    Err(e) => {
                                        warn!("[COMPUTE-SCHED] Job {} gagal: {}", job_id.0, e);
                                        let _ = events.send(ComputeEvent::JobFailed(
                                            job_id,
                                            e.to_string(),
                                        ));
                                    }
                                }
                            });
                        }
                        Ok(None) => {}
                        Err(e) => error!("[COMPUTE-SCHED] Error baca antrian: {}", e),
                    }
                }
            }
        }
    });

    handle
}

