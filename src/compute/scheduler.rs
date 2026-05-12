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
use crate::compute::store::ComputeStore;
use crate::compute::types::{ComputeError, ComputeJobSpec, ComputeResult, JobId};

use dashmap::DashMap;
use libp2p::PeerId;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

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
}

impl ComputeSchedulerHandle {
    /// Submit job baru. Validasi authority dilakukan di scheduler.
    pub async fn submit_job(&self, spec: ComputeJobSpec) -> Result<JobId, ComputeError> {
        let id = spec.job_id.clone();
        self.submit_tx
            .send(spec)
            .await
            .map_err(|_| ComputeError::ExecutionError("Scheduler channel closed".into()))?;
        Ok(id)
    }

    /// Batalkan job yang sedang berjalan atau masih di antrian.
    pub async fn cancel_job(&self, job_id: JobId) -> Result<(), ComputeError> {
        // Batalkan via CancellationToken jika sedang running
        if let Some(token) = self.running_jobs.get(job_id.0.as_str()) {
            token.cancel();
        }
        // Kirim ke channel untuk cleanup dari store
        self.cancel_tx
            .send(job_id)
            .await
            .map_err(|_| ComputeError::ExecutionError("Cancel channel closed".into()))?;
        Ok(())
    }

    /// Subscribe ke event stream
    pub fn subscribe_events(&self) -> broadcast::Receiver<ComputeEvent> {
        self.event_tx.subscribe()
    }

    /// Jumlah job yang sedang berjalan
    pub fn running_count(&self) -> usize {
        self.running_jobs.len()
    }
}

/// Spawn scheduler sebagai background task.
pub fn spawn_scheduler(
    config: SchedulerConfig,
    store: Arc<ComputeStore>,
    engine: WasmEngine,               // WasmEngine sudah Clone (membungkus Arc<Engine>)
    authority: Arc<AuthorityManager>,
    node_peer_id: String,
) -> ComputeSchedulerHandle {
    let (submit_tx, mut submit_rx) = mpsc::channel::<ComputeJobSpec>(256);
    let (cancel_tx, mut cancel_rx) = mpsc::channel::<JobId>(64);
    let (event_tx, _) = broadcast::channel::<ComputeEvent>(1024);
    let running_jobs: Arc<DashMap<String, CancellationToken>> = Arc::new(DashMap::new());

    let event_tx_clone = event_tx.clone();
    let running_jobs_clone = running_jobs.clone();
    let store_clone = store.clone();
    let engine = engine; // sudah bisa di‑clone
    let authority_clone = authority.clone();
    let executor_peer_id = node_peer_id.clone();

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
                // ── Terima job submission baru ──────────────────────────────
                Some(spec) = submit_rx.recv() => {
                    // Validasi authority: hanya peer dengan role >= Client
                    let peer_id = spec.submitter_peer_id.parse::<PeerId>();
                    let allowed = match peer_id {
                        Ok(pid) => authority_clone.is_allowed(&pid, Action::Connect),
                        Err(_) => false,
                    };

                    if !allowed {
                        warn!(
                            "[COMPUTE-SCHED] Job {} ditolak: authority denied untuk {}",
                            spec.job_id.0, spec.submitter_peer_id
                        );
                        let _ = event_tx_clone.send(ComputeEvent::JobFailed(
                            spec.job_id.clone(),
                            "authority denied".into(),
                        ));
                        continue;
                    }

                    // Masukkan ke persistent store
                    match store_clone.enqueue(&spec) {
                        Ok(()) => {
                            info!(
                                "[COMPUTE-SCHED] Job {} di-queue (depth={})",
                                spec.job_id.0,
                                store_clone.queue_depth()
                            );
                            let _ = event_tx_clone.send(ComputeEvent::JobQueued(spec.job_id));
                        }
                        Err(e) => {
                            error!("[COMPUTE-SCHED] Gagal enqueue job {}: {}", spec.job_id.0, e);
                        }
                    }
                }

                // ── Terima cancellation request ─────────────────────────────
                Some(job_id) = cancel_rx.recv() => {
                    if let Some((_, token)) = running_jobs_clone.remove(job_id.0.as_str()) {
                        token.cancel();
                        info!("[COMPUTE-SCHED] Job {} dibatalkan", job_id.0);
                        let _ = event_tx_clone.send(ComputeEvent::JobCancelled(job_id));
                    }
                }

                // ── Poll antrian: ambil dan eksekusi job ────────────────────
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

                            // Clone engine untuk eksekusi terpisah
                            let engine_for_job = engine.clone();
                            let store_task = store_clone.clone();
                            let events = event_tx_clone.clone();
                            let running = running_jobs_clone.clone();
                            let job_id = spec.job_id.clone();
                            let exec_peer = executor_peer_id.clone();

                            tokio::spawn(async move {
                                let _permit = permit; // drop permit saat task selesai

                                info!("[COMPUTE-SCHED] Mulai eksekusi job {}", job_id.0);
                                let _ = events.send(ComputeEvent::JobStarted(job_id.clone()));

                                // Perbaikan: kirim executor_peer_id ke engine.execute
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
                        Ok(None) => {
                            // Antrian kosong — normal
                            debug!("[COMPUTE-SCHED] Antrian kosong");
                        }
                        Err(e) => {
                            error!("[COMPUTE-SCHED] Error baca antrian: {}", e);
                        }
                    }
                }
            }
        }
    });

    ComputeSchedulerHandle {
        submit_tx,
        cancel_tx,
        event_tx,
        running_jobs,
    }
}
