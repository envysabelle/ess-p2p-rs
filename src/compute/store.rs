// src/compute/store.rs
//! Persistent store untuk job metadata dan hasil eksekusi.
//! Menggunakan sled (embedded KV store yang sudah ada di ESS).
//!
//! Schema:
//!   "job:{id}" → ComputeJobSpec (serialized dengan bincode)
//!   "result:{id}" → ComputeResult
//!   "status:{id}" → JobStatus
//!   "queue:pending" → sorted set job IDs (by created_at)

use crate::compute::types::{ComputeError, ComputeJobSpec, ComputeResult};
use sled::Transactional;
use std::sync::Arc;
use tracing::{debug, info, warn};

const DB_PATH: &str = "data/compute_store";
const MAX_STORED_RESULTS: usize = 10_000; // Batas total hasil yang disimpan

#[derive(Debug)]
pub struct ComputeStore {
    db: Arc<sled::Db>,
    jobs_tree: sled::Tree,
    results_tree: sled::Tree,
    queue_tree: sled::Tree,
}

impl ComputeStore {
    /// Buka atau buat database compute store.
    pub fn open() -> Result<Self, ComputeError> {
        let db = sled::open(DB_PATH)
            .map_err(|e| ComputeError::StoreError(format!("Gagal buka DB: {}", e)))?;

        let jobs_tree = db
            .open_tree("jobs")
            .map_err(|e| ComputeError::StoreError(e.to_string()))?;
        let results_tree = db
            .open_tree("results")
            .map_err(|e| ComputeError::StoreError(e.to_string()))?;
        let queue_tree = db
            .open_tree("queue")
            .map_err(|e| ComputeError::StoreError(e.to_string()))?;

        info!("[COMPUTE-STORE] Database dibuka di {}", DB_PATH);
        Ok(Self {
            db: Arc::new(db),
            jobs_tree,
            results_tree,
            queue_tree,
        })
    }

    /// Simpan job spec dan masukkan ke antrian pending.
    pub fn enqueue(&self, spec: &ComputeJobSpec) -> Result<(), ComputeError> {
        let key = format!("job:{}", spec.job_id.0.as_str());
        let value = bincode::serialize(spec)
            .map_err(|e| ComputeError::SerdeError(e.to_string()))?;

        // Atomic: simpan spec + masukkan ke queue
        (&self.jobs_tree, &self.queue_tree)
            .transaction(|(jobs, queue)| {
                jobs.insert(key.as_bytes(), value.as_slice())?;
                // Key queue: timestamp (big-endian 8 bytes) + job_id agar FIFO
                let ts = spec.created_at.to_be_bytes();
                let mut q_key = ts.to_vec();
                q_key.extend_from_slice(spec.job_id.0.as_str().as_bytes());
                queue.insert(q_key, spec.job_id.0.as_str().as_bytes())?;
                Ok(())
            })
            .map_err(|e: sled::transaction::TransactionError| {
                ComputeError::StoreError(format!("Transaksi enqueue gagal: {:?}", e))
            })?;

        debug!("[COMPUTE-STORE] Job {} masuk antrian", spec.job_id.0);
        Ok(())
    }

    /// Ambil job spec berikutnya dari antrian (oldest first / FIFO).
    pub fn dequeue_next(&self) -> Result<Option<ComputeJobSpec>, ComputeError> {
        // Ambil entry pertama dari queue_tree (sudah diurutkan by key = timestamp)
        let first = self
            .queue_tree
            .iter()
            .next()
            .transpose()
            .map_err(|e| ComputeError::StoreError(e.to_string()))?;

        let (q_key, job_id_bytes) = match first {
            Some(kv) => kv,
            None => return Ok(None),
        };

        let job_id_str = String::from_utf8_lossy(&job_id_bytes).to_string();
        let job_key = format!("job:{}", job_id_str);

        let spec_bytes = self
            .jobs_tree
            .get(job_key.as_bytes())
            .map_err(|e| ComputeError::StoreError(e.to_string()))?;

        if let Some(bytes) = spec_bytes {
            let spec: ComputeJobSpec = bincode::deserialize(&bytes)
                .map_err(|e| ComputeError::SerdeError(e.to_string()))?;

            // Hapus dari queue (sudah diambil untuk diproses)
            self.queue_tree
                .remove(&q_key)
                .map_err(|e| ComputeError::StoreError(e.to_string()))?;

            Ok(Some(spec))
        } else {
            // Job ada di queue tapi tidak ada di jobs tree — anomali, skip
            warn!(
                "[COMPUTE-STORE] Job {} ada di queue tapi tidak ada di jobs tree",
                job_id_str
            );
            self.queue_tree.remove(&q_key).ok();
            Ok(None)
        }
    }

    /// Simpan hasil eksekusi.
    pub fn save_result(&self, result: &ComputeResult) -> Result<(), ComputeError> {
        let key = format!("result:{}", result.job_id.0.as_str());
        let value = bincode::serialize(result)
            .map_err(|e| ComputeError::SerdeError(e.to_string()))?;

        self.results_tree
            .insert(key.as_bytes(), value)
            .map_err(|e| ComputeError::StoreError(e.to_string()))?;

        // Flush async ke disk
        let _ = self.results_tree.flush_async();

        // GC: hapus hasil lama jika melebihi batas
        self.gc_results_if_needed();

        debug!("[COMPUTE-STORE] Hasil job {} disimpan", result.job_id.0);
        Ok(())
    }

    /// Ambil hasil eksekusi berdasarkan job_id.
    pub fn get_result(&self, job_id: &str) -> Result<Option<ComputeResult>, ComputeError> {
        let key = format!("result:{}", job_id);
        match self
            .results_tree
            .get(key.as_bytes())
            .map_err(|e| ComputeError::StoreError(e.to_string()))?
        {
            Some(bytes) => {
                let result = bincode::deserialize(&bytes)
                    .map_err(|e| ComputeError::SerdeError(e.to_string()))?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    // ========== PATCH #8: Tambah method get_result_bytes untuk pengiriman ==========
    /// Ambil hasil eksekusi dalam bentuk serialized bytes (untuk keperluan pengiriman via network).
    /// Mengembalikan `None` jika job_id tidak ditemukan.
    pub fn get_result_bytes(&self, job_id: &str) -> Option<Vec<u8>> {
        let key = format!("result:{}", job_id);
        self.results_tree
            .get(key.as_bytes())
            .ok()
            .flatten()
            .map(|bytes| bytes.to_vec())
    }
    // =================================================================================

    /// Jumlah job yang masih ada di antrian.
    pub fn queue_depth(&self) -> usize {
        self.queue_tree.len()
    }

    /// Jumlah total hasil yang tersimpan.
    pub fn result_count(&self) -> usize {
        self.results_tree.len()
    }

    /// Statistik database (memastikan field `db` terpakai)
    pub fn db_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "db_size_on_disk": self.db.size_on_disk().unwrap_or(0),
            "total_trees": 3,
        })
    }

    /// GC: hapus hasil terlama jika melebihi MAX_STORED_RESULTS.
    fn gc_results_if_needed(&self) {
        let count = self.results_tree.len();
        if count <= MAX_STORED_RESULTS {
            return;
        }

        // Hapus 10% dari yang terlama
        let to_delete = count / 10;
        let mut deleted = 0;
        for kv in self.results_tree.iter() {
            if deleted >= to_delete {
                break;
            }
            if let Ok((k, _)) = kv {
                let _ = self.results_tree.remove(&k);
                deleted += 1;
            }
        }
        info!("[COMPUTE-STORE] GC: hapus {} hasil lama", deleted);
    }
}
