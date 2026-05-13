// src/storage_layer/mod.rs
//! ESS Sharded DHT Storage Layer
//!
//! Menyediakan penyimpanan objek terdistribusi dengan fitur penuh:
//! - Enkripsi per chunk (AES-256-GCM)
//! - Sharding: objek besar dipecah menjadi chunk 1 MB
//! - Replikasi: setiap chunk disimpan di k node terdekat (default k=3)
//! - Erasure coding (opsional) untuk efisiensi
//! - Integritas dan otentikasi terjamin oleh hash + signature

pub mod protocol;
pub mod chunk;
pub mod dht_store;
pub mod object;
pub mod erasure;

use std::sync::Arc;
use crate::authority::{AuthorityManager, Action};
use crate::keystore::SoftwareKeystore;
use crate::network_controller::NetworkController;
use libp2p::PeerId;
use erasure::{ErasureConfig, ErasureEncoder};
use dashmap::DashMap;
use parking_lot::Mutex;

// ============================================================================
// Config & public structs
// ============================================================================

#[derive(Debug, Clone)]
pub struct StorageLayerConfig {
    pub chunk_size: usize,           // default 1 MB
    pub replication_factor: usize,   // quorum storage, minimal 2
    pub use_erasure_coding: bool,
    pub max_object_size: usize,      // maksimum 1 GB
}

impl Default for StorageLayerConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024, // 1 MB
            replication_factor: 3,
            use_erasure_coding: false,
            max_object_size: 1024 * 1024 * 1024, // 1 GB
        }
    }
}

#[derive(Clone, Debug)]
pub struct StorageLayer {
    pub config: StorageLayerConfig,
    pub keystore: SoftwareKeystore,
    pub authority: Arc<AuthorityManager>,
    pub dht: Arc<dht_store::DhtStore>,
    pub cache: Arc<DashMap<String, chunk::Chunk>>,
    pub stats: Arc<Mutex<StorageStats>>,
    pub controller: Arc<NetworkController>,
    
    // ========== FIX: Pindah dari HashMap ke Sled Database ==========
    pub metadata_db: Arc<sled::Db>,
    // ===============================================================
    
    /// Encoder erasure aktif hanya jika `config.use_erasure_coding == true`.
    pub erasure_encoder: Option<Arc<ErasureEncoder>>,
}

#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    pub objects_stored: usize,
    pub chunks_stored: usize,
    pub bytes_stored: usize,
    pub chunks_served: usize,
    pub bytes_served: usize,
}

// ============================================================================
// Implementation
// ============================================================================

impl StorageLayer {
    pub fn new(
        config: StorageLayerConfig,
        keystore: SoftwareKeystore,
        authority: Arc<AuthorityManager>,
        controller: Arc<NetworkController>,
    ) -> Self {
        // Bangun ErasureEncoder jika erasure coding diaktifkan di config.
        let erasure_encoder = if config.use_erasure_coding {
            match ErasureEncoder::new(ErasureConfig::default()) {
                Ok(enc) => {
                    log::info!("[STORAGE] Erasure coding aktif (4 data shards, 2 parity shards)");
                    Some(Arc::new(enc))
                }
                Err(e) => {
                    log::warn!("[STORAGE] Gagal inisialisasi ErasureEncoder: {}; fallback ke chunking biasa", e);
                    None
                }
            }
        } else {
            None
        };

        // Buka database Sled untuk Metadata Persistence
        let metadata_db = sled::open("data/storage_metadata")
            .expect("Gagal membuka database untuk Storage Metadata");

        Self {
            config,
            keystore,
            authority,
            dht: Arc::new(dht_store::DhtStore::new(controller.clone())),
            cache: Arc::new(DashMap::new()),
            stats: Arc::new(Mutex::new(StorageStats::default())),
            controller,
            metadata_db: Arc::new(metadata_db),
            erasure_encoder,
        }
    }

    /// Handle incoming storage request dari network
    pub async fn handle_request(&self, request: protocol::StorageRequest, peer_id: &str) -> protocol::StorageResponse {
        if let Ok(pid) = peer_id.parse::<PeerId>() {
            let action = match &request {
                protocol::StorageRequest::Put { .. } => Action::Connect,
                protocol::StorageRequest::Get { .. } => Action::Connect,
            };

            if !self.authority.is_allowed(&pid, action) {
                return protocol::StorageResponse::Error { message: "Access denied".into() };
            }
        }

        match &request {
            protocol::StorageRequest::Put { object_id, data, .. } => self.put_object(object_id, data).await,
            protocol::StorageRequest::Get { object_id, .. } => self.get_object(object_id).await,
        }
    }

    /// Mendapatkan statistik penyimpanan (digunakan dashboard)
    pub fn get_stats(&self) -> StorageStats {
        self.stats.lock().clone()
    }
}

