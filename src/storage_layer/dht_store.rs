// src/storage_layer/dht_store.rs
//
// Sharded DHT store berbasis Kademlia (libp2p).
// Chunk disimpan sebagai Record Kademlia → otomatis terdistribusi
// ke node yang bertanggung jawab berdasarkan key-nya.

use std::collections::HashMap;
use std::sync::Arc;
use libp2p::PeerId;
use parking_lot::Mutex;
use libp2p::kad::{Record, Quorum};
use crate::network_controller::NetworkController;

use super::chunk::Chunk;

#[derive(Debug)]
pub struct DhtStore {
    /// Cache lokal agar akses berulang cepat
    local_cache: Arc<Mutex<HashMap<String, Chunk>>>,
    /// Handle ke controller untuk akses swarm
    controller: Arc<NetworkController>,
}

impl DhtStore {
    pub fn new(controller: Arc<NetworkController>) -> Self {
        Self {
            local_cache: Arc::new(Mutex::new(HashMap::new())),
            controller,
        }
    }

    /// Simpan chunk ke DHT.
    /// `peers` bisa dipakai nanti untuk replikasi manual, abaikan dulu.
    pub async fn put_chunk(&self, chunk: Chunk, _peers: Vec<PeerId>) -> Result<(), String> {
        let key = chunk.chunk_id(); // format: "object_id:chunk_index"

        // Serialisasi chunk
        let value = bincode::serialize(&chunk).map_err(|e| e.to_string())?;

        let record = Record {
            key: key.clone().into_bytes().into(),
            value,
            publisher: None,
            expires: None,
        };

        // Masukkan ke cache lokal
        self.local_cache.lock().insert(key, chunk);

        // Sebarkan ke DHT via Kademlia
        let handle = self.controller.swarm_handle();
        let mut guard = handle.lock();
        if let Some(swarm) = guard.as_mut() {
            swarm.behaviour_mut().kademlia
                .put_record(record, Quorum::One)
                .map_err(|e| e.to_string())?;
            Ok(())
        } else {
            Err("Swarm not available".into())
        }
    }

    /// Ambil chunk – periksa cache dulu, jika tidak ada kembalikan None.
    /// Nanti bisa ditambahkan `get_record` dari Kademlia.
    pub async fn get_chunk(&self, object_id: &str, index: usize) -> Option<Chunk> {
        let key = format!("{}:{}", object_id, index);
        if let Some(chunk) = self.local_cache.lock().get(&key) {
            return Some(chunk.clone());
        }
        // TODO: lakukan get_record ke KAD
        None
    }
}
