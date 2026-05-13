// src/storage_layer/dht_store.rs
//
// Sharded DHT store berbasis Kademlia (libp2p).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use libp2p::PeerId;
use parking_lot::Mutex;
use libp2p::kad::{Record, Quorum, RecordKey};
use crate::network_controller::NetworkController;
use super::chunk::Chunk;

#[derive(Debug)]
pub struct DhtStore {
    local_cache: Arc<Mutex<HashMap<String, Chunk>>>,
    controller: Arc<NetworkController>,
}

impl DhtStore {
    pub fn new(controller: Arc<NetworkController>) -> Self {
        Self {
            local_cache: Arc::new(Mutex::new(HashMap::new())),
            controller,
        }
    }

    pub async fn put_chunk(&self, chunk: Chunk, _peers: Vec<PeerId>) -> Result<(), String> {
        let key = chunk.chunk_id();
        let value = bincode::serialize(&chunk).map_err(|e| e.to_string())?;
        let record = Record {
            key: key.clone().into_bytes().into(),
            value,
            publisher: None,
            expires: None,
        };
        self.local_cache.lock().insert(key, chunk);
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

    pub async fn get_chunk(&self, object_id: &str, index: usize) -> Result<Option<Chunk>, String> {
        let key = format!("{}:{}", object_id, index);
        if let Some(chunk) = self.local_cache.lock().get(&key) {
            return Ok(Some(chunk.clone()));
        }
        self.get_chunk_from_dht(&key).await
    }

    async fn get_chunk_from_dht(&self, key: &str) -> Result<Option<Chunk>, String> {
        // Convert ke Vec<u8> agar tipe K di RecordKey::new menjadi Sized
        let key_vec = key.as_bytes().to_vec();
        let record_key = RecordKey::new(&key_vec);

        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = self.controller.swarm_handle();
        let mut guard = handle.lock();
        let swarm = guard.as_mut().ok_or("Swarm not available")?;
        let query_id = swarm.behaviour_mut().kademlia.get_record(record_key);
        drop(guard);
        self.controller.register_kad_get_query(query_id, tx).await
            .map_err(|e| format!("Failed to register query: {}", e))?;
        match tokio::time::timeout(Duration::from_secs(5), rx).await {
            Ok(inner) => match inner {
                Ok(Ok(Some(chunk))) => Ok(Some(chunk)),
                Ok(Ok(None)) => Ok(None),
                Ok(Err(e)) => Err(format!("Kad query error: {}", e)),
                Err(e) => Err(format!("Channel receive error: {}", e)),
            },
            Err(_) => Err("DHT get chunk timeout".to_string()),
        }
    }

    pub fn complete_get_query(&self, query_id: libp2p::kad::QueryId, result: Result<Option<Chunk>, String>) {
        if let Some(sender) = self.controller.take_kad_pending(query_id) {
            let _ = sender.send(result);
        }
    }
}
