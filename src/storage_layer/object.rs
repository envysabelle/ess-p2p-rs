// src/storage_layer/object.rs
use super::chunk::{Chunk, derive_object_key};
use super::StorageLayer;
use super::protocol::StorageResponse;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObjectMetadata {
    pub object_id: String,
    pub total_chunks: usize,
    pub chunk_hashes: Vec<String>,
    pub hash: String,
}

impl StorageLayer {
    /// Simpan metadata objek ke dalam map lokal (dummy, nanti bisa DHT)
    async fn save_object_metadata(&self, meta: &ObjectMetadata) {
        let mut store = self.metadata_store.write().unwrap();
        store.insert(meta.object_id.clone(), meta.clone());
    }

    /// Baca metadata objek
    async fn load_object_metadata(&self, object_id: &str) -> Result<ObjectMetadata, String> {
        let store = self.metadata_store.read().unwrap();
        store.get(object_id).cloned().ok_or_else(|| "Metadata not found".to_string())
    }

    /// Simpan objek besar dengan chunking
    pub async fn put_object(&self, object_id: &str, data: &[u8]) -> StorageResponse {
        // Validasi ukuran
        if data.len() > self.config.max_object_size {
            return StorageResponse::Error { message: "Object too large".into() };
        }

        let key = derive_object_key(&self.keystore.master_key(), object_id);
        let chunks: Vec<Chunk> = data.chunks(self.config.chunk_size)
            .enumerate()
            .map(|(i, chunk_data)| Chunk::encrypt(object_id, i, chunk_data, &key))
            .collect();

        // Simpan metadata
        let metadata = ObjectMetadata {
            object_id: object_id.to_string(),
            total_chunks: chunks.len(),
            chunk_hashes: chunks.iter().map(|c| c.hash.clone()).collect(),
            hash: hex::encode(Sha256::digest(data)),
        };
        self.save_object_metadata(&metadata).await;

        // Simpan setiap chunk ke DHT (sharded via Kademlia)
        for chunk in &chunks {
            let peer: Vec<libp2p::PeerId> = Vec::new(); // nanti diisi replikasi
            if let Err(e) = self.dht.put_chunk(chunk.clone(), peer).await {
                return StorageResponse::Error { message: format!("Failed to store chunk {}: {}", chunk.chunk_index, e) };
            }
        }

        // Update stats
        let mut stats = self.stats.lock();
        stats.objects_stored += 1;
        stats.chunks_stored += chunks.len();
        stats.bytes_stored += data.len();

        StorageResponse::Success
    }

    /// Ambil objek dari DHT
    pub async fn get_object(&self, object_id: &str) -> StorageResponse {
        let metadata = match self.load_object_metadata(object_id).await {
            Ok(m) => m,
            Err(e) => return StorageResponse::Error { message: e },
        };

        let key = derive_object_key(&self.keystore.master_key(), object_id);
        let mut buffer = Vec::new();

        for i in 0..metadata.total_chunks {
            match self.dht.get_chunk(object_id, i).await {
                Some(chunk) => {
                    let decrypted = match chunk.decrypt(&key) {
                        Ok(d) => d,
                        Err(e) => return StorageResponse::Error { message: e },
                    };
                    buffer.extend_from_slice(&decrypted);
                },
                None => return StorageResponse::Error {
                    message: format!("Missing chunk {}", i),
                },
            }
        }

        // Verifikasi hash
        let computed_hash = hex::encode(Sha256::digest(&buffer));
        if computed_hash != metadata.hash {
            return StorageResponse::Error { message: "Object hash mismatch".into() };
        }

        // Update stats
        let mut stats = self.stats.lock();
        stats.chunks_served += metadata.total_chunks;
        stats.bytes_served += buffer.len();

        // Return full data dalam response khusus (pakai varian Chunk untuk menyatakan data penuh)
        StorageResponse::Chunk { chunk_index: 0, data: buffer } // sementara, perlu perbaiki tipe response
    }
}
