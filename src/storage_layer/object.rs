// src/storage_layer/object.rs
use super::chunk::{derive_object_key, Chunk};
use super::erasure::ErasureEncoder;
use super::protocol::StorageResponse;
use super::StorageLayer;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObjectMetadata {
    pub object_id: String,
    pub total_chunks: usize,
    pub chunk_hashes: Vec<String>,
    /// SHA-256 hex dari seluruh data asli sebelum chunking/erasure.
    pub hash: String,
    /// Ukuran data asli dalam bytes. Dipakai ErasureEncoder::decode untuk
    /// memotong trailing padding setelah rekonstruksi shard.
    pub original_size: usize,
    /// True jika object disimpan dengan erasure coding (shards), bukan
    /// chunking biasa. Dipakai get_object untuk memilih jalur dekode yang tepat.
    pub use_erasure_coding: bool,
    /// Jumlah total shards (data + parity) – valid hanya jika use_erasure_coding.
    pub total_shards: usize,
}

impl StorageLayer {
    /// Simpan objek besar dengan chunking (biasa atau erasure-coded).
    pub async fn put_object(&self, object_id: &str, data: &[u8]) -> StorageResponse {
        if data.len() > self.config.max_object_size {
            return StorageResponse::Error {
                message: "Object too large".into(),
            };
        }

        let key = derive_object_key(&self.keystore.master_key(), object_id);
        let object_hash = hex::encode(Sha256::digest(data));

        // ── Path A: Erasure Coding ────────────────────────────────────────────
        if self.config.use_erasure_coding {
            if let Some(ref encoder) = self.erasure_encoder {
                return self
                    .put_object_erasure(object_id, data, &key, object_hash, encoder)
                    .await;
            }
            log::warn!("[STORAGE] use_erasure_coding=true tapi encoder None, fallback ke chunking");
        }

        // ── Path B: Chunking biasa ────────────────────────────────────────────
        self.put_object_chunked(object_id, data, &key, object_hash)
            .await
    }

    /// Simpan object dengan chunking sederhana (tanpa erasure coding).
    async fn put_object_chunked(
        &self,
        object_id: &str,
        data: &[u8],
        key: &[u8; 32],
        object_hash: String,
    ) -> StorageResponse {
        let chunks: Vec<Chunk> = data
            .chunks(self.config.chunk_size)
            .enumerate()
            .map(|(i, chunk_data)| Chunk::encrypt(object_id, i, chunk_data, key))
            .collect();

        let metadata = ObjectMetadata {
            object_id: object_id.to_string(),
            total_chunks: chunks.len(),
            total_shards: 0,
            chunk_hashes: chunks.iter().map(|c| c.hash.clone()).collect(),
            hash: object_hash,
            original_size: data.len(),
            use_erasure_coding: false,
        };

        // Simpan metadata ke Sled DB menggunakan modul MetadataStore
        if let Err(e) = self.metadata_store.save_metadata(&metadata).await {
            return StorageResponse::Error { 
                message: format!("Metadata persist failed: {}", e) 
            };
        }

        self.store_chunks(object_id, &chunks).await
    }

    /// Simpan object dengan erasure coding: data → shards → setiap shard = 1 Chunk.
    async fn put_object_erasure(
        &self,
        object_id: &str,
        data: &[u8],
        key: &[u8; 32],
        object_hash: String,
        encoder: &ErasureEncoder,
    ) -> StorageResponse {
        let shards = match encoder.encode(data) {
            Ok(s) => s,
            Err(e) => {
                return StorageResponse::Error {
                    message: format!("Erasure encode error: {}", e),
                }
            }
        };

        let total_shards = shards.len();
        // Setiap shard di-encrypt dan disimpan sebagai Chunk independen.
        let chunks: Vec<Chunk> = shards
            .iter()
            .enumerate()
            .map(|(i, shard_data)| Chunk::encrypt(object_id, i, shard_data, key))
            .collect();

        let metadata = ObjectMetadata {
            object_id: object_id.to_string(),
            total_chunks: chunks.len(),
            total_shards,
            chunk_hashes: chunks.iter().map(|c| c.hash.clone()).collect(),
            hash: object_hash,
            original_size: data.len(),
            use_erasure_coding: true,
        };

        // Simpan metadata ke Sled DB menggunakan modul MetadataStore
        if let Err(e) = self.metadata_store.save_metadata(&metadata).await {
            return StorageResponse::Error { 
                message: format!("Metadata persist failed: {}", e) 
            };
        }

        self.store_chunks(object_id, &chunks).await
    }

    /// Simpan semua chunks ke DHT dan update stats.
    async fn store_chunks(&self, _object_id: &str, chunks: &[Chunk]) -> StorageResponse {
        for chunk in chunks {
            let peers: Vec<libp2p::PeerId> = Vec::new(); // Dikosongkan karena Kademlia akan otomatis mencari nodes terdekat

            // Melempar config.replication_factor ke DHT Store agar dikelola oleh Quorum Kademlia
            if let Err(e) = self.dht.put_chunk(chunk.clone(), peers, self.config.replication_factor).await {
                return StorageResponse::Error {
                    message: format!("Failed to store chunk {}: {}", chunk.chunk_index, e),
                };
            }
        }

        let mut stats = self.stats.lock();
        stats.objects_stored += 1;
        stats.chunks_stored += chunks.len();
        stats.bytes_stored += chunks.iter().map(|c| c.encrypted_data.len()).sum::<usize>();

        StorageResponse::Success
    }

    /// Ambil objek dari DHT.
    pub async fn get_object(&self, object_id: &str) -> StorageResponse {
        // Ambil metadata dengan aman lewat MetadataStore
        let metadata = match self.metadata_store.load_metadata(object_id).await {
            Ok(Some(m)) => m,
            Ok(None) => return StorageResponse::Error { message: "Metadata not found in local DB".into() },
            Err(e) => return StorageResponse::Error { message: format!("Failed to load metadata: {}", e) },
        };

        let key = derive_object_key(&self.keystore.master_key(), object_id);

        if metadata.use_erasure_coding {
            self.get_object_erasure(object_id, metadata, &key).await
        } else {
            self.get_object_chunked(object_id, metadata, &key).await
        }
    }

    async fn get_object_chunked(
        &self,
        object_id: &str,
        metadata: ObjectMetadata,
        key: &[u8; 32],
    ) -> StorageResponse {
        let mut object_data = Vec::new();

        for i in 0..metadata.total_chunks {
            match self.dht.get_chunk(object_id, i).await {
                Ok(Some(chunk)) => match chunk.decrypt(key) {
                    Ok(plain) => object_data.extend_from_slice(&plain),
                    Err(e) => return StorageResponse::Error { message: format!("Decryption error chunk {}: {}", i, e) },
                },
                Ok(None) => return StorageResponse::Error { message: format!("Chunk {} not found on network", i) },
                Err(e) => return StorageResponse::Error { message: format!("DHT error chunk {}: {}", i, e) },
            }
        }

        let computed_hash = hex::encode(Sha256::digest(&object_data));
        if computed_hash != metadata.hash {
            return StorageResponse::Error { message: "Object integrity check failed".into() };
        }

        let mut stats = self.stats.lock();
        stats.chunks_served += metadata.total_chunks;
        stats.bytes_served += object_data.len();

        StorageResponse::Object { data: object_data }
    }

    async fn get_object_erasure(
        &self,
        object_id: &str,
        metadata: ObjectMetadata,
        key: &[u8; 32],
    ) -> StorageResponse {
        let encoder = match &self.erasure_encoder {
            Some(enc) => enc,
            None => return StorageResponse::Error { message: "Erasure decoder not configured".into() },
        };

        let mut shards = vec![None; metadata.total_shards];

        for i in 0..metadata.total_shards {
            if let Ok(Some(chunk)) = self.dht.get_chunk(object_id, i).await {
                if let Ok(plain) = chunk.decrypt(key) {
                    shards[i] = Some(plain);
                }
            }
        }

        match encoder.decode(&mut shards, metadata.original_size) {
            Ok(object_data) => {
                let computed_hash = hex::encode(Sha256::digest(&object_data));
                if computed_hash != metadata.hash {
                    return StorageResponse::Error { message: "Erasure object integrity check failed".into() };
                }

                let mut stats = self.stats.lock();
                stats.chunks_served += metadata.total_chunks;
                stats.bytes_served += object_data.len();

                StorageResponse::Object { data: object_data }
            }
            Err(e) => StorageResponse::Error { message: format!("Erasure decoding failed: {}", e) },
        }
    }
}

