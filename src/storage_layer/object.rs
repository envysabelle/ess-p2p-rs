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
    /// Simpan metadata objek ke dalam map lokal (dummy, nanti bisa DHT)
    async fn save_object_metadata(&self, meta: &ObjectMetadata) {
        let mut store = self.metadata_store.write().unwrap();
        store.insert(meta.object_id.clone(), meta.clone());
    }

    /// Baca metadata objek
    async fn load_object_metadata(&self, object_id: &str) -> Result<ObjectMetadata, String> {
        let store = self.metadata_store.read().unwrap();
        store
            .get(object_id)
            .cloned()
            .ok_or_else(|| "Metadata not found".to_string())
    }

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
            // Encoder tidak tersedia (inisialisasi gagal) → fallthrough ke chunking biasa
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
        self.save_object_metadata(&metadata).await;
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
        self.save_object_metadata(&metadata).await;
        self.store_chunks(object_id, &chunks).await
    }

    /// Simpan semua chunks ke DHT dan update stats.
    async fn store_chunks(&self, _object_id: &str, chunks: &[Chunk]) -> StorageResponse {
        for chunk in chunks {
            let peers: Vec<libp2p::PeerId> = Vec::new(); // nanti diisi replication targets
            if let Err(e) = self.dht.put_chunk(chunk.clone(), peers).await {
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
        let metadata = match self.load_object_metadata(object_id).await {
            Ok(m) => m,
            Err(e) => return StorageResponse::Error { message: e },
        };

        let key = derive_object_key(&self.keystore.master_key(), object_id);

        // ── Path A: Erasure Coding ────────────────────────────────────────────
        if metadata.use_erasure_coding {
            if let Some(ref encoder) = self.erasure_encoder {
                return self.get_object_erasure(&metadata, &key, encoder).await;
            }
            return StorageResponse::Error {
                message: "Metadata menandai erasure coding tapi encoder tidak tersedia".into(),
            };
        }

        // ── Path B: Chunking biasa ────────────────────────────────────────────
        self.get_object_chunked(&metadata, &key).await
    }

    /// Ambil object dari DHT menggunakan chunking biasa (dengan DHT get).
    async fn get_object_chunked(
        &self,
        metadata: &ObjectMetadata,
        key: &[u8; 32],
    ) -> StorageResponse {
        let mut buffer = Vec::new();
        for i in 0..metadata.total_chunks {
            match self.dht.get_chunk(&metadata.object_id, i).await {
                Ok(Some(chunk)) => {
                    let decrypted = match chunk.decrypt(key) {
                        Ok(d) => d,
                        Err(e) => return StorageResponse::Error { message: e },
                    };
                    buffer.extend_from_slice(&decrypted);
                }
                Ok(None) => {
                    return StorageResponse::Error {
                        message: format!("Missing chunk {}", i),
                    }
                }
                Err(e) => {
                    return StorageResponse::Error {
                        message: format!("DHT error for chunk {}: {}", i, e),
                    }
                }
            }
        }

        self.verify_and_return(metadata, buffer)
    }

    /// Ambil object dari DHT menggunakan erasure decoding.
    /// Toleransi kehilangan: hingga `parity_shards` shards bisa hilang.
    async fn get_object_erasure(
        &self,
        metadata: &ObjectMetadata,
        key: &[u8; 32],
        encoder: &ErasureEncoder,
    ) -> StorageResponse {
        let total = metadata.total_shards;
        if total == 0 {
            return StorageResponse::Error {
                message: "total_shards=0 tapi use_erasure_coding=true (metadata corrupt)".into(),
            };
        }

        // Kumpulkan semua shards – None jika shard tidak tersedia (node down/hilang).
        let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);
        let mut missing = 0usize;
        for i in 0..total {
            match self.dht.get_chunk(&metadata.object_id, i).await {
                Ok(Some(chunk)) => match chunk.decrypt(key) {
                    Ok(d) => shards.push(Some(d)),
                    Err(e) => {
                        log::warn!("[STORAGE] Shard {} decrypt gagal: {}; dianggap missing", i, e);
                        shards.push(None);
                        missing += 1;
                    }
                },
                Ok(None) => {
                    log::debug!("[STORAGE] Shard {} tidak ditemukan di DHT", i);
                    shards.push(None);
                    missing += 1;
                }
                Err(e) => {
                    log::warn!("[STORAGE] DHT error untuk shard {}: {}; dianggap missing", i, e);
                    shards.push(None);
                    missing += 1;
                }
            }
        }

        if missing > 0 {
            log::info!(
                "[STORAGE] Erasure recovery: {} dari {} shards hilang, mencoba rekonstruksi",
                missing,
                total
            );
        }

        let buffer = match encoder.decode(&mut shards, metadata.original_size) {
            Ok(d) => d,
            Err(e) => {
                return StorageResponse::Error {
                    message: format!("Erasure decode gagal (terlalu banyak shard hilang?): {}", e),
                }
            }
        };

        self.verify_and_return(metadata, buffer)
    }

    /// Verifikasi hash dan kembalikan data, update stats.
    fn verify_and_return(&self, metadata: &ObjectMetadata, buffer: Vec<u8>) -> StorageResponse {
        let computed_hash = hex::encode(Sha256::digest(&buffer));
        if computed_hash != metadata.hash {
            return StorageResponse::Error {
                message: format!(
                    "Hash mismatch: expected={}, got={}",
                    metadata.hash, computed_hash
                ),
            };
        }
        let len = buffer.len();
        {
            let mut stats = self.stats.lock();
            stats.chunks_served += metadata.total_chunks;
            stats.bytes_served += len;
        }
        // Kembalikan Object (bukan Chunk workaround)
        StorageResponse::Object { data: buffer }
    }
}
