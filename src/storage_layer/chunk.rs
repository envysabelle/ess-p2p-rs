//! Chunk-level encryption and integrity for the Sharded DHT Storage Layer.
//! Each object is split into 1 MB chunks. Every chunk is encrypted with AES-256-GCM
//! using a per-object derived key and carries a SHA-256 hash for integrity verification.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// An encrypted chunk of an object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    /// ID of the object this chunk belongs to.
    pub object_id: String,
    /// 0‑based index of this chunk within the object.
    pub chunk_index: usize,
    /// The AES‑256‑GCM encrypted data.
    pub encrypted_data: Vec<u8>,
    /// The 96‑bit nonce used for AES‑GCM.
    pub nonce: [u8; 12],
    /// SHA‑256 hash of the encrypted data (integrity check).
    pub hash: String,
}

impl Chunk {
    /// Encrypt `plain_data` with the given 256‑bit `key` and wrap it into a `Chunk`.
    ///
    /// The nonce is randomly generated for each chunk.
    pub fn encrypt(
        object_id: &str,
        chunk_index: usize,
        plain_data: &[u8],
        key: &[u8; 32],
    ) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("valid 256‑bit key");
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted_data = cipher
            .encrypt(nonce, plain_data)
            .expect("AES‑256‑GCM encryption should never fail with a valid key");

        let hash = hex::encode(Sha256::digest(&encrypted_data));

        Self {
            object_id: object_id.to_string(),
            chunk_index,
            encrypted_data,
            nonce: nonce_bytes,
            hash,
        }
    }

    /// Decrypt the chunk data after verifying its integrity.
    ///
    /// Returns `Ok(plain_data)` on success, or an `Err` with a description on failure.
    pub fn decrypt(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        // Integrity check: recompute SHA‑256 of the encrypted blob
        let computed_hash = hex::encode(Sha256::digest(&self.encrypted_data));
        if computed_hash != self.hash {
            return Err("Chunk integrity check failed – hash mismatch".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(&self.nonce);
        cipher
            .decrypt(nonce, self.encrypted_data.as_ref())
            .map_err(|e| format!("decryption error: {}", e))
    }

    /// Key unik untuk DHT: "object_id:chunk_index"
    pub fn chunk_id(&self) -> String {
        format!("{}:{}", self.object_id, self.chunk_index)
    }
}

/// Derive a unique AES‑256 key for a specific object from the system‑wide master key.
///
/// The derivation uses SHA‑256 with a domain separation prefix so that different
/// protocols cannot accidentally share keys.
pub fn derive_object_key(master_key: &[u8; 32], object_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ESS-STORAGE-OBJECT-KEY-v1");
    hasher.update(master_key);
    hasher.update(object_id.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_chunk() {
        let master_key = [0xAAu8; 32];
        let obj_id = "test-object-1";
        let plain = b"Hello, decentralized world!";
        let obj_key = derive_object_key(&master_key, obj_id);
        let chunk = Chunk::encrypt(obj_id, 0, plain, &obj_key);
        let decrypted = chunk.decrypt(&obj_key).expect("decryption failed");
        assert_eq!(&decrypted[..], plain);
    }

    #[test]
    fn integrity_failure() {
        let master_key = [0xBBu8; 32];
        let obj_id = "obj2";
        let plain = b"Data";
        let obj_key = derive_object_key(&master_key, obj_id);
        let mut chunk = Chunk::encrypt(obj_id, 0, plain, &obj_key);
        // Tamper with the encrypted data
        chunk.encrypted_data[0] ^= 0xFF;
        assert!(chunk.decrypt(&obj_key).is_err());
    }

    #[test]
    fn different_objects_have_different_keys() {
        let mk = [0xCCu8; 32];
        let k1 = derive_object_key(&mk, "a");
        let k2 = derive_object_key(&mk, "b");
        assert_ne!(k1, k2);
    }
}
