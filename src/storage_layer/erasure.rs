//! Erasure coding untuk penyimpanan efisien
//! Skema default: Reed-Solomon (k data shards, m parity shards)
//! Total shards = k + m, hanya butuh k untuk rekonstruksi

use reed_solomon_erasure::galois_8::ReedSolomon;
use std::fmt;

/// Konfigurasi erasure coding
#[derive(Debug, Clone)]
pub struct ErasureConfig {
    pub data_shards: usize,   // k
    pub parity_shards: usize, // m
}

impl Default for ErasureConfig {
    fn default() -> Self {
        Self {
            data_shards: 4,
            parity_shards: 2, // toleransi kehilangan 2 shard
        }
    }
}

pub struct ErasureEncoder {
    config: ErasureConfig,
    encoder: ReedSolomon,
}

impl fmt::Debug for ErasureEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErasureEncoder")
            .field("config", &self.config)
            .finish()
    }
}

impl ErasureEncoder {
    pub fn new(config: ErasureConfig) -> Result<Self, String> {
        let encoder = ReedSolomon::new(config.data_shards, config.parity_shards)
            .map_err(|e| e.to_string())?;
        Ok(Self { config, encoder })
    }

    /// Encode data menjadi beberapa shard (ukuran sama).
    /// Data dipecah menjadi blok, ditambahkan parity shards.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let shard_size = (data.len() + self.config.data_shards - 1) / self.config.data_shards;
        let mut shards = Vec::with_capacity(self.config.data_shards + self.config.parity_shards);
        for i in 0..self.config.data_shards {
            let start = i * shard_size;
            let end = std::cmp::min(start + shard_size, data.len());
            let mut shard = vec![0u8; shard_size];
            shard[..end - start].copy_from_slice(&data[start..end]);
            shards.push(shard);
        }
        // Parity shards kosong
        for _ in 0..self.config.parity_shards {
            shards.push(vec![0u8; shard_size]);
        }
        self.encoder.encode(&mut shards)
            .map_err(|e| e.to_string())?;
        Ok(shards)
    }

    /// Decode dari shards yang mungkin hilang (harus ada minimal k data shards).
    /// `original_size` digunakan untuk memotong padding setelah rekonstruksi.
    pub fn decode(&self, shards: &mut [Option<Vec<u8>>], original_size: usize) -> Result<Vec<u8>, String> {
        self.encoder.reconstruct(shards).map_err(|e| e.to_string())?;
        let mut data = Vec::new();
        for shard in shards.iter().take(self.config.data_shards) {
            if let Some(ref s) = shard {
                data.extend_from_slice(s);
            } else {
                return Err("Missing data shard after reconstruction".into());
            }
        }
        // Potong sesuai original_size untuk menghilangkan padding
        if original_size < data.len() {
            data.truncate(original_size);
        }
        Ok(data)
    }
}
