//! Erasure coding untuk penyimpanan efisien
//! Skema default: Reed-Solomon (k data shards, m parity shards)
//! Total shards = k + m, hanya butuh k untuk rekonstruksi

use reed_solomon_erasure::galois_8::ReedSolomon;

/// Konfigurasi erasure coding
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

impl ErasureEncoder {
    pub fn new(config: ErasureConfig) -> Result<Self, String> {
        let encoder = ReedSolomon::new(config.data_shards, config.parity_shards)
            .map_err(|e| e.to_string())?;
        Ok(Self { config, encoder })
    }

    /// Encode data menjadi beberapa shard (ukuran sama).
    /// Data dipecah menjadi blok, ditambahkan parity shards.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        // Pastikan data bisa dibagi rata oleh data_shards, padding jika perlu
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

    /// Decode dari shards yang mungkin hilang (harus ada minimal k data shards)
    pub fn decode(&self, shards: &mut [Option<Vec<u8>>]) -> Result<Vec<u8>, String> {
        // reconstruct membutuhkan mutable slices
        self.encoder.reconstruct(shards).map_err(|e| e.to_string())?;
        // Gabungkan data dari data_shards pertama yang tidak None
        let mut data = Vec::new();
        for shard in shards.iter().take(self.config.data_shards) {
            if let Some(ref s) = shard {
                data.extend_from_slice(s);
            } else {
                return Err("Missing data shard after reconstruction".into());
            }
        }
        // Potong sesuai ukuran asli jika ada padding (tidak ditangani di sini, asumsikan tanpa padding)
        Ok(data)
    }
}
