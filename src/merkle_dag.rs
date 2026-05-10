//! Merkle-DAG Audit Trail untuk CRDT state.
//! Setiap perubahan state yang signifikan (merge, update peer) menghasilkan
//! node baru yang merekam hash state, ID node sebelumnya, timestamp, dan metadata.
//! Digunakan untuk memverifikasi riwayat perubahan dan partisi.

use std::collections::VecDeque;
use sha2::{Digest, Sha256};
use serde::{Serialize, Deserialize};

const MAX_DAG_NODES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub index: u64,
    pub state_hash: String,
    pub parent_hash: Option<String>,
    pub timestamp: u64,
    pub metadata: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MerkleDag {
    nodes: VecDeque<MerkleNode>,
    next_index: u64,
}

impl MerkleDag {
    pub fn new() -> Self {
        Self {
            nodes: VecDeque::new(),
            next_index: 0,
        }
    }

    /// Tambahkan state baru dari representasi JSON yang sudah di-serialize.
    /// Metode ini memisahkan borrow: caller harus serialisasi state sebelum memanggil.
    pub fn add_state_json(&mut self, json: &str) {
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let parent_hash = self.nodes.back().map(|node| node.state_hash.clone());
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let node = MerkleNode {
            index: self.next_index,
            state_hash: hash,
            parent_hash,
            timestamp,
            metadata: String::new(),
        };

        self.next_index += 1;
        self.nodes.push_back(node);

        // Batasi ukuran DAG
        while self.nodes.len() > MAX_DAG_NODES {
            self.nodes.pop_front();
        }
    }

    /// Memeriksa apakah rantai hash masih konsisten (untuk verifikasi integritas).
    pub fn verify_chain(&self) -> bool {
        self.nodes.iter().enumerate().all(|(i, node)| {
            if i == 0 {
                true
            } else {
                let prev = &self.nodes[i - 1];
                node.parent_hash.as_deref() == Some(&prev.state_hash)
            }
        })
    }

    /// Mengembalikan jumlah node saat ini.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
}
