//! Protocol types for the Sharded DHT Storage Layer.
//! Defines request/response envelopes exchanged between peers over the `/ess/storage/1` protocol.

use serde::{Deserialize, Serialize};

/// Requests that can be sent to a storage peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageRequest {
    /// Store (or replicate) a single encrypted chunk.
    Put {
        /// Unique identifier of the object (e.g., hash of content).
        object_id: String,
        /// Index of this chunk within the object (0‑based).
        chunk_index: usize,
        /// Total number of chunks the object was split into.
        total_chunks: usize,
        /// Encrypted chunk data.
        data: Vec<u8>,
        /// Signature of the sender (for authenticity).
        signature: Vec<u8>,
        /// Additional peers that should also store this chunk (replication targets).
        replication_nodes: Vec<String>,
    },
    /// Retrieve a specific chunk of an object.
    Get {
        object_id: String,
        chunk_index: usize,
    },
    // Future extensions: Delete, List, GetMetadata, etc.
}

/// Responses returned by a storage peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageResponse {
    /// A single chunk (used for chunk retrieval).
    Chunk {
        chunk_index: usize,
        data: Vec<u8>,
    },
    /// Full object data setelah semua chunks/shards direkonstruksi dan diverifikasi.
    /// Digunakan oleh `get_object` setelah patch object.rs (mengganti workaround Chunk { chunk_index: 0 }).
    Object {
        data: Vec<u8>,
    },
    /// Operation completed successfully (e.g., after a Put).
    Success,
    /// An error occurred.
    Error {
        message: String,
    },
}
