// src/compute/types.rs
//! Tipe data fundamental untuk ESS Compute Layer.
//! Semua tipe di sini adalah wire-compatible (Serialize/Deserialize)
//! sehingga bisa dikirim via P2P atau disimpan di sled.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Konstanta batas keamanan ────────────────────────────────────────────────

/// Batas maksimum ukuran bytecode WASM yang bisa disubmit (4 MB)
pub const MAX_WASM_BYTECODE_SIZE: usize = 4 * 1024 * 1024;

/// Default batas memori per job (64 MB)
pub const DEFAULT_MEMORY_LIMIT_MB: u64 = 64;
/// Default timeout eksekusi per job (30 detik)
pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = 30_000;

/// Maksimum timeout yang diizinkan (10 menit)
pub const MAX_EXEC_TIMEOUT_MS: u64 = 10 * 60 * 1000;

/// Maksimum ukuran output per job (1 MB)
pub const MAX_OUTPUT_SIZE_BYTES: usize = 1 * 1024 * 1024;

// ── Identitas Job ───────────────────────────────────────────────────────────

/// ID unik sebuah job — SHA-256 dari wasm_bytecode + input_data + submitter
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub String);

impl JobId {
    pub fn new(wasm_hash: &str, input_hash: &str, submitter: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(wasm_hash.as_bytes());
        h.update(b"|");
        h.update(input_hash.as_bytes());
        h.update(b"|");
        h.update(submitter.as_bytes());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        h.update(ts.to_le_bytes());
        Self(hex::encode(h.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "job:{}", &self.0[..16])
    }
}

// ── Resource Limits ─────────────────────────────────────────────────────────

/// Batas resource yang diberikan ke satu job.
/// Semua batas ini di-enforce oleh WasmExecutor sebelum memulai eksekusi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Batas memori linear WASM dalam MB (default: 64)
    pub memory_mb: u64,

    /// Timeout eksekusi dalam milidetik (default: 30_000)
    pub timeout_ms: u64,

    /// Batas fuel (instruksi WASM yang dapat dieksekusi).
    /// Mencegah infinite loop. 1 fuel ≈ 1 instruksi WASM.
    /// Default: 1_000_000_000 (1 miliar instruksi)
    pub fuel_limit: u64,

    /// Maksimum ukuran output yang dikembalikan (bytes)
    pub max_output_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: DEFAULT_MEMORY_LIMIT_MB,
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            fuel_limit: 1_000_000_000,
            max_output_bytes: MAX_OUTPUT_SIZE_BYTES,
        }
    }
}

impl ResourceLimits {
    /// Validasi: pastikan tidak ada batas yang melebihi maksimum global.
    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.timeout_ms > MAX_EXEC_TIMEOUT_MS {
            return Err(ComputeError::ResourceLimitExceeded(
                format!("timeout_ms {} melebihi maksimum {}", self.timeout_ms, MAX_EXEC_TIMEOUT_MS)
            ));
        }
        if self.memory_mb > 512 {
            return Err(ComputeError::ResourceLimitExceeded(
                "memory_mb tidak boleh melebihi 512 MB per job".into()
            ));
        }
        Ok(())
    }
}

// ── Job Specification ───────────────────────────────────────────────────────

/// Spesifikasi lengkap sebuah compute job yang dikirimkan ke jaringan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJobSpec {
    /// ID unik job
    pub job_id: JobId,

    /// SHA-256 dari wasm_bytecode — dipakai untuk verifikasi integritas
    pub wasm_hash: String,

    /// Bytecode WASM yang akan dieksekusi.
    /// WAJIB: module harus export fungsi `_start` atau `main`.
    pub wasm_bytecode: Vec<u8>,

    /// Input data yang akan dipasskan ke WASM via WASI stdin atau
    /// environment variable `ESS_INPUT`.
    pub input_data: Vec<u8>,

    /// Environment variables yang tersedia di dalam sandbox WASI.
    /// Keys tidak boleh mengandung "=" atau null byte.
    pub env_vars: HashMap<String, String>,

    /// Resource limits untuk job ini
    pub limits: ResourceLimits,

    /// PeerId submitter (ditandatangani)
    pub submitter_peer_id: String,

    /// Tanda tangan Ed25519 dari submitter atas canonical form job
    pub signature: Vec<u8>,

    /// Public key submitter (protobuf-encoded)
    pub submitter_pubkey: Vec<u8>,

    /// Timestamp saat job dibuat (Unix secs)
    pub created_at: u64,

    /// Versi API (untuk backward compat)
    pub api_version: u8,
}

impl ComputeJobSpec {
    /// Canonical bytes yang ditandatangani — deterministik, tidak berubah
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.job_id.as_str().as_bytes());
        out.extend_from_slice(b"|");
        out.extend_from_slice(self.wasm_hash.as_bytes());
        out.extend_from_slice(b"|");
        out.extend_from_slice(&self.input_data);
        out.extend_from_slice(b"|");
        out.extend_from_slice(self.submitter_peer_id.as_bytes());
        out.extend_from_slice(b"|");
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out
    }

    /// Hitung SHA-256 dari wasm_bytecode dan bandingkan dengan wasm_hash.
    pub fn verify_bytecode_integrity(&self) -> bool {
        use sha2::{Digest, Sha256};
        let computed = hex::encode(Sha256::digest(&self.wasm_bytecode));
        computed == self.wasm_hash
    }

    /// Validasi lengkap sebelum eksekusi: integritas, tanda tangan, batas resource.
    pub fn validate(&self) -> Result<(), ComputeError> {
        // Ukuran bytecode
        if self.wasm_bytecode.len() > MAX_WASM_BYTECODE_SIZE {
            return Err(ComputeError::InvalidSpec(format!(
                "WASM bytecode terlalu besar: {} bytes (maks {})",
                self.wasm_bytecode.len(), MAX_WASM_BYTECODE_SIZE
            )));
        }
        // Integritas hash
        if !self.verify_bytecode_integrity() {
            return Err(ComputeError::IntegrityFailed(
                "wasm_hash tidak cocok dengan bytecode".into()
            ));
        }
        // Resource limits
        self.limits.validate()?;
        // Submitter tidak boleh kosong
        if self.submitter_peer_id.is_empty() {
            return Err(ComputeError::InvalidSpec("submitter_peer_id kosong".into()));
        }
        // Timestamp tidak terlalu lama (15 menit)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(self.created_at) > 900 {
            return Err(ComputeError::InvalidSpec("job terlalu lama (>15 menit)".into()));
        }
        Ok(())
    }
}

// ── Job Status ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    /// Job diterima, menunggu di antrian
    Queued,
    /// Sedang dieksekusi di node ini
    Running { started_at: u64 },
    /// Selesai dengan sukses
    Completed { finished_at: u64 },
    /// Gagal dengan pesan error
    Failed { reason: String, finished_at: u64 },
    /// Dibatalkan (oleh submitter atau governance)
    Cancelled { reason: String },
    /// Timeout — fuel habis atau waktu habis
    TimedOut { finished_at: u64 },
}

impl JobStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed { .. } | Self::Failed { .. } | Self::Cancelled { .. } | Self::TimedOut { .. })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running { .. } => "running",
            Self::Completed { .. } => "completed",
            Self::Failed { .. } => "failed",
            Self::Cancelled { .. } => "cancelled",
            Self::TimedOut { .. } => "timed_out",
        }
    }
}

// ── Hasil Eksekusi ──────────────────────────────────────────────────────────

/// Hasil lengkap eksekusi sebuah job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeResult {
    pub job_id: JobId,
    pub status: JobStatus,
    /// Output dari WASM (WASI stdout)
    pub output: Vec<u8>,
    /// Stderr dari WASM (WASI stderr) — untuk debugging
    pub stderr: Vec<u8>,
    /// Exit code dari WASM process
    pub exit_code: i32,
    /// Fuel yang dikonsumsi (instruksi)
    pub fuel_consumed: u64,
    /// Waktu eksekusi aktual dalam milidetik
    pub exec_time_ms: u64,
    /// Memori peak yang digunakan dalam bytes
    pub memory_used_bytes: u64,
    /// Node yang mengeksekusi job ini
    pub executor_peer_id: String,
    // ========== PATCH #7a: Tambah submitter_peer_id untuk callback ==========
    /// Submitter yang mengirim job (untuk callback hasil)
    pub submitter_peer_id: String,
    // ========================================================================
    /// Timestamp selesai
    pub finished_at: u64,
}

// ── Error Types ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ComputeError {
    #[error("WASM compilation error: {0}")]
    CompilationError(String),

    #[error("WASM execution error: {0}")]
    ExecutionError(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    #[error("Integrity check failed: {0}")]
    IntegrityFailed(String),

    #[error("Invalid job spec: {0}")]
    InvalidSpec(String),

    #[error("Execution timed out after {0}ms")]
    Timeout(u64),

    #[error("Fuel exhausted after {0} instructions")]
    FuelExhausted(u64),

    #[error("Serialization error: {0}")]
    SerdeError(String),

    #[error("Store error: {0}")]
    StoreError(String),

    #[error("Authority denied: {0}")]
    AuthorityDenied(String),

    #[error("Executor not initialized")]
    NotInitialized,
}

// NOTE: thiserror dibutuhkan — tambahkan ke Cargo.toml:
// thiserror = "1"
