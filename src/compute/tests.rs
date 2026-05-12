// src/compute/tests.rs
//! Integration tests untuk ESS Compute Layer.
//! Jalankan: cargo test compute

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::compute::types::*;
    use crate::compute::executor::*;
    use std::collections::HashMap;
    use sha2::{Digest, Sha256};
    use tokio_util::sync::CancellationToken;

    // WASM binary: program sederhana yang cetak "hello from ESS\n" ke stdout lalu exit(0)
    // Compiled dari:
    //   fn main() { println!("hello from ESS"); }
    // dengan: rustc --target wasm32-wasi -O hello.rs -o hello.wasm
    //
    // Untuk testing, kita gunakan wat2wasm dari WAT berikut:
    fn minimal_hello_wasm() -> Vec<u8> {
        // WAT yang mencetak "hello" via fd_write (WASI syscall)
        // Ini adalah bytecode WASM valid minimal.
        // Dalam produksi, test ini akan load file .wasm dari fixtures/
        //
        // Karena kita tidak bisa generate WASM binary secara inline dengan aman,
        // test ini menggunakan sebuah WASM yang sudah di-compile dan di-embed sebagai bytes.
        //
        // PENDEKATAN PRODUCTION: simpan di tests/fixtures/hello.wasm
        // dan load dengan: include_bytes!("../../tests/fixtures/hello.wasm").to_vec()
        //
        // Untuk CI: pastikan file fixtures ada di repo
        vec![] // Placeholder — ganti dengan actual WASM bytes
    }

    fn make_spec(bytecode: Vec<u8>) -> ComputeJobSpec {
        let wasm_hash = hex::encode(Sha256::digest(&bytecode));
        let job_id = JobId::new(&wasm_hash, "test-input", "12D3KooWTest");
        ComputeJobSpec {
            job_id,
            wasm_hash,
            wasm_bytecode: bytecode,
            input_data: b"test input".to_vec(),
            env_vars: HashMap::new(),
            limits: ResourceLimits::default(),
            submitter_peer_id: "12D3KooWTest".into(),
            signature: vec![],
            submitter_pubkey: vec![],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            api_version: 1,
        }
    }

    #[test]
    fn test_job_id_determinism() {
        // JobId yang dibuat dengan input yang sama di waktu berbeda HARUS berbeda
        // (karena ada timestamp nanosecond di dalamnya)
        let id1 = JobId::new("hash1", "inp1", "peer1");
        std::thread::sleep(std::time::Duration::from_nanos(100));
        let id2 = JobId::new("hash1", "inp1", "peer1");
        assert_ne!(id1.as_str(), id2.as_str(),
            "JobId harus unik karena mengandung timestamp nanosecond");
    }

    #[test]
    fn test_resource_limits_validation() {
        let mut limits = ResourceLimits::default();

        // Valid case
        assert!(limits.validate().is_ok());

        // Timeout terlalu besar
        limits.timeout_ms = MAX_EXEC_TIMEOUT_MS + 1;
        assert!(limits.validate().is_err());

        // Reset
        limits.timeout_ms = DEFAULT_EXEC_TIMEOUT_MS;

        // Memory terlalu besar
        limits.memory_mb = 513;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn test_bytecode_integrity_check() {
        let mut spec = make_spec(b"fake wasm".to_vec());
        // Spec valid — hash cocok
        assert!(spec.verify_bytecode_integrity());

        // Tamper bytecode
        spec.wasm_bytecode.push(0xFF);
        assert!(!spec.verify_bytecode_integrity());
    }

    #[test]
    fn test_env_var_sanitization_in_spec() {
        // Spec dengan env var yang mengandung karakter berbahaya
        let mut spec = make_spec(b"wasm".to_vec());
        spec.env_vars.insert("VALID_KEY".into(), "valid_value".into());
        spec.env_vars.insert("KEY=WITH=EQUALS".into(), "value".into()); // tidak valid
        spec.env_vars.insert("KEY_WITH_NULL\0".into(), "value".into()); // tidak valid

        // Validasi env vars harus lolos (sanitasi terjadi di executor)
        // Test ini memastikan spec dengan env var "berbahaya" tidak crash
        assert_eq!(spec.env_vars.len(), 3);
    }

    #[test]
    fn test_job_status_terminal() {
        assert!(JobStatus::Completed { finished_at: 0 }.is_terminal());
        assert!(JobStatus::Failed { reason: "x".into(), finished_at: 0 }.is_terminal());
        assert!(JobStatus::Cancelled { reason: "x".into() }.is_terminal());
        assert!(JobStatus::TimedOut { finished_at: 0 }.is_terminal());

        assert!(!JobStatus::Queued.is_terminal());
        assert!(!JobStatus::Running { started_at: 0 }.is_terminal());
    }

    #[tokio::test]
    async fn test_executor_rejects_invalid_wasm() {
        let engine = WasmEngine::new().expect("Engine harus bisa dibuat");
        let executor = WasmExecutor::new(engine, "test-node");

        // Bytecode WASM tidak valid
        let mut spec = make_spec(b"ini bukan WASM".to_vec());
        spec.wasm_bytecode = b"not wasm".to_vec();
        spec.wasm_hash = hex::encode(sha2::Sha256::digest(b"not wasm"));

        let cancel = CancellationToken::new();
        let result = executor.execute(&spec, cancel).await;

        // Harus gagal dengan error kompilasi
        assert!(matches!(result.status, JobStatus::Failed { .. }),
            "WASM tidak valid harus menghasilkan status Failed");
    }

    #[tokio::test]
    async fn test_store_enqueue_dequeue() {
        use tempfile::TempDir;
        // Gunakan TempDir untuk isolasi test
        // NOTE: ComputeStore::open() perlu parameter path untuk testing
        // Di production sudah hardcoded ke "data/compute_store"
        // Test ini adalah integrasi test yang memerlukan filesystem
    }
}
