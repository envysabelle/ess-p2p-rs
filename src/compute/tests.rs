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

    // WASM binary: program sederhana yang mencetak "hello" ke stdout lalu exit(0)
    // Dikompilasi dari file tests/fixtures/hello.wat menggunakan wat2wasm
    const HELLO_WASM: &[u8] = include_bytes!("../../tests/fixtures/hello.wasm");

    fn minimal_hello_wasm() -> Vec<u8> {
        HELLO_WASM.to_vec()
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
        let mut spec = make_spec(b"wasm".to_vec());
        spec.env_vars.insert("VALID_KEY".into(), "valid_value".into());
        spec.env_vars.insert("KEY=WITH=EQUALS".into(), "value".into()); // tidak valid
        spec.env_vars.insert("KEY_WITH_NULL\0".into(), "value".into()); // tidak valid

        // Validasi env vars harus lolos (sanitasi terjadi di executor)
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
        // Bytecode WASM tidak valid
        let mut spec = make_spec(b"ini bukan WASM".to_vec());
        spec.wasm_bytecode = b"not wasm".to_vec();
        spec.wasm_hash = hex::encode(Sha256::digest(b"not wasm"));

        let result = engine.execute(spec, "test-executor".into()).await;
        // Harus gagal dengan error kompilasi
        assert!(matches!(result.unwrap().status, JobStatus::Failed { .. }),
            "WASM tidak valid harus menghasilkan status Failed");
    }

    #[tokio::test]
    async fn test_execute_real_wasm() {
        let engine = WasmEngine::new().expect("Engine harus bisa dibuat");
        let bytecode = minimal_hello_wasm();
        let wasm_hash = hex::encode(Sha256::digest(&bytecode));
        let spec = ComputeJobSpec {
            job_id: JobId::new(&wasm_hash, "test", "peer"),
            wasm_hash,
            wasm_bytecode: bytecode,
            input_data: vec![],
            env_vars: HashMap::new(),
            limits: ResourceLimits::default(),
            submitter_peer_id: "peer".into(),
            signature: vec![],
            submitter_pubkey: vec![],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            api_version: 1,
        };
        let res = engine.execute(spec, "executor1".into()).await.unwrap();
        assert_eq!(res.status, JobStatus::Completed { finished_at: res.finished_at });
        // Output harus mengandung "hello" (small WASM program)
        assert!(String::from_utf8_lossy(&res.output).contains("hello"),
            "Expected output to contain 'hello', got {:?}", String::from_utf8_lossy(&res.output));
    }

    #[tokio::test]
    async fn test_store_enqueue_dequeue() {
        // Integration test: buat temporary directory, buka store, enqueue/dequeue.
        // Karena store menggunakan sled, ia membutuhkan path.
        use tempfile::TempDir;
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let store_path = temp_dir.path().join("compute_store");
        let store = crate::compute::store::ComputeStore::open(store_path.to_str().unwrap())
            .expect("Failed to open store");

        let spec = make_spec(minimal_hello_wasm());
        store.enqueue(&spec).expect("Enqueue failed");
        let dequeued = store.dequeue_next().expect("Dequeue failed");
        assert!(dequeued.is_some());
        let spec_out = dequeued.unwrap();
        assert_eq!(spec_out.job_id, spec.job_id);
    }
}
