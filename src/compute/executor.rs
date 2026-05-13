// src/compute/executor.rs
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasi_common::pipe::{ReadPipe, WritePipe};
use wasi_common::WasiCtx;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use std::io::Write;

use crate::compute::types::{ComputeError, ComputeJobSpec, ComputeResult, JobStatus};

struct CapturingWrite {
    buf: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl Write for CapturingWrite {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.buf.lock().unwrap();
        guard.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

unsafe impl Send for CapturingWrite {}

#[derive(Clone)]
pub struct WasmEngine {
    engine: Arc<Engine>,
}

impl WasmEngine {
    pub fn new() -> Result<Self, ComputeError> {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);
        let engine = Engine::new(&config)
            .map_err(|e| ComputeError::ExecutionError(format!("Engine creation: {e}")))?;
        Ok(Self { engine: Arc::new(engine) })
    }

    pub async fn execute(
        &self,
        spec: ComputeJobSpec,
        executor_peer_id: String,
    ) -> Result<ComputeResult, ComputeError> {
        let start = SystemTime::now();

        let module = Module::from_binary(&self.engine, &spec.wasm_bytecode)
            .map_err(|e| ComputeError::ExecutionError(format!("Module compile: {e}")))?;

        let stdin = Box::new(ReadPipe::from(spec.input_data.clone()));
        let stdout_buf = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stderr_buf = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stdout_pipe = WritePipe::new(Box::new(CapturingWrite { buf: stdout_buf.clone() }));
        let stderr_pipe = WritePipe::new(Box::new(CapturingWrite { buf: stderr_buf.clone() }));

        let mut wasi_builder = WasiCtxBuilder::new();
        wasi_builder.stdin(stdin);
        wasi_builder.stdout(Box::new(stdout_pipe));
        wasi_builder.stderr(Box::new(stderr_pipe));
        for (k, v) in &spec.env_vars {
            let _ = wasi_builder.env(k, v);
        }
        let wasi_ctx = wasi_builder.build();

        struct JobHostState { wasi: WasiCtx }
        let mut store = Store::new(&self.engine, JobHostState { wasi: wasi_ctx });

        store.set_fuel(spec.limits.fuel_limit)
            .map_err(|e| ComputeError::ExecutionError(format!("Fuel set: {e}")))?;

        let mut linker = Linker::new(&self.engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s: &mut JobHostState| &mut s.wasi)
            .map_err(|e| ComputeError::ExecutionError(format!("Linker: {e}")))?;

        let instance = linker.instantiate_async(&mut store, &module).await
            .map_err(|e| ComputeError::ExecutionError(format!("Instantiate: {e}")))?;
        drop(linker);

        let cancel_token = CancellationToken::new();
        let cancel_clone = cancel_token.clone();
        let (res_tx, res_rx) = oneshot::channel::<(Result<(), String>, u64)>();

        let limits = spec.limits.clone();
        let _exec_handle = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            let future = async {
                if let Ok(start_func) = instance.get_typed_func::<(), ()>(&mut store, "_start") {
                    start_func.call_async(&mut store, ()).await
                } else if let Ok(main_func) = instance.get_typed_func::<(), ()>(&mut store, "main") {
                    main_func.call_async(&mut store, ()).await
                } else {
                    Err(anyhow::anyhow!("no _start or main"))
                }
            };
            let result = rt.block_on(async {
                tokio::select! {
                    res = future => res.map_err(|e| e.to_string()),
                    _ = cancel_clone.cancelled() => Err("cancelled".into()),
                }
            });
            let fuel_consumed = limits.fuel_limit - store.get_fuel().unwrap_or(0);
            let _ = res_tx.send((result, fuel_consumed));
        });

        let (exec_result, fuel_consumed) = match timeout(Duration::from_millis(spec.limits.timeout_ms), res_rx).await {
            Ok(Ok((res, fuel))) => (res, fuel),
            Ok(Err(_)) => (Err("cancel channel error".to_string()), 0),
            Err(_) => {
                cancel_token.cancel();
                (Err("timeout".to_string()), 0)
            }
        };

        let exec_result: Result<(), ComputeError> = match exec_result {
            Ok(()) => Ok(()),
            Err(e) => {
                if e == "timeout" {
                    Err(ComputeError::Timeout(spec.limits.timeout_ms))
                } else {
                    Err(ComputeError::ExecutionError(e))
                }
            }
        };

        let exec_time_ms = start.elapsed().unwrap_or_default().as_millis() as u64;
        let finished_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        let output = {
            let guard = stdout_buf.lock().unwrap();
            let mut buf = guard.clone();
            buf.truncate(spec.limits.max_output_bytes);
            buf
        };
        let stderr = {
            let guard = stderr_buf.lock().unwrap();
            guard.clone()
        };

        let exit_code = if matches!(&exec_result, Ok(_)) { 0 } else { -1 };

        let status = match exec_result {
            Ok(()) => JobStatus::Completed { finished_at },
            Err(e) => JobStatus::Failed { reason: format!("{e}"), finished_at },
        };

        // ========== PATCH #7b: Isi submitter_peer_id dari spec ==========
        Ok(ComputeResult {
            job_id: spec.job_id.clone(),
            status,
            output,
            stderr,
            exit_code,
            fuel_consumed,
            exec_time_ms,
            memory_used_bytes: 0,
            executor_peer_id,
            submitter_peer_id: spec.submitter_peer_id.clone(), // <-- NEW
            finished_at,
        })
        // ================================================================
    }
}
