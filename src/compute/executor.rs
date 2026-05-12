// src/compute/executor.rs
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use log::warn;
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;      // builder tetap dari wasmtime_wasi
use wasi_common::WasiCtx;              // tipe state yang cocok dengan add_to_linker

use crate::compute::types::{ComputeError, ComputeJobSpec, ComputeResult, JobStatus};

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

        let wasi_ctx = WasiCtxBuilder::new().build(); // menghasilkan WasiCtx dari wasi_common

        struct JobHostState {
            wasi: WasiCtx,   // wasi_common::WasiCtx
        }

        let mut store = Store::new(&self.engine, JobHostState { wasi: wasi_ctx });

        // Fuel
        store.set_fuel(spec.limits.fuel_limit)
            .map_err(|e| ComputeError::ExecutionError(format!("Fuel set: {e}")))?;

        let mut linker = Linker::new(&self.engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s: &mut JobHostState| &mut s.wasi)
            .map_err(|e| ComputeError::ExecutionError(format!("Linker: {e}")))?;

        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .map_err(|e| ComputeError::ExecutionError(format!("Instantiate: {e}")))?;

        // Execute entry point
        let run_result = if let Ok(start_func) = instance.get_typed_func::<(), ()>(&mut store, "_start") {
            start_func.call_async(&mut store, ()).await
        } else if let Ok(main_func) = instance.get_typed_func::<(), ()>(&mut store, "main") {
            main_func.call_async(&mut store, ()).await
        } else {
            warn!("[EXECUTOR] No _start or main function");
            Ok(())
        };

        let fuel_consumed = spec.limits.fuel_limit - store.get_fuel().unwrap_or(0);
        let exec_time_ms = start.elapsed().unwrap_or_default().as_millis() as u64;
        let finished_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match run_result {
            Ok(()) => Ok(ComputeResult {
                job_id: spec.job_id,
                status: JobStatus::Completed { finished_at },
                output: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
                fuel_consumed,
                exec_time_ms,
                memory_used_bytes: 0,
                executor_peer_id,
                finished_at,
            }),
            Err(e) => Ok(ComputeResult {
                job_id: spec.job_id,
                status: JobStatus::Failed {
                    reason: format!("{e}"),
                    finished_at,
                },
                output: Vec::new(),
                stderr: format!("{e}").into_bytes(),
                exit_code: -1,
                fuel_consumed,
                exec_time_ms,
                memory_used_bytes: 0,
                executor_peer_id,
                finished_at,
            }),
        }
    }
}
