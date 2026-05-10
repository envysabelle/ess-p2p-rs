pub mod events;
pub mod runner;
pub mod support;
pub mod types;
pub mod governance;

// 🔥 FIX: Export nama fungsi yang benar sesuai runner.rs
pub use runner::run_with_dashboard_and_authority as run;

pub const PROTOCOL_VERSION: &str = "/ess/1.0.0";
pub const DIRECT_PROTOCOL: &str = "/ess/direct/1";
pub const CONFIG_PROTOCOL: &str = "/ess/config/1";
pub const GATEWAY_PROTOCOL: &str = "/ess/gateway/1";
pub const WEB_PROTOCOL: &str = "/ess/web/1";

pub mod swarm;
