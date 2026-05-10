//! 🌐 Network Module (Clean + Production Ready)
//! Acts as bridge between main.rs and runtime layer

pub mod runtime;
pub mod util;

/// Main Network Entry Point (with Authority + Dashboard + Ghost + Security)
///
/// This is the only public entry used by main.rs.
pub use runtime::run;
