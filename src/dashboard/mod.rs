pub mod api;
pub mod http;
pub mod model;
pub mod server;
pub mod service;
pub mod store;

pub use http::*;
pub use model::*;
pub use server::serve_dashboard_http;
pub use service::DashboardService;
pub use store::DashboardStore;

pub fn prime_dashboard_models() {
    let _ = DashboardSummary::empty();
    let _ = RouteInfo::new("", "");
    let _ = DashboardService::new(DashboardStore::new()).store(); // konstruktor 1 argumen
    let h = NodeHealth::default();
    let _ = h.key();
}
