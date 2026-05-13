use chrono::Utc;
use serde_json::{json, Value};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use super::service::DashboardService;
// ── Compute-related imports (PATCH #6) ────────────────────────────────
use crate::compute::types::ComputeJobSpec;

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn world_payload(service: &DashboardService) -> Value {
    match service.world_snapshot() {
        Some(snapshot) => {
            let authority_hash_full = snapshot
                .authority_hash
                .clone()
                .unwrap_or_else(|| "none".to_string());

            json!({
                "available": true,
                "authority_version": snapshot.authority_version,
                "authority_hash": authority_hash_full,
                "ghost_state": snapshot.ghost_state,
                "health_level": snapshot.health_level,
                "connected_peers": snapshot.connected_peers,
                "known_peers": snapshot.known_peers,
                "route_peers": snapshot.route_peers,
                "trusted_peers": snapshot.trusted_peers,
                "last_signal": snapshot.last_signal.clone().unwrap_or_else(|| "-".to_string()),
                "last_updated_at": snapshot.last_updated_display(),
            })
        }
        None => json!({
            "available": false,
            "authority_version": 0,
            "authority_hash": "none",
            "ghost_state": "unknown",
            "health_level": "unknown",
            "connected_peers": 0,
            "known_peers": 0,
            "route_peers": 0,
            "trusted_peers": 0,
            "last_signal": "-",
            "last_updated_at": "unknown",
        }),
    }
}

pub async fn dashboard_payload(service: &DashboardService) -> Value {
    let summary = service.summary().await;
    let world = world_payload(service);

    // Storage stats integration (from patch)
    let storage_stats = service.storage_stats();

    json!({
        "ok": true,
        "timestamp": now(),
        "summary": {
            "total_nodes": summary.total_nodes,
            "supernodes": summary.supernodes,
            "relays": summary.relays,
            "clients": summary.clients,
            "healthy_nodes": summary.healthy_nodes,
            "degraded_nodes": summary.degraded_nodes,
            "critical_nodes": summary.critical_nodes,
            "connected_peers": summary.connected_peers,
            "known_peers": summary.known_peers,
            "route_peers": summary.route_peers,
            "trusted_peers": summary.trusted_peers,
            "updated_at": summary.updated_at,
            "status": summary.status,
        },
        "cluster": {
            "total_nodes": summary.total_nodes,
            "supernodes": summary.supernodes,
            "relays": summary.relays,
            "clients": summary.clients,
            "healthy_nodes": summary.healthy_nodes,
            "degraded_nodes": summary.degraded_nodes,
            "critical_nodes": summary.critical_nodes,
        },
        "network": {
            "connected_peers": summary.connected_peers,
            "known_peers": summary.known_peers,
            "route_peers": summary.route_peers,
            "trusted_peers": summary.trusted_peers,
        },
        "world": world,
        "storage": {
            "objects_stored": storage_stats.objects_stored,
            "chunks_stored": storage_stats.chunks_stored,
            "bytes_stored": storage_stats.bytes_stored,
            "bytes_served": storage_stats.bytes_served,
        },
        "status": summary.status,
    })
}

pub async fn nodes_payload(service: &DashboardService) -> Value {
    let nodes = service.nodes().await;

    json!({
        "ok": true,
        "timestamp": now(),
        "nodes": nodes,
    })
}

pub async fn node_payload(service: &DashboardService, node_id: &str) -> Value {
    match service.node_detail(node_id).await {
        Some(node) => json!({
            "ok": true,
            "timestamp": now(),
            "node": node,
        }),
        None => json!({
            "ok": false,
            "timestamp": now(),
            "error": "not_found",
            "node_id": node_id,
        }),
    }
}

pub async fn routes_payload(service: &DashboardService) -> Value {
    let routes = service.routes().await;

    json!({
        "ok": true,
        "timestamp": now(),
        "routes": routes,
    })
}

pub async fn logs_payload(
    service: &DashboardService,
    limit: usize,
    level: Option<&str>,
    node_id: Option<&str>,
) -> Value {
    let logs = service.logs(limit, level, node_id).await;

    json!({
        "ok": true,
        "timestamp": now(),
        "logs": logs,
    })
}

// 🔥 Authority Snapshot endpoint
pub fn authority_payload(service: &DashboardService) -> Value {
    match service.get_authority_state() {
        Ok(auth_state) => {
            json!({
                "ok": true,
                "timestamp": now(),
                "authority": {
                    "version": auth_state.version,
                    "root": {
                        "name": auth_state.root.name,
                        "issuer": auth_state.root.issuer,
                        "active": auth_state.root.active,
                        "updated_at": auth_state.root.updated_at,
                    },
                    "supernodes": auth_state.supernodes,
                    "allowed_peers_count": auth_state.allowed_peers.len(),
                    "policies": {
                        "max_connections": auth_state.policies.max_connections,
                        "allow_unknown_peers": auth_state.policies.allow_unknown_peers,
                        "require_signed_messages": auth_state.policies.require_signed_messages,
                        "allow_gateway_traffic": auth_state.policies.allow_gateway_traffic,
                        "allow_route_transit": auth_state.policies.allow_route_transit,
                        "allow_web_traffic": auth_state.policies.allow_web_traffic,
                    },
                    "hash": B64.encode(&auth_state.hash),
                    "signature": B64.encode(&auth_state.signature),
                }
            })
        }
        Err(e) => json!({
            "ok": false,
            "timestamp": now(),
            "error": e,
        }),
    }
}

// ──────────────────────────────────────────────
//  Policy management endpoints
// ──────────────────────────────────────────────

pub async fn policy_status_payload(service: &DashboardService) -> Value {
    match service.policy_status() {
        Ok(config) => json!({ "ok": true, "policy": config }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

pub async fn policy_export_payload(service: &DashboardService) -> Value {
    match service.export_policy_rules() {
        Ok(json_str) => json!({ "ok": true, "rules": json_str }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

pub async fn policy_reload_payload(service: &DashboardService) -> Value {
    match service.reload_policy() {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

// ──────────────────────────────────────────────
//  Send direct message endpoint (NEW)
// ──────────────────────────────────────────────

pub async fn send_message_payload(service: &DashboardService, peer_id: &str, message: &str) -> Value {
    match peer_id.parse::<libp2p::PeerId>() {
        Ok(peer) => {
            match service.send_direct_message(peer, message.to_string()).await {
                Ok(reply) => json!({
                    "ok": true,
                    "timestamp": now(),
                    "reply": reply,
                }),
                Err(e) => json!({
                    "ok": false,
                    "timestamp": now(),
                    "error": e,
                }),
            }
        }
        Err(e) => json!({
            "ok": false,
            "timestamp": now(),
            "error": format!("Invalid peer_id: {}", e),
        }),
    }
}

// ── Compute endpoint handlers (PATCH #6) ────────────────────────────────────────

/// POST /api/ess/compute/submit  body: JSON ComputeJobSpec
pub async fn handle_compute_submit(
    service: &DashboardService,
    body: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let handle = service.compute_handle()?;
    let spec: ComputeJobSpec = serde_json::from_str(body)?;
    let job_id = handle.submit_job(spec).await?;
    Ok(json!({"ok":true,"job_id":job_id.0}))
}

/// GET /api/ess/compute/status/:job_id
pub async fn handle_compute_status(
    service: &DashboardService,
    job_id: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let store = service.compute_store()?;
    let result = store.get_result(job_id)?;
    match result {
        Some(res) => Ok(json!({
            "ok": true,
            "job_id": job_id,
            "status": res.status.as_str(),
            "output": B64.encode(&res.output),
            "stderr": B64.encode(&res.stderr),
            "exec_time_ms": res.exec_time_ms,
            "fuel_consumed": res.fuel_consumed,
            "exit_code": res.exit_code,
            "executor_peer_id": res.executor_peer_id,
        })),
        None => Err("job not found".into()),
    }
}

// ── Compute capacity / stats endpoints (untuk menghilangkan warning) ─────────

/// GET /api/ess/compute/capacity
pub async fn handle_compute_capacity(
    service: &DashboardService,
) -> Result<Value, Box<dyn std::error::Error>> {
    service.compute_capacity().map_err(|e| e.into())
}

/// GET /api/ess/compute/stats
pub async fn handle_compute_stats(
    service: &DashboardService,
) -> Result<Value, Box<dyn std::error::Error>> {
    service.compute_store_stats().map_err(|e| e.into())
}

/// GET /api/ess/compute/db-stats
pub async fn handle_compute_db_stats(
    service: &DashboardService,
) -> Result<Value, Box<dyn std::error::Error>> {
    service.compute_db_stats().map_err(|e| e.into())
}
