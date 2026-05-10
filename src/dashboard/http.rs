// src/dashboard/http.rs
use serde_json::Value;

use super::api::{
    dashboard_payload,
    logs_payload,
    node_payload,
    nodes_payload,
    routes_payload,
    authority_payload,
    policy_status_payload,
    policy_export_payload,
    policy_reload_payload,
    send_message_payload,
};
use super::service::DashboardService;

#[derive(Debug, Clone)]
pub struct DashboardHttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl DashboardHttpResponse {
    pub fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json; charset=utf-8".to_string(),
            body,
            headers: vec![("x-ess-dashboard".to_string(), "1".to_string())],
        }
    }

    pub fn html(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "text/html; charset=utf-8".to_string(),
            body,
            headers: vec![("x-ess-dashboard".to_string(), "1".to_string())],
        }
    }
}

fn parse_query_value(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k.trim() == key {
            return Some(v.trim().replace('+', " "));
        }
    }
    None
}

fn parse_limit(query: Option<&str>) -> usize {
    query
        .and_then(|q| parse_query_value(q, "limit"))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200)
}

fn parse_optional_str(query: Option<&str>, key: &str) -> Option<String> {
    query.and_then(|q| parse_query_value(q, key)).and_then(|v| {
        let trimmed = v.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn json_response(status: u16, value: Value) -> DashboardHttpResponse {
    DashboardHttpResponse::json(
        status,
        serde_json::to_string_pretty(&value)
            .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"serialize_failed\"}".to_string()),
    )
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub async fn handle_dashboard_http(
    service: &DashboardService,
    method: &str,
    path: &str,
    query: Option<&str>,
    accept_json: bool,
    body: Option<&str>,
    token: Option<&str>,  // Patch 1: parameter token
) -> Option<DashboardHttpResponse> {
    let method = method.trim().to_ascii_uppercase();

    if method != "GET" && method != "POST" {
        return None;
    }

    let normalized = path.trim();

    // Helper untuk cek token pada endpoint sensitif
    let require_admin = || -> Option<DashboardHttpResponse> {
        if token.is_none() {
            Some(json_response(
                403,
                serde_json::json!({"ok":false,"error":"admin token required"}),
            ))
        } else {
            None
        }
    };

    match normalized {
        "/api/ess/dashboard" => {
            if method != "GET" { return None; }
            let payload = dashboard_payload(service).await;
            Some(json_response(200, payload))
        }

        "/api/ess/nodes" => {
            if method != "GET" { return None; }
            let payload = nodes_payload(service).await;
            Some(json_response(200, payload))
        }

        "/api/ess/routes" => {
            if method != "GET" { return None; }
            let payload = routes_payload(service).await;
            Some(json_response(200, payload))
        }

        "/api/ess/logs" => {
            if method != "GET" { return None; }
            let limit = parse_limit(query);
            let level = parse_optional_str(query, "level");
            let node_id = parse_optional_str(query, "node_id")
                .or_else(|| parse_optional_str(query, "nodeId"));

            let payload = logs_payload(service, limit, level.as_deref(), node_id.as_deref()).await;
            Some(json_response(200, payload))
        }

        // [FIX M-12] Protect /api/ess/authority with require_admin() check.
        "/api/ess/authority" => {
            if method != "GET" { return None; }
            if let Some(err) = require_admin() {
                return Some(err);
            }
            let payload = authority_payload(service);
            Some(json_response(200, payload))
        }

        // Policy endpoints
        "/api/policy" => {
            if method != "GET" { return None; }
            let payload = policy_status_payload(service).await;
            Some(json_response(200, payload))
        }

        "/api/policy/export" => {
            if method != "GET" { return None; }
            let payload = policy_export_payload(service).await;
            Some(json_response(200, payload))
        }

        "/api/policy/reload" => {
            if method != "POST" { return None; }
            // Patch 1: Hanya admin yang bisa reload policy
            if let Some(err) = require_admin() {
                return Some(err);
            }
            let payload = policy_reload_payload(service).await;
            Some(json_response(200, payload))
        }

        // Send direct message endpoint
        "/api/ess/send" => {
            if method != "POST" { return None; }
            // Patch 1: Hanya admin yang bisa mengirim pesan langsung
            if let Some(err) = require_admin() {
                return Some(err);
            }
            let body_str = match body {
                Some(b) => b,
                None => return Some(json_response(400, serde_json::json!({"ok":false,"error":"missing body"}))),
            };
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(body_str);
            let payload = match parsed {
                Ok(json) => {
                    let peer_id = json["peer_id"].as_str().unwrap_or("");
                    let message = json["message"].as_str().unwrap_or("");
                    if peer_id.is_empty() || message.is_empty() {
                        serde_json::json!({"ok":false,"error":"peer_id and message required"})
                    } else {
                        send_message_payload(service, peer_id, message).await
                    }
                }
                Err(e) => serde_json::json!({"ok":false,"error":format!("invalid json: {}", e)}),
            };
            Some(json_response(200, payload))
        }

        _ if normalized.starts_with("/api/ess/nodes/") => {
            if method != "GET" { return None; }
            let node_id = normalized.trim_start_matches("/api/ess/nodes/").trim();
            if node_id.is_empty() {
                return Some(json_response(
                    400,
                    serde_json::json!({
                        "ok": false,
                        "error": "missing_node_id"
                    }),
                ));
            }

            let payload = node_payload(service, node_id).await;
            Some(json_response(200, payload))
        }

        "/" | "/dashboard" => {
            if method != "GET" { return None; }
            if accept_json {
                let payload = dashboard_payload(service).await;
                Some(json_response(200, payload))
            } else {
                let summary = service.summary().await;
                let world = service.world_snapshot();

                let authority_version = world
                    .as_ref()
                    .map(|s| s.authority_version)
                    .unwrap_or_default();

                let authority_hash = world
                    .as_ref()
                    .and_then(|s| s.authority_hash.clone())
                    .unwrap_or_else(|| "none".to_string());

                let authority_hash_short = if authority_hash == "none" {
                    "none".to_string()
                } else {
                    authority_hash.chars().take(8).collect::<String>()
                };

                let ghost_state = world
                    .as_ref()
                    .map(|s| s.ghost_state.clone())
                    .unwrap_or_else(|| "unknown".to_string());

                let health_level = world
                    .as_ref()
                    .map(|s| s.health_level.clone())
                    .unwrap_or_else(|| "unknown".to_string());

                let last_signal = world
                    .as_ref()
                    .and_then(|s| s.last_signal.clone())
                    .unwrap_or_else(|| "-".to_string());

                let body = format!(
                    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ESS Autonomous Control Plane</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      padding: 24px;
      background: #0b1020;
      color: #e9eefc;
    }}
    .card {{
      max-width: 1000px;
      margin: 0 auto;
      background: #121a33;
      border: 1px solid #263154;
      border-radius: 18px;
      padding: 20px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-top: 16px;
    }}
    .item {{
      background: rgba(255,255,255,0.03);
      border-radius: 14px;
      padding: 14px;
    }}
    .label {{ font-size: 12px; color: #9fb0dd; text-transform: uppercase; letter-spacing: .08em; }}
    .value {{ font-size: 22px; font-weight: 700; margin-top: 6px; }}
    .muted {{ color: #9fb0dd; }}
    .status-healthy {{ color: #4ade80; font-weight: bold; }}
    .status-degraded {{ color: #facc15; font-weight: bold; }}
    .status-critical {{ color: #f87171; font-weight: bold; }}
    code {{
      display: inline-block;
      padding: 2px 6px;
      border-radius: 8px;
      background: rgba(122,162,255,0.12);
      color: #cfe0ff;
      word-break: break-all;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>ESS Autonomous Control Plane</h1>
    <p>Network Status: <span class="status-{}">{}</span> • Updated: <code>{}</code></p>
    <p class="muted">
      Authority: v{} • Hash: <code title="{}">{}</code><br>
      Ghost Engine: <code>{}</code> • System Health: <span class="status-{}">{}</span><br>
      Last Autonomous Signal: <code>{}</code>
    </p>
    <div class="grid">
      <div class="item"><div class="label">Total Nodes</div><div class="value">{}</div></div>
      <div class="item"><div class="label">Healthy</div><div class="value status-healthy">{}</div></div>
      <div class="item"><div class="label">Degraded</div><div class="value status-degraded">{}</div></div>
      <div class="item"><div class="label">Critical</div><div class="value status-critical">{}</div></div>
      <div class="item"><div class="label">Network Peers</div><div class="value">{}</div></div>
      <div class="item"><div class="label">Known Identities</div><div class="value">{}</div></div>
      <div class="item"><div class="label">Active Routes</div><div class="value">{}</div></div>
      <div class="item"><div class="label">Trusted Peers</div><div class="value">{}</div></div>
    </div>
  </div>
</body>
</html>"#,
                    html_escape(&summary.status),
                    html_escape(&summary.status).to_uppercase(),
                    html_escape(&summary.updated_at),
                    authority_version,
                    html_escape(&authority_hash),
                    html_escape(&authority_hash_short),
                    html_escape(&ghost_state).to_uppercase(),
                    html_escape(&health_level),
                    html_escape(&health_level).to_uppercase(),
                    html_escape(&last_signal),
                    summary.total_nodes,
                    summary.healthy_nodes,
                    summary.degraded_nodes,
                    summary.critical_nodes,
                    summary.connected_peers,
                    summary.known_peers,
                    summary.route_peers,
                    summary.trusted_peers
                );

                Some(DashboardHttpResponse::html(200, body))
            }
        }

        _ => None,
    }
}
