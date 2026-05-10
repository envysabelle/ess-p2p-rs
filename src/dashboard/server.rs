use crate::dashboard::{handle_dashboard_http, DashboardService, DashboardHttpResponse};
use std::io;
use subtle::ConstantTimeEq;
use rand::RngCore;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        401 => "Unauthorized",
        _ => "OK",
    }
}

fn build_http_response(
    status: u16,
    content_type: &str,
    headers: &[(String, String)],
    body: &str,
) -> String {
    let mut response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        status,
        reason_phrase(status),
        content_type,
        body.len()
    );

    // [FIX M-13] Add security headers to every response
    response.push_str("Access-Control-Allow-Origin: http://localhost:8080\r\n");
    response.push_str("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
    response.push_str("Access-Control-Allow-Headers: Authorization, Content-Type\r\n");
    response.push_str("X-Content-Type-Options: nosniff\r\n");
    response.push_str("X-Frame-Options: DENY\r\n");

    for (k, v) in headers {
        response.push_str(&format!("{k}: {v}\r\n"));
    }

    response.push_str("\r\n");
    response.push_str(body);
    response
}

// [FIX C-02] Constant-time token comparison to prevent timing side-channel attacks
fn verify_token_constant_time(expected: &[u8], provided: &[u8]) -> bool {
    if expected.len() != provided.len() {
        // still run ct_eq on same-length dummy to avoid length-oracle side-channel
        let _ = expected.ct_eq(expected);
        return false;
    }
    expected.ct_eq(provided).into()
}

pub async fn serve_dashboard_http(
    service: DashboardService,
    bind_addr: &str,
    dashboard_token: Option<String>,
) -> io::Result<()> {
    // [FIX M-16] Always enforce token authentication; auto-generate if missing
    let token = match dashboard_token {
        Some(t) => t,
        None => {
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            let token = B64.encode(bytes);
            tracing::warn!(
                "[DASHBOARD] No ESS_DASHBOARD_TOKEN set. Generated random token: Bearer {}",
                token
            );
            token
        }
    };

    let listener = TcpListener::bind(bind_addr).await?;
    println!("[DASHBOARD][HTTP] listening on {bind_addr}");

    loop {
        let (mut socket, _) = listener.accept().await?;
        let svc = service.clone();
        let token = token.clone();

        tokio::spawn(async move {
            // [FIX H-09] Use a larger buffer and proper read-until-headers-complete loop
            const MAX_HEADER_SIZE: usize = 16_384; // 16 KiB for headers
            const MAX_BODY_SIZE: usize = 1_048_576; // 1 MiB body limit
            let mut header_buf = Vec::with_capacity(MAX_HEADER_SIZE);
            let mut tmp = [0u8; 4096];

            // Read until we find the header/body boundary \r\n\r\n
            let header_end = loop {
                match socket.read(&mut tmp).await {
                    Ok(0) => return,
                    Ok(n) => {
                        header_buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        if header_buf.len() > MAX_HEADER_SIZE {
                            return; // header too large, abort
                        }
                    }
                    Err(_) => return,
                }
            };

            let req_str = match String::from_utf8(header_buf[..header_end].to_vec()) {
                Ok(s) => s,
                Err(_) => return,
            };

            let mut lines = req_str.lines();
            let request_line = lines.next().unwrap_or("");
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("GET");
            let full_path = parts.next().unwrap_or("/");

            let (path, query) = match full_path.split_once('?') {
                Some((p, q)) => (p, Some(q)),
                None => (full_path, None),
            };

            let accept_json = req_str.lines().any(|line| {
                line.to_ascii_lowercase().starts_with("accept:")
                    && line.contains("application/json")
            });

            // Read body up to Content-Length (bounded by MAX_BODY_SIZE)
            let body = if method.to_ascii_uppercase() == "POST" {
                let content_length = req_str
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|line| {
                        line.split_once(':')
                            .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                    });

                if let Some(len) = content_length {
                    let to_read = len.min(MAX_BODY_SIZE);
                    let already = header_buf.len().saturating_sub(header_end);
                    let mut body_buf = header_buf[header_end..].to_vec();
                    // Read remaining bytes
                    while body_buf.len() < to_read {
                        match socket.read(&mut tmp).await {
                            Ok(0) => break,
                            Ok(n) => body_buf.extend_from_slice(&tmp[..n]),
                            Err(_) => break,
                        }
                    }
                    let _ = already; // suppress unused warning
                    String::from_utf8(body_buf[..body_buf.len().min(to_read)].to_vec()).ok()
                } else {
                    None
                }
            } else {
                None
            };

            // [FIX M-16] Always enforce token authentication
            let provided = req_str
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .and_then(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()))
                .unwrap_or_default();
            let expected_bearer = format!("Bearer {}", token);
            let authorized = verify_token_constant_time(expected_bearer.as_bytes(), provided.as_bytes());

            let handled = if authorized {
                handle_dashboard_http(&svc, method, path, query, accept_json, body.as_deref(), Some(token.as_str())).await
            } else {
                Some(DashboardHttpResponse {
                    status: 401,
                    content_type: "application/json".to_string(),
                    headers: vec![],
                    body: r#"{"ok":false,"error":"unauthorized"}"#.to_string(),
                })
            };

            let response = match handled {
                Some(res) => {
                    build_http_response(res.status, &res.content_type, &res.headers, &res.body)
                }
                None => build_http_response(404, "text/plain; charset=utf-8", &[], "not found"),
            };

            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
    }
}
