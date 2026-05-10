use crate::authority::AuthorityManager;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ==========================================
// 1. GATEWAY TYPES
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedGatewayResponse {
    pub status: u16,
    pub body: String,
}

impl VerifiedGatewayResponse {
    pub fn new(status: u16, body: String) -> Self { Self { status, body } }
}

pub fn validate_gateway_access(peer_id: &PeerId, authority: &AuthorityManager) -> Result<(), String> {
    let decision = authority.decision_for_gateway_peer(peer_id);
    if decision.allowed { Ok(()) } else {
        Err(format!("Access Denied: {}", decision.reason))
    }
}

pub fn validate_gateway_route(peer_id: &PeerId, authority: &AuthorityManager) -> Result<(), String> {
    if authority.can_route(peer_id) && authority.trust_path_exists(peer_id) { Ok(()) } else {
        Err("Route Trust Failed".into())
    }
}

// ==========================================
// 2. RATE LIMITING
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayAuditEntry {
    pub tracing_id: String,
    pub request_id: String,
    pub peer_id: String,
    pub method: String,
    pub url: String,
    pub route: Vec<String>,
    pub allowed: bool,
    pub status: Option<u16>,
    pub reason: String,
    pub ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GatewayRateLimitDecision {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_secs: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatewayRateLimitConfig {
    pub max_requests_per_minute: u32,
    pub burst: u32,
}

impl Default for GatewayRateLimitConfig {
    fn default() -> Self { Self { max_requests_per_minute: 120, burst: 30 } }
}

#[derive(Debug, Clone)]
struct GatewayTokenBucket {
    tokens: f64,
    last_refill_secs: u64,
}

#[derive(Debug, Clone)]
pub struct GatewayRateLimiter {
    config: GatewayRateLimitConfig,
    buckets: HashMap<String, GatewayTokenBucket>,
}

impl GatewayRateLimiter {
    pub fn new(config: GatewayRateLimitConfig) -> Self { Self { config, buckets: HashMap::new() } }

    pub fn allow(&mut self, peer_id: &PeerId, weight: u32) -> GatewayRateLimitDecision {
        let now = now_secs();
        let refill_rate = (self.config.max_requests_per_minute as f64) / 60.0;
        let burst = self.config.burst as f64;

        let bucket = self.buckets.entry(peer_id.to_string()).or_insert(GatewayTokenBucket {
            tokens: burst,
            last_refill_secs: now,
        });

        let elapsed = now.saturating_sub(bucket.last_refill_secs) as f64;
        bucket.tokens = (bucket.tokens + elapsed * refill_rate).min(burst);
        bucket.last_refill_secs = now;

        if bucket.tokens >= weight as f64 {
            bucket.tokens -= weight as f64;
            GatewayRateLimitDecision { allowed: true, remaining: bucket.tokens.floor() as u32, ..Default::default() }
        } else {
            let retry = ((weight as f64 - bucket.tokens) / refill_rate).ceil() as u64;
            GatewayRateLimitDecision { allowed: false, retry_after_secs: retry, reason: "rate_limit_exceeded".into(), ..Default::default() }
        }
    }
}

// ==========================================
// 3. BUILDERS (🔥 FIX E0308: Gunakan impl Into<String>)
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayRequest {
    pub message_id: String,
    pub tracing_id: String,
    pub from: String,
    pub to: String,
    pub kind: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub route: Vec<String>,
    pub nonce: String,
    pub ts: u64,
    pub encrypted: bool,
    pub sender_pubkey: String,
    pub signature: String,
}

impl GatewayRequest {
    pub fn plain(
        from: impl Into<String>,
        to: impl Into<String>,
        method: impl Into<String>,
        url: impl Into<String>,
        h: Vec<(String, String)>,
        body: impl Into<String>,
        route: Vec<String>
    ) -> Self {
        let ts = now_secs();
        let mid = format!("gw-{}", short_nonce());
        Self {
            message_id: mid.clone(),
            tracing_id: format!("trace-{}", mid),
            from: from.into(),
            to: to.into(),
            kind: "gateway_request".into(),
            method: method.into().to_uppercase(),
            url: url.into(),
            headers: h,
            body: body.into(),
            route,
            ts,
            ..Default::default()
        }
    }

    pub fn audit_entry(&self, peer_id: String, allowed: bool, status: Option<u16>, reason: String) -> GatewayAuditEntry {
        GatewayAuditEntry {
            tracing_id: self.tracing_id.clone(),
            request_id: self.message_id.clone(),
            peer_id, method: self.method.clone(),
            url: self.url.clone(), route: self.route.clone(),
            allowed, status, reason, ts: now_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayResponse {
    pub message_id: String,
    pub tracing_id: String,
    pub in_reply_to: String,
    pub from: String,
    pub to: String,
    pub kind: String,
    pub ok: bool,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub nonce: String,
    pub ts: u64,
    pub encrypted: bool,
    pub sender_pubkey: String,
    pub signature: String,
}

impl GatewayResponse {
    pub fn plain_ok(
        in_reply: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        status: u16,
        h: Vec<(String, String)>,
        body: impl Into<String>
    ) -> Self {
        Self {
            message_id: format!("gw-res-{}", short_nonce()),
            in_reply_to: in_reply.into(),
            from: from.into(), to: to.into(),
            kind: "gateway_response".into(),
            ok: true, status, headers: h,
            body: body.into(), ts: now_secs(), ..Default::default()
        }
    }

    pub fn plain_error(
        in_reply: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        err_msg: impl Into<String>
    ) -> Self {
        Self {
            message_id: format!("gw-err-{}", short_nonce()),
            in_reply_to: in_reply.into(),
            from: from.into(), to: to.into(),
            kind: "gateway_response".into(),
            ok: false, status: 502, body: err_msg.into(),
            ts: now_secs(), ..Default::default()
        }
    }
}

// --- Internal Utils ---
fn now_secs() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
fn short_nonce() -> String { format!("{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos()) }

/// Sanity probe untuk memastikan konstruktor yang mungkin belum terpakai tetap dianggap "used" oleh compiler.
pub fn gateway_api_sanity_probe() {
    // Menggunakan metode‑metode yang sebelumnya tidak terpakai
    let _ = GatewayRequest::plain(
        "peer-a", "peer-b", "GET", "/test",
        vec![("X-Test".into(), "1".into())],
        "hello",
        vec![],
    );
    let _ = GatewayResponse::plain_ok("req-1", "peer-b", "peer-a", 200, vec![], "ok");
    let _ = GatewayResponse::plain_error("req-1", "peer-b", "peer-a", "oops");
    let _ = VerifiedGatewayResponse::new(200, "test".into());
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    #[test]
    fn test_rate_limit_blocks_after_burst() {
        let config = GatewayRateLimitConfig {
            max_requests_per_minute: 10,
            burst: 3,
        };
        let mut limiter = GatewayRateLimiter::new(config);
        let peer = PeerId::random();

        // 3 request pertama harus lolos (burst)
        for _ in 0..3 {
            let dec = limiter.allow(&peer, 1);
            assert!(dec.allowed, "Request should be allowed within burst");
        }

        // Request ke-4 harus ditolak karena bucket kosong
        let dec = limiter.allow(&peer, 1);
        assert!(!dec.allowed, "Request should be rate limited after burst exhausted");
        assert!(dec.retry_after_secs > 0, "Should include retry_after_secs");
        assert_eq!(dec.reason, "rate_limit_exceeded");
    }
}
