use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn normalize_string_list(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = items
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    out.sort();
    out.dedup();
    out
}

fn normalize_role(role: &str) -> String {
    role.trim().to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Konfigurasi onion routing (STEP 1)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Jumlah hop onion (0 = nonaktif, 3 = nilai default)
    pub onion_hops: usize,
    /// Ukuran payload setelah padding (0 = tanpa padding, 1400 = default)
    pub onion_payload_size: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            onion_hops: 3,
            onion_payload_size: 1400,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigBundle {
    pub role: String,
    pub policy_version: u64,
    pub allowed_peers: Vec<String>,
    pub bootstrap_addrs: Vec<String>,
    pub issued_at: u64,
}

impl ConfigBundle {
    pub fn normalized(mut self) -> Self {
        self.role = normalize_role(&self.role);
        self.allowed_peers = normalize_string_list(self.allowed_peers);
        self.bootstrap_addrs = normalize_string_list(self.bootstrap_addrs);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigRequest {
    pub message_id: String,
    pub from: String,
    pub to: String,
    pub kind: String,
    pub body: String,
    pub nonce: String,
    pub ts: u64,
    pub encrypted: bool,
    pub sender_pubkey: String,
    pub signature: String,
}

impl ConfigRequest {
    // AKTIVASI: Digunakan oleh security_runtime untuk request otonom
    pub fn plain(from: impl Into<String>, to: impl Into<String>, body: impl Into<String>) -> Self {
        let ts = now_secs();
        Self {
            message_id: format!("cfg-{ts}"),
            from: from.into(),
            to: to.into(),
            kind: "config_request".to_string(),
            body: body.into(),
            ts,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigResponse {
    pub message_id: String,
    pub in_reply_to: String,
    pub from: String,
    pub to: String,
    pub ok: bool,
    pub kind: String,
    pub body: String,
    pub nonce: String,
    pub ts: u64,
    pub encrypted: bool,
    pub sender_pubkey: String,
    pub signature: String,
}

impl ConfigResponse {
    pub fn plain_ok(
        in_reply_to: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        let ts = now_secs();
        Self {
            message_id: format!("cfg-resp-{ts}"),
            in_reply_to: in_reply_to.into(),
            from: from.into(),
            to: to.into(),
            ok: true,
            kind: "config_response".to_string(),
            body: body.into(),
            ts,
            ..Default::default()
        }
    }

    pub fn plain_error(
        in_reply_to: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        let ts = now_secs();
        Self {
            message_id: format!("cfg-resp-{ts}"),
            in_reply_to: in_reply_to.into(),
            from: from.into(),
            to: to.into(),
            ok: false,
            kind: "config_response".to_string(),
            body: body.into(),
            ts,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_bundle_normalized_dedup_bootstrap() {
        let bundle = ConfigBundle {
            role: "  client  ".into(),
            policy_version: 1,
            allowed_peers: vec![" peer1 ".into(), " peer1 ".into()],
            bootstrap_addrs: vec!["/ip4/0.0.0.0/tcp/0".into()],
            issued_at: 0,
        }.normalized();
        assert_eq!(bundle.role, "client");
        assert_eq!(bundle.allowed_peers.len(), 1);
    }
}
