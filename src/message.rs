use crate::authority::NodeRole;
use crate::onion::OnionLayer; // ← tambahan untuk onion routing
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// --- Internal Helpers ---

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn short_nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:x}")
}

fn normalize_text(s: &str) -> String {
    s.trim().to_string()
}

fn normalize_message_type(message_type: &str) -> String {
    match message_type.trim().to_ascii_lowercase().as_str() {
        "control" => "control".to_string(),
        _ => "data".to_string(),
    }
}

// ==========================================
// 1. DIRECT REQUEST STRUCT
// ==========================================
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectRequest {
    pub message_id: String,
    pub from: String,
    pub to: String,
    pub kind: String,
    pub message_type: String,
    pub priority: u8,
    pub batch_id: String,
    pub batch_index: u32,
    pub batch_size: u32,
    pub body: Vec<u8>,
    pub nonce: String,
    pub ts: u64,
    pub encrypted: bool,
    pub sender_pubkey: String,
    #[serde(default)]
    pub sender_role: Option<NodeRole>,
    pub signature: String,
}

impl DirectRequest {
    /// Membuat DirectRequest baru dengan body dari string (diubah ke bytes).
    pub fn plain(from: impl Into<String>, to: impl Into<String>, body: impl Into<String>) -> Self {
        let ts = now_secs();
        let body: String = body.into();
        Self {
            message_id: format!("dm-{ts}-{}", short_nonce()),
            from: from.into(),
            to: to.into(),
            kind: "message".to_string(),
            message_type: "data".to_string(),
            priority: 5,
            body: body.into_bytes(),
            ts,
            ..Default::default()
        }.normalized()
    }

    /// Membuat DirectRequest dengan body yang sudah berupa `Vec<u8>`.
    pub fn plain_bytes(from: impl Into<String>, to: impl Into<String>, body: Vec<u8>) -> Self {
        let ts = now_secs();
        Self {
            message_id: format!("dm-{ts}-{}", short_nonce()),
            from: from.into(),
            to: to.into(),
            kind: "message".to_string(),
            message_type: "data".to_string(),
            priority: 5,
            body,
            ts,
            ..Default::default()
        }.normalized()
    }

    pub fn normalized(mut self) -> Self {
        self.message_id = normalize_text(&self.message_id);
        self.from = normalize_text(&self.from);
        self.to = normalize_text(&self.to);
        self.kind = normalize_text(&self.kind);
        self.message_type = normalize_message_type(&self.message_type);
        self.signature = normalize_text(&self.signature);
        self
    }

    pub fn signature_material(&self, clear_body: &[u8]) -> Vec<u8> {
        let mut material = Vec::new();
        material.extend_from_slice(self.message_id.as_bytes()); material.push(b'|');
        material.extend_from_slice(self.from.as_bytes()); material.push(b'|');
        material.extend_from_slice(self.to.as_bytes()); material.push(b'|');
        material.extend_from_slice(self.kind.as_bytes()); material.push(b'|');
        material.extend_from_slice(self.message_type.as_bytes()); material.push(b'|');
        material.extend_from_slice(&self.priority.to_ne_bytes()); material.push(b'|');
        material.extend_from_slice(self.batch_id.as_bytes()); material.push(b'|');
        material.extend_from_slice(&self.batch_index.to_ne_bytes()); material.push(b'|');
        material.extend_from_slice(&self.batch_size.to_ne_bytes()); material.push(b'|');
        material.extend_from_slice(&self.ts.to_ne_bytes()); material.push(b'|');
        material.extend_from_slice(self.nonce.as_bytes()); material.push(b'|');
        material.extend_from_slice(self.sender_pubkey.as_bytes()); material.push(b'|');
        material.extend_from_slice(clear_body);
        material
    }
}

// ==========================================
// 2. DIRECT RESPONSE STRUCT
// ==========================================
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectResponse {
    pub message_id: String,
    pub in_reply_to: String,
    pub from: String,
    pub to: String,
    pub ok: bool,
    pub kind: String,
    pub message_type: String,
    pub priority: u8,
    pub batch_id: String,
    pub batch_index: u32,
    pub batch_size: u32,
    pub body: Vec<u8>,
    pub nonce: String,
    pub ts: u64,
    pub encrypted: bool,
    pub sender_pubkey: String,
    #[serde(default)]
    pub sender_role: Option<NodeRole>,
    pub signature: String,
}

impl DirectResponse {
    /// Membuat response sukses dengan body dari string (diubah ke bytes).
    pub fn plain_ok(in_reply_to: impl Into<String>, from: impl Into<String>, to: impl Into<String>, body: impl Into<String>) -> Self {
        let ts = now_secs();
        let body: String = body.into();
        Self {
            message_id: format!("dm-resp-{ts}-{}", short_nonce()),
            in_reply_to: in_reply_to.into(),
            from: from.into(),
            to: to.into(),
            ok: true,
            kind: "response".to_string(),
            message_type: "data".to_string(),
            priority: 5,
            body: body.into_bytes(),
            ts,
            ..Default::default()
        }.normalized()
    }

    /// Membuat response sukses dengan body bytes langsung.
    pub fn plain_ok_bytes(in_reply_to: impl Into<String>, from: impl Into<String>, to: impl Into<String>, body: Vec<u8>) -> Self {
        let ts = now_secs();
        Self {
            message_id: format!("dm-resp-{ts}-{}", short_nonce()),
            in_reply_to: in_reply_to.into(),
            from: from.into(),
            to: to.into(),
            ok: true,
            kind: "response".to_string(),
            message_type: "data".to_string(),
            priority: 5,
            body,
            ts,
            ..Default::default()
        }.normalized()
    }

    /// Membuat response error dengan body dari string (diubah ke bytes).
    pub fn plain_error(in_reply_to: impl Into<String>, from: impl Into<String>, to: impl Into<String>, body: impl Into<String>) -> Self {
        let ts = now_secs();
        let body: String = body.into();
        Self {
            message_id: format!("dm-resp-{ts}-{}", short_nonce()),
            in_reply_to: in_reply_to.into(),
            from: from.into(),
            to: to.into(),
            ok: false,
            kind: "error".to_string(),
            message_type: "control".to_string(),
            priority: 1,
            body: body.into_bytes(),
            ts,
            ..Default::default()
        }.normalized()
    }

    pub fn normalized(mut self) -> Self {
        self.message_id = normalize_text(&self.message_id);
        self.in_reply_to = normalize_text(&self.in_reply_to);
        self.from = normalize_text(&self.from);
        self.to = normalize_text(&self.to);
        self.kind = normalize_text(&self.kind);
        // body sudah Vec<u8>, tidak dinormalisasi
        self.signature = normalize_text(&self.signature);
        self
    }

    pub fn signature_material(&self, clear_body: &[u8]) -> Vec<u8> {
        let mut material = Vec::new();
        material.extend_from_slice(self.message_id.as_bytes()); material.push(b'|');
        material.extend_from_slice(self.in_reply_to.as_bytes()); material.push(b'|');
        material.extend_from_slice(self.from.as_bytes()); material.push(b'|');
        material.extend_from_slice(self.to.as_bytes()); material.push(b'|');
        material.extend_from_slice(if self.ok { b"true" } else { b"false" }); material.push(b'|');
        material.extend_from_slice(self.kind.as_bytes()); material.push(b'|');
        material.extend_from_slice(self.message_type.as_bytes()); material.push(b'|');
        material.extend_from_slice(&self.priority.to_ne_bytes()); material.push(b'|');
        material.extend_from_slice(self.batch_id.as_bytes()); material.push(b'|');
        material.extend_from_slice(&self.batch_index.to_ne_bytes()); material.push(b'|');
        material.extend_from_slice(&self.batch_size.to_ne_bytes()); material.push(b'|');
        material.extend_from_slice(&self.ts.to_ne_bytes()); material.push(b'|');
        material.extend_from_slice(self.nonce.as_bytes()); material.push(b'|');
        material.extend_from_slice(self.sender_pubkey.as_bytes()); material.push(b'|');
        material.extend_from_slice(clear_body);
        material
    }
}

// ==========================================
// 3. ONION RELAY MESSAGES (STEP 2)
// ==========================================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionRelayRequest {
    pub layer: OnionLayer,
    pub hop: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionRelayResponse {
    pub success: bool,
    pub error: Option<String>,
}

// ==========================================
// 4. UNIFIED REQUEST / RESPONSE ENUMS
// ==========================================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EssRequest {
    DirectRequest(DirectRequest),
    OnionRelay(OnionRelayRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EssResponse {
    DirectResponse(DirectResponse),
    OnionRelay(OnionRelayResponse),
}

// ==========================================
// 5. SANITY PROBE & TESTS
// ==========================================
pub fn message_api_sanity_probe() {
    let req = DirectRequest::plain("peer-a", "peer-b", "hello");
    let _ = req.signature_material(b"hello");
    let resp = DirectResponse::plain_ok("msg-1", "peer-b", "peer-a", "ok");
    let _ = resp.signature_material(b"ok");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_request_normalized() {
        let req = DirectRequest::plain("  peer-A  ", "  peer-B  ", " hello ");
        assert_eq!(req.from, "peer-A");
        assert_eq!(req.to, "peer-B");
        // body sekarang Vec<u8>; bandingkan dengan bytes dari "hello"
        assert_eq!(req.body, b"hello".to_vec());
    }

    #[test]
    fn test_signature_material_same_for_same_input() {
        let req = DirectRequest::plain("a", "b", "data");
        let m1 = req.signature_material(b"data");
        let m2 = req.signature_material(b"data");
        assert_eq!(m1, m2);
    }
}
