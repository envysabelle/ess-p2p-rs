use crate::gateway::{GatewayRequest, GatewayResponse};
use crate::message::{DirectRequest, DirectResponse};
use crate::web::{WebRequest, WebResponse};
use crate::config::{ConfigRequest, ConfigResponse};
use std::{error::Error, fmt};

// ==========================================
// ERROR TAXONOMY
// ==========================================
#[derive(Debug)]
pub enum SecurityError {
    TimestampOutOfWindow,
    ReplayDetected,
    UnknownPeerKey,
    BadPeerIdentity,
    BadSignature,
    CryptoError(String),
    DecodeError(String),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::TimestampOutOfWindow => write!(f, "timestamp out of window"),
            SecurityError::ReplayDetected => write!(f, "replay detected (nonce reuse)"),
            SecurityError::UnknownPeerKey => write!(f, "unknown peer public key"),
            SecurityError::BadPeerIdentity => write!(f, "peer identity mismatch"),
            SecurityError::BadSignature => write!(f, "signature verification failed"),
            SecurityError::CryptoError(e) => write!(f, "crypto error: {e}"),
            SecurityError::DecodeError(e) => write!(f, "decode error: {e}"),
        }
    }
}

impl Error for SecurityError {}

// --- Signing Material Helpers ---

// Direct Request & Response – sekarang body bertipe Vec<u8>
pub(crate) fn signing_bytes_request(req: &DirectRequest, clear_body: &[u8]) -> Vec<u8> {
    req.signature_material(clear_body)
}

pub(crate) fn signing_bytes_response(resp: &DirectResponse, clear_body: &[u8]) -> Vec<u8> {
    resp.signature_material(clear_body)
}

// Gateway, Web, Config – body masih String (belum diubah)
pub(crate) fn signing_bytes_gateway_request(req: &GatewayRequest, clear_body: &str) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        req.message_id, req.from, req.to, req.method, req.url, req.ts, clear_body
    )
    .into_bytes()
}

pub(crate) fn signing_bytes_gateway_response(resp: &GatewayResponse, clear_body: &str) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        resp.message_id, resp.in_reply_to, resp.from, resp.to, resp.status, resp.ts, resp.nonce, clear_body
    )
    .into_bytes()
}

pub(crate) fn signing_bytes_web_request(req: &WebRequest, clear_body: &str) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        req.message_id, req.from, req.to, req.method, req.url, req.ts, clear_body
    )
    .into_bytes()
}

pub(crate) fn signing_bytes_web_response(resp: &WebResponse, clear_body: &str) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        resp.message_id, resp.in_reply_to, resp.from, resp.to, resp.status, resp.content_type, resp.ts, resp.nonce, clear_body
    )
    .into_bytes()
}

pub(crate) fn signing_bytes_config_request(req: &ConfigRequest) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}",
        req.message_id, req.from, req.to, req.kind, req.ts, req.nonce
    )
    .into_bytes()
}

pub(crate) fn signing_bytes_config_response(resp: &ConfigResponse) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        resp.message_id, resp.in_reply_to, resp.from, resp.to, resp.ok, resp.ts, resp.nonce, resp.body
    )
    .into_bytes()
}
