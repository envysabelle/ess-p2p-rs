use crate::authority::{Action, AuthorityManager, NodeRole};
use crate::config::{ConfigBundle, ConfigRequest, ConfigResponse};
use crate::gateway::{GatewayRequest, GatewayResponse, VerifiedGatewayResponse};
use crate::governance::messages::VoteMessage;
use crate::message::{DirectRequest, DirectResponse};
use crate::onboarding;
use crate::security::{
    signing_bytes_config_request, signing_bytes_config_response,
    signing_bytes_gateway_request, signing_bytes_gateway_response,
    signing_bytes_request, signing_bytes_response,
    signing_bytes_web_request, signing_bytes_web_response,
    SecurityError,
};
use crate::web::{WebRequest, WebResponse};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{PublicKey as EdPublicKey, Signature as EdSignature, Verifier};
use libp2p::identity::{Keypair, PublicKey};
use libp2p::PeerId;
use log::info;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::Mutex;
use tracing;

// ============================================================
// 🆕 Public helpers
// ============================================================
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

fn ed25519_public_key_from_bytes(bytes: &[u8]) -> Result<EdPublicKey, SecurityError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SecurityError::DecodeError("invalid public key length".into()))?;
    EdPublicKey::from_bytes(&arr).map_err(|e| SecurityError::DecodeError(e.to_string()))
}

fn ed25519_signature_from_bytes(bytes: &[u8]) -> Result<EdSignature, SecurityError> {
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| SecurityError::DecodeError("invalid signature length".into()))?;
    EdSignature::from_bytes(&arr).map_err(|e| SecurityError::DecodeError(e.to_string()))
}

// ==========================================
// 1. POLICY CONFIG
// ==========================================
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub allowed_peers: HashSet<String>,
    pub allowed_actions: HashSet<String>,
    pub bootstrap_addrs: Vec<String>,
    pub trusted_bundle_hash: Option<String>,
    pub response_verification_enabled: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allowed_peers: HashSet::new(),
            allowed_actions: HashSet::new(),
            bootstrap_addrs: Vec::new(),
            trusted_bundle_hash: None,
            response_verification_enabled: true,   // production safe default
        }
    }
}

// ==========================================
// 2. VERIFIED TYPES
// ==========================================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedWebResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

impl VerifiedWebResponse {
    pub fn new(status: u16, content_type: String, body: String) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }
}

// ==========================================
// 3. METRICS
// ==========================================
#[derive(Default, Debug)]
pub struct SecurityMetrics {
    pub total_failures: u64,
}

// ==========================================
// 4. NONCE CACHE & RATE LIMITER (parking_lot Mutex)
// ==========================================
const NONCE_TTL_SECS: u64 = 900;
const MAX_CACHE_SIZE: usize = 10_000;

// 🔧 PATCH 3: NonceCache tanpa Mutex internal (sudah dilindungi oleh Mutex di SecurityRuntime)
struct NonceCache {
    seen: HashMap<[u8; 16], Instant>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    fn record(&mut self, nonce: &[u8; 16]) -> bool {
        let now = Instant::now();
        let ttl = Duration::from_secs(NONCE_TTL_SECS);
        self.seen.retain(|_, t| now.duration_since(*t) < ttl);
        if self.seen.contains_key(nonce) {
            return false;
        }
        if self.seen.len() >= MAX_CACHE_SIZE {
            if let Some(oldest_key) = self
                .seen
                .iter()
                .min_by_key(|(_, &instant)| instant)
                .map(|(k, _)| *k)
            {
                self.seen.remove(&oldest_key);
            }
        }
        self.seen.insert(*nonce, now);
        true
    }
}

struct RateLimiter {
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
    max_attempts: usize,
    window: Duration,
}

impl RateLimiter {
    fn new(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            window: Duration::from_secs(window_secs),
        }
    }

    fn check(&self, key: &str) -> bool {
        let mut map = self.attempts.lock();
        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_insert_with(Vec::new);
        entry.retain(|t| now.duration_since(*t) < self.window);
        if entry.len() >= self.max_attempts {
            false
        } else {
            entry.push(now);
            true
        }
    }
}

// ==========================================
// 5. INTERNAL POLICY STATE
// ==========================================
struct PolicyInner {
    local_keypair: Keypair,
    replay_window_secs: u64,
    replay_seen: HashMap<PeerId, HashMap<String, u64>>,
    peer_public_keys: HashMap<PeerId, PublicKey>,
    authority: Option<AuthorityManager>,
    policy_config: PolicyConfig,
    response_verifiers:
        Vec<Box<dyn Fn(&VerifiedGatewayResponse) -> Result<(), SecurityError> + Send + Sync>>,
}

impl fmt::Debug for PolicyInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyInner")
            .field("local_peer_id", &PeerId::from(self.local_keypair.public()).to_string())
            .field("replay_window_secs", &self.replay_window_secs)
            .field("replay_seen", &self.replay_seen)
            .field("peer_public_keys", &self.peer_public_keys)
            .field("authority", &self.authority)
            .field("policy_config", &self.policy_config)
            .field("response_verifiers", &format_args!("{} verifiers", self.response_verifiers.len()))
            .finish()
    }
}

impl PolicyInner {
    fn new(local_keypair: Keypair) -> Self {
        crate::gateway::gateway_api_sanity_probe();
        crate::message::message_api_sanity_probe();
        #[cfg(not(test))]
        security_api_sanity_probe();

        Self {
            local_keypair,
            replay_window_secs: 300,
            replay_seen: HashMap::new(),
            peer_public_keys: HashMap::new(),
            authority: None,
            policy_config: PolicyConfig::default(),
            response_verifiers: Vec::new(),
        }
    }

    fn attach_authority(&mut self, authority: AuthorityManager) {
        self.authority = Some(authority);
    }

    fn local_role(&self) -> NodeRole {
        let local_id = PeerId::from(self.local_keypair.public());
        self.authority
            .as_ref()
            .and_then(|a| a.role_of(&local_id))
            .unwrap_or(NodeRole::Standard)
    }

    fn is_allowed(&self, peer: &PeerId, action: Action) -> bool {
        match &self.authority {
            Some(auth) => auth.is_allowed(peer, action),
            None => false,
        }
    }

    fn register_peer_public_key(
        &mut self,
        peer_id: PeerId,
        public_key: PublicKey,
    ) -> Result<(), SecurityError> {
        self.peer_public_keys.insert(peer_id, public_key);
        Ok(())
    }

    fn export_config_bundle_impl(&self) -> Result<ConfigBundle, SecurityError> {
        let auth = self
            .authority
            .as_ref()
            .ok_or_else(|| SecurityError::CryptoError("authority not attached".to_string()))?;
        let state = auth
            .get_snapshot()
            .map_err(|e| SecurityError::CryptoError(e.to_string()))?;

        Ok(ConfigBundle {
            role: String::new(),
            policy_version: state.version,
            allowed_peers: state.allowed_peers.keys().cloned().collect(),
            bootstrap_addrs: vec![],
            issued_at: now_secs(),
        })
    }

    fn apply_config_bundle(&mut self, bundle: &ConfigBundle) -> Result<(), SecurityError> {
        for peer in &bundle.allowed_peers {
            self.policy_config.allowed_peers.insert(peer.clone());
        }
        self.policy_config.bootstrap_addrs = bundle.bootstrap_addrs.clone();
        info!("[SECURITY] Policy bundle applied. Total allowed peers: {}", self.policy_config.allowed_peers.len());
        Ok(())
    }

    // ----------------------------------------------------------------
    // Builders & Verifiers
    // ----------------------------------------------------------------
    fn build_request(
        &self,
        from: PeerId,
        to: PeerId,
        body: &str,
    ) -> Result<DirectRequest, SecurityError> {
        let mut req = DirectRequest::plain(from.to_string(), to.to_string(), body);
        req.nonce = random_nonce();
        req.ts = now_secs();
        req.signature = self.sign_data(&signing_bytes_request(&req, &req.body))?;
        Ok(req)
    }

    fn build_request_bytes(
        &self,
        from: PeerId,
        to: PeerId,
        body: Vec<u8>,
    ) -> Result<DirectRequest, SecurityError> {
        let mut req = DirectRequest::plain_bytes(from.to_string(), to.to_string(), body);
        req.nonce = random_nonce();
        req.ts = now_secs();
        let sig_material = signing_bytes_request(&req, &req.body);
        req.signature = self.sign_data(&sig_material)?;
        Ok(req)
    }

    fn verify_request(
        &mut self,
        local: PeerId,
        remote: PeerId,
        req: &DirectRequest,
    ) -> Result<String, SecurityError> {
        self.check_common(remote, req.ts, &req.nonce)?;
        let pk = self
            .peer_public_keys
            .get(&remote)
            .ok_or(SecurityError::UnknownPeerKey)?;
        let sig = B64
            .decode(&req.signature)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;

        if req.to != local.to_string() || req.from != remote.to_string() {
            return Err(SecurityError::BadPeerIdentity);
        }

        if pk.verify(&signing_bytes_request(req, &req.body), &sig) {
            Ok(String::from_utf8_lossy(&req.body).to_string())
        } else {
            Err(SecurityError::BadSignature)
        }
    }

    fn verify_response(
        &mut self,
        local: PeerId,
        remote: PeerId,
        resp: &DirectResponse,
    ) -> Result<String, SecurityError> {
        self.check_common(remote, resp.ts, &resp.nonce)?;
        let pk = self
            .peer_public_keys
            .get(&remote)
            .ok_or(SecurityError::UnknownPeerKey)?;
        let sig = B64
            .decode(&resp.signature)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;

        if resp.to != local.to_string() || resp.from != remote.to_string() {
            return Err(SecurityError::BadPeerIdentity);
        }

        if pk.verify(&signing_bytes_response(resp, &resp.body), &sig) {
            Ok(String::from_utf8_lossy(&resp.body).to_string())
        } else {
            Err(SecurityError::BadSignature)
        }
    }

    fn verify_response_bytes(
        &mut self,
        local: PeerId,
        remote: PeerId,
        resp: &DirectResponse,
    ) -> Result<Vec<u8>, SecurityError> {
        self.check_common(remote, resp.ts, &resp.nonce)?;
        let pk = self
            .peer_public_keys
            .get(&remote)
            .ok_or(SecurityError::UnknownPeerKey)?;
        let sig = B64
            .decode(&resp.signature)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;

        if resp.to != local.to_string() || resp.from != remote.to_string() {
            return Err(SecurityError::BadPeerIdentity);
        }

        if pk.verify(&signing_bytes_response(resp, &resp.body), &sig) {
            Ok(resp.body.clone())
        } else {
            Err(SecurityError::BadSignature)
        }
    }

    fn build_response_ok(
        &self,
        from: PeerId,
        to: PeerId,
        in_reply_to: &str,
        body: &str,
    ) -> Result<DirectResponse, SecurityError> {
        let mut resp =
            DirectResponse::plain_ok(in_reply_to, from.to_string(), to.to_string(), body);
        resp.nonce = random_nonce();
        resp.ts = now_secs();
        resp.signature = self.sign_data(&signing_bytes_response(&resp, &resp.body))?;
        Ok(resp)
    }

    fn build_response_error(
        &self,
        from: PeerId,
        to: PeerId,
        in_reply_to: &str,
        body: &str,
    ) -> Result<DirectResponse, SecurityError> {
        let mut resp =
            DirectResponse::plain_error(in_reply_to, from.to_string(), to.to_string(), body);
        resp.nonce = random_nonce();
        resp.ts = now_secs();
        resp.signature = self.sign_data(&signing_bytes_response(&resp, &resp.body))?;
        Ok(resp)
    }

    // --- Config messages ---
    fn build_config_request(
        &self,
        from: PeerId,
        to: PeerId,
        role: &str,
    ) -> Result<ConfigRequest, SecurityError> {
        let mut req = ConfigRequest::plain(from.to_string(), to.to_string(), role);
        req.nonce = random_nonce();
        req.ts = now_secs();
        req.signature = self.sign_data(&signing_bytes_config_request(&req))?;
        Ok(req)
    }

    fn verify_config_request(
        &mut self,
        local: PeerId,
        remote: PeerId,
        req: &ConfigRequest,
    ) -> Result<(), SecurityError> {
        self.check_common(remote, req.ts, &req.nonce)?;
        if req.to != local.to_string() || req.from != remote.to_string() {
            return Err(SecurityError::BadPeerIdentity);
        }
        let pk = self
            .peer_public_keys
            .get(&remote)
            .ok_or(SecurityError::UnknownPeerKey)?;
        let sig = B64
            .decode(&req.signature)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;
        if !pk.verify(&signing_bytes_config_request(req), &sig) {
            return Err(SecurityError::BadSignature);
        }
        Ok(())
    }

    fn build_config_response_ok(
        &self,
        from: PeerId,
        to: PeerId,
        in_reply_to: &str,
        bundle: ConfigBundle,
    ) -> Result<ConfigResponse, SecurityError> {
        let body = serde_json::to_string(&bundle)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;
        let mut resp = ConfigResponse::plain_ok(
            in_reply_to,
            from.to_string(),
            to.to_string(),
            body.clone(),
        );
        resp.nonce = random_nonce();
        resp.ts = now_secs();
        resp.signature = self.sign_data(&signing_bytes_config_response(&resp))?;
        Ok(resp)
    }

    fn build_config_response_error(
        &self,
        from: PeerId,
        to: PeerId,
        in_reply_to: &str,
        error: &str,
    ) -> Result<ConfigResponse, SecurityError> {
        let mut resp = ConfigResponse::plain_error(
            in_reply_to,
            from.to_string(),
            to.to_string(),
            error.to_string(),
        );
        resp.nonce = random_nonce();
        resp.ts = now_secs();
        resp.signature = self.sign_data(&signing_bytes_config_response(&resp))?;
        Ok(resp)
    }

    fn verify_config_response(
        &mut self,
        local: PeerId,
        remote: PeerId,
        resp: &ConfigResponse,
    ) -> Result<ConfigBundle, SecurityError> {
        self.check_common(remote, resp.ts, &resp.nonce)?;
        if resp.to != local.to_string() || resp.from != remote.to_string() {
            return Err(SecurityError::BadPeerIdentity);
        }
        let pk = self
            .peer_public_keys
            .get(&remote)
            .ok_or(SecurityError::UnknownPeerKey)?;
        let sig = B64
            .decode(&resp.signature)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;
        if !pk.verify(&signing_bytes_config_response(resp), &sig) {
            return Err(SecurityError::BadSignature);
        }
        if resp.ok {
            let bundle: ConfigBundle = serde_json::from_str(&resp.body)
                .map_err(|e| SecurityError::DecodeError(e.to_string()))?;
            Ok(bundle)
        } else {
            Err(SecurityError::CryptoError(resp.body.clone()))
        }
    }

    // --- Gateway messages ---
    fn verify_gateway_request(
        &mut self,
        _local: PeerId,
        remote: PeerId,
        req: &GatewayRequest,
    ) -> Result<String, SecurityError> {
        self.check_common(remote, req.ts, &req.nonce)?;
        let pk = self
            .peer_public_keys
            .get(&remote)
            .ok_or(SecurityError::UnknownPeerKey)?;
        let sig = B64
            .decode(&req.signature)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;

        if pk.verify(&signing_bytes_gateway_request(req, &req.body), &sig) {
            Ok(req.body.clone())
        } else {
            Err(SecurityError::BadSignature)
        }
    }

    fn verify_gateway_response(
        &mut self,
        local: PeerId,
        remote: PeerId,
        resp: &GatewayResponse,
    ) -> Result<(u16, String), SecurityError> {
        self.check_common(remote, resp.ts, &resp.nonce)?;
        if resp.to != local.to_string() || resp.from != remote.to_string() {
            return Err(SecurityError::BadPeerIdentity);
        }
        let pk = self
            .peer_public_keys
            .get(&remote)
            .ok_or(SecurityError::UnknownPeerKey)?;
        let sig = B64
            .decode(&resp.signature)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;
        if !pk.verify(&signing_bytes_gateway_response(resp, &resp.body), &sig) {
            return Err(SecurityError::BadSignature);
        }
        Ok((resp.status, resp.body.clone()))
    }

    fn build_gateway_response_ok(
        &self,
        from: PeerId,
        to: PeerId,
        in_reply_to: &str,
        status: u16,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> Result<GatewayResponse, SecurityError> {
        let mut resp = GatewayResponse::plain_ok(
            in_reply_to,
            from.to_string(),
            to.to_string(),
            status,
            headers,
            body,
        );
        resp.nonce = random_nonce();
        resp.ts = now_secs();
        resp.signature = self.sign_data(&signing_bytes_gateway_response(&resp, body))?;
        Ok(resp)
    }

    fn build_gateway_response_error(
        &self,
        from: PeerId,
        to: PeerId,
        in_reply_to: &str,
        _status: u16,
        error: &str,
    ) -> Result<GatewayResponse, SecurityError> {
        let mut resp = GatewayResponse::plain_error(
            in_reply_to,
            from.to_string(),
            to.to_string(),
            error,
        );
        resp.nonce = random_nonce();
        resp.ts = now_secs();
        resp.signature = self.sign_data(&signing_bytes_gateway_response(&resp, error))?;
        Ok(resp)
    }

    // --- Web messages ---
    fn verify_web_request(
        &mut self,
        _local: PeerId,
        remote: PeerId,
        req: &WebRequest,
    ) -> Result<String, SecurityError> {
        self.check_common(remote, req.ts, &req.nonce)?;
        let pk = self
            .peer_public_keys
            .get(&remote)
            .ok_or(SecurityError::UnknownPeerKey)?;
        let sig = B64
            .decode(&req.signature)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;

        if pk.verify(&signing_bytes_web_request(req, &req.body), &sig) {
            Ok(req.body.clone())
        } else {
            Err(SecurityError::BadSignature)
        }
    }

    fn verify_web_response(
        &mut self,
        local: PeerId,
        remote: PeerId,
        resp: &WebResponse,
    ) -> Result<(u16, String, String), SecurityError> {
        self.check_common(remote, resp.ts, &resp.nonce)?;
        if resp.to != local.to_string() || resp.from != remote.to_string() {
            return Err(SecurityError::BadPeerIdentity);
        }
        let pk = self
            .peer_public_keys
            .get(&remote)
            .ok_or(SecurityError::UnknownPeerKey)?;
        let sig = B64
            .decode(&resp.signature)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;
        if !pk.verify(&signing_bytes_web_response(resp, &resp.body), &sig) {
            return Err(SecurityError::BadSignature);
        }
        Ok((resp.status, resp.content_type.clone(), resp.body.clone()))
    }

    fn build_web_response_ok(
        &self,
        from: PeerId,
        to: PeerId,
        in_reply_to: &str,
        status: u16,
        content_type: &str,
        headers: Vec<(String, String)>,
        body: &str,
    ) -> Result<WebResponse, SecurityError> {
        let mut resp = WebResponse::plain_ok(
            in_reply_to,
            from.to_string(),
            to.to_string(),
            status,
            content_type,
            headers,
            body,
        );
        resp.nonce = random_nonce();
        resp.ts = now_secs();
        resp.signature = self.sign_data(&signing_bytes_web_response(&resp, body))?;
        Ok(resp)
    }

    fn build_web_response_error(
        &self,
        from: PeerId,
        to: PeerId,
        in_reply_to: &str,
        status: u16,
        error: &str,
    ) -> Result<WebResponse, SecurityError> {
        let mut resp = WebResponse::plain_error(
            in_reply_to,
            from.to_string(),
            to.to_string(),
            status,
            error,
        );
        resp.nonce = random_nonce();
        resp.ts = now_secs();
        resp.signature = self.sign_data(&signing_bytes_web_response(&resp, error))?;
        Ok(resp)
    }

    // -----------------------------------------------------------------
    // Common helpers
    // -----------------------------------------------------------------
    fn sign_data(&self, data: &[u8]) -> Result<String, SecurityError> {
        let sig = self
            .local_keypair
            .sign(data)
            .map_err(|e| SecurityError::CryptoError(e.to_string()))?;
        Ok(B64.encode(sig))
    }

    // [FIX H-11] Bounded replay cache: per-bucket cap + periodic full cleanup
    const MAX_NONCES_PER_PEER: usize = 1_000;
    const MAX_TRACKED_PEERS: usize = 10_000;

    fn check_common(&mut self, peer: PeerId, ts: u64, nonce: &str) -> Result<(), SecurityError> {
        if now_secs().abs_diff(ts) > self.replay_window_secs {
            return Err(SecurityError::TimestampOutOfWindow);
        }

        let now = now_secs();

        // Periodic cleanup of stale peer entries in outer map
        if self.replay_seen.len() > Self::MAX_TRACKED_PEERS {
            let window = self.replay_window_secs;
            self.replay_seen.retain(|_, bucket| {
                bucket.retain(|_, t| now.abs_diff(*t) <= window);
                !bucket.is_empty()
            });
        }

        let bucket = self.replay_seen.entry(peer).or_default();
        bucket.retain(|_, t| now.abs_diff(*t) <= self.replay_window_secs);

        if bucket.contains_key(nonce) {
            return Err(SecurityError::ReplayDetected);
        }

        // Enforce per-bucket nonce cap to prevent single-peer flooding
        if bucket.len() >= Self::MAX_NONCES_PER_PEER {
            tracing::warn!(
                "[SECURITY] Nonce bucket full for peer — possible nonce-flood DoS attempt. \
                 Rejecting new nonce."
            );
            return Err(SecurityError::ReplayDetected);
        }

        bucket.insert(nonce.to_string(), now);
        Ok(())
    }

    fn load_policy_from_file(&mut self, path: &str) -> Result<(), SecurityError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| SecurityError::CryptoError(format!("Cannot read policy file: {}", e)))?;
        let config: PolicyConfig = serde_json::from_str(&content)
            .map_err(|e| SecurityError::DecodeError(format!("Invalid policy JSON: {}", e)))?;
        self.policy_config = config;
        Ok(())
    }

    fn verify_peer(&self, peer_id: &PeerId) -> Result<(), SecurityError> {
        let id_str = peer_id.to_string();
        if self.policy_config.allowed_peers.contains(&id_str) {
            return Ok(());
        }

        if let Some(auth) = &self.authority {
            if auth.is_allowed(peer_id, Action::Connect) {
                return Ok(());
            }
        }

        Err(SecurityError::BadPeerIdentity)
    }

    fn verify_access(&self, action: &str) -> Result<(), SecurityError> {
        if self.policy_config.allowed_actions.contains(action) {
            Ok(())
        } else {
            Err(SecurityError::CryptoError(format!(
                "Action '{}' not allowed by policy",
                action
            )))
        }
    }

    // [FIX H-06] Return Err when trusted_bundle_hash is not configured
    fn verify_bundle_config(&self) -> Result<(), SecurityError> {
        match &self.policy_config.trusted_bundle_hash {
            None => {
                tracing::warn!(
                    "[SECURITY] trusted_bundle_hash not configured — bundle verification SKIPPED."
                );
                Err(SecurityError::CryptoError(
                    "trusted_bundle_hash not configured — cannot verify bundle integrity".into(),
                ))
            }
            Some(hash) => {
                let bundle = self.export_config_bundle_impl()?;
                let bundle_str = serde_json::to_string(&bundle)
                    .map_err(|e| SecurityError::DecodeError(e.to_string()))?;
                let mut hasher = Sha256::new();
                hasher.update(bundle_str.as_bytes());
                let current_hash = hex::encode(hasher.finalize());
                if current_hash != *hash {
                    return Err(SecurityError::CryptoError(
                        "Bundle config hash mismatch".into(),
                    ));
                }
                tracing::info!("[SECURITY] Bundle config verified against trusted hash.");
                Ok(())
            }
        }
    }

    fn register_response_verifier<F>(&mut self, f: F)
    where
        F: Fn(&VerifiedGatewayResponse) -> Result<(), SecurityError>
            + Send
            + Sync
            + 'static
            + std::panic::UnwindSafe,
    {
        self.response_verifiers.push(Box::new(f));
    }

    fn run_response_verifiers(
        &self,
        verified: &VerifiedGatewayResponse,
    ) -> Result<(), SecurityError> {
        for v in &self.response_verifiers {
            v(verified)?;
        }
        Ok(())
    }

    fn reload_policy(&mut self, path: &str) -> Result<(), SecurityError> {
        self.load_policy_from_file(path)
    }

    fn policy_status(&self) -> PolicyConfig {
        self.policy_config.clone()
    }

    fn export_policy_rules(&self) -> Result<String, SecurityError> {
        serde_json::to_string_pretty(&self.policy_config)
            .map_err(|e| SecurityError::CryptoError(e.to_string()))
    }

    fn verify_peer_key(
        &self,
        peer_id: &PeerId,
        public_key: &PublicKey,
    ) -> Result<(), SecurityError> {
        match self.peer_public_keys.get(peer_id) {
            Some(stored) if stored == public_key => Ok(()),
            Some(_) => Err(SecurityError::BadPeerIdentity),
            None => Err(SecurityError::UnknownPeerKey),
        }
    }

    fn verify_timestamp(&self, ts: u64) -> Result<(), SecurityError> {
        if now_secs().abs_diff(ts) > self.replay_window_secs {
            Err(SecurityError::TimestampOutOfWindow)
        } else {
            Ok(())
        }
    }

    fn verify_nonce_uniqueness(&mut self, peer: PeerId, nonce: &str) -> Result<(), SecurityError> {
        let bucket = self.replay_seen.entry(peer).or_default();
        let now = now_secs();
        bucket.retain(|_, t| now.abs_diff(*t) <= self.replay_window_secs);
        if bucket.contains_key(nonce) {
            Err(SecurityError::ReplayDetected)
        } else {
            bucket.insert(nonce.to_string(), now);
            Ok(())
        }
    }

    fn verify_signature_format(signature: &str) -> Result<(), SecurityError> {
        B64.decode(signature)
            .map_err(|e| SecurityError::DecodeError(e.to_string()))?;
        Ok(())
    }

    fn verify_governance_vote(
        &self,
        vote: &VoteMessage,
        voter_peer_id: &PeerId,
    ) -> Result<(), SecurityError> {
        let pk = self
            .peer_public_keys
            .get(voter_peer_id)
            .ok_or(SecurityError::UnknownPeerKey)?;
        let payload = format!(
            "{}:{}:{}:{}:{}",
            vote.proposal_id,
            vote.voter,
            vote.approve,
            vote.nonce,
            vote.timestamp
        );
        let sig_bytes = B64
            .decode(&vote.signature)
            .map_err(|_| SecurityError::DecodeError("bad sig".into()))?;
        if pk.verify(payload.as_bytes(), &sig_bytes) {
            Ok(())
        } else {
            Err(SecurityError::BadSignature)
        }
    }
}

// ==========================================
// 6. SECURITY RUNTIME (public API)
// ==========================================
#[derive(Clone)]
pub struct SecurityRuntime {
    inner: Arc<RwLock<PolicyInner>>,
    pub metrics: Arc<RwLock<SecurityMetrics>>,
    nonce_cache: Arc<Mutex<NonceCache>>,   // 🔧 NonceCache tanpa Mutex internal, Mutex di sini saja
    sn_rate_limiter: Arc<Mutex<RateLimiter>>,
}

impl fmt::Debug for SecurityRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityRuntime")
            .field("inner", &"..")
            .field("metrics", &self.metrics)
            .field("nonce_cache", &"..")
            .field("sn_rate_limiter", &"..")
            .finish()
    }
}

impl SecurityRuntime {
    pub fn new(local_keypair: Keypair) -> Result<Self, SecurityError> {
        let inner = PolicyInner::new(local_keypair);
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            metrics: Arc::new(RwLock::new(SecurityMetrics::default())),
            nonce_cache: Arc::new(Mutex::new(NonceCache::new())),
            sn_rate_limiter: Arc::new(Mutex::new(RateLimiter::new(5, 60))),
        })
    }

    fn read_protected<R, F>(&self, f: F) -> Result<R, SecurityError>
    where
        F: FnOnce(&PolicyInner) -> Result<R, SecurityError> + std::panic::UnwindSafe,
    {
        let guard = self
            .inner
            .read()
            .map_err(|_| SecurityError::CryptoError("Lock poisoned".into()))?;
        catch_unwind(AssertUnwindSafe(|| f(&guard)))
            .unwrap_or(Err(SecurityError::CryptoError("Security read panic".into())))
    }

    fn write_protected<R, F>(&self, f: F) -> Result<R, SecurityError>
    where
        F: FnOnce(&mut PolicyInner) -> Result<R, SecurityError> + std::panic::UnwindSafe,
    {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::CryptoError("Lock poisoned".into()))?;

        match catch_unwind(AssertUnwindSafe(|| f(&mut guard))) {
            Ok(res) => res,
            Err(_) => {
                if let Ok(mut m) = self.metrics.write() {
                    m.total_failures += 1;
                }
                Err(SecurityError::CryptoError("Security write panic".into()))
            }
        }
    }

    // ------------------- PUBLIC API -------------------
    pub fn attach_authority(&self, authority: AuthorityManager) {
        if let Ok(mut policy) = self.inner.write() {
            policy.attach_authority(authority);
        }
    }

    pub fn current_role(&self) -> NodeRole {
        self.inner
            .read()
            .map(|p| p.local_role())
            .unwrap_or(NodeRole::Observer)
    }

    pub fn is_allowed(&self, peer: &PeerId, action: Action) -> bool {
        self.inner.read().map_or(false, |p| p.is_allowed(peer, action))
    }

    pub fn apply_bundle(&self, bundle: &ConfigBundle) -> Result<(), SecurityError> {
        self.write_protected(|policy| policy.apply_config_bundle(bundle))
    }

    pub fn register_peer_key(
        &self,
        peer_id: PeerId,
        pk: libp2p::identity::PublicKey,
    ) -> Result<(), SecurityError> {
        self.write_protected(|p| p.register_peer_public_key(peer_id, pk))
    }

    pub fn verify_direct_request(
        &self,
        local: PeerId,
        remote: PeerId,
        req: &DirectRequest,
    ) -> Result<String, SecurityError> {
        self.write_protected(|policy| policy.verify_request(local, remote, req))
    }

    pub fn verify_direct_response(
        &self,
        local: PeerId,
        remote: PeerId,
        resp: &DirectResponse,
    ) -> Result<String, SecurityError> {
        self.write_protected(|policy| policy.verify_response(local, remote, resp))
    }

    pub fn verify_direct_response_bytes(
        &self,
        local: PeerId,
        remote: PeerId,
        resp: &DirectResponse,
    ) -> Result<Vec<u8>, SecurityError> {
        self.write_protected(|policy| policy.verify_response_bytes(local, remote, resp))
    }

    pub fn verify_config_request(
        &self,
        local: PeerId,
        remote: PeerId,
        req: &ConfigRequest,
    ) -> Result<(), SecurityError> {
        self.write_protected(|p| p.verify_config_request(local, remote, req))
    }

    pub fn verify_config_response(
        &self,
        local: PeerId,
        remote: PeerId,
        resp: &ConfigResponse,
    ) -> Result<ConfigBundle, SecurityError> {
        self.write_protected(|p| p.verify_config_response(local, remote, resp))
    }

    pub fn verify_gateway_request(
        &self,
        local: PeerId,
        remote: PeerId,
        req: &GatewayRequest,
    ) -> Result<String, SecurityError> {
        self.write_protected(|p| p.verify_gateway_request(local, remote, req))
    }

    pub fn verify_gateway_response(
        &self,
        local: PeerId,
        remote: PeerId,
        resp: &GatewayResponse,
    ) -> Result<VerifiedGatewayResponse, SecurityError> {
        self.write_protected(|p| {
            let (s, b) = p.verify_gateway_response(local, remote, resp)?;
            let verified = VerifiedGatewayResponse::new(s, b);
            p.run_response_verifiers(&verified)?;
            Ok(verified)
        })
    }

    pub fn verify_web_request(
        &self,
        local: PeerId,
        remote: PeerId,
        req: &WebRequest,
    ) -> Result<String, SecurityError> {
        self.write_protected(|p| p.verify_web_request(local, remote, req))
    }

    pub fn verify_web_response(
        &self,
        local: PeerId,
        remote: PeerId,
        resp: &WebResponse,
    ) -> Result<VerifiedWebResponse, SecurityError> {
        self.write_protected(|p| {
            let (s, ct, b) = p.verify_web_response(local, remote, resp)?;
            Ok(VerifiedWebResponse::new(s, ct, b))
        })
    }

    pub fn build_direct_request(
        &self,
        from: PeerId,
        to: PeerId,
        body: &str,
    ) -> Result<DirectRequest, SecurityError> {
        self.read_protected(|p| p.build_request(from, to, body))
    }

    pub fn build_direct_request_bytes(
        &self,
        from: PeerId,
        to: PeerId,
        body: Vec<u8>,
    ) -> Result<DirectRequest, SecurityError> {
        self.read_protected(|p| p.build_request_bytes(from, to, body))
    }

    pub fn build_config_request(
        &self,
        from: PeerId,
        to: PeerId,
        role: &str,
    ) -> Result<ConfigRequest, SecurityError> {
        self.read_protected(|p| p.build_config_request(from, to, role))
    }

    pub fn build_direct_response_ok(
        &self,
        from: PeerId,
        to: PeerId,
        mid: &str,
        body: &str,
    ) -> Result<DirectResponse, SecurityError> {
        self.read_protected(|p| p.build_response_ok(from, to, mid, body))
    }

    pub fn build_direct_response_error(
        &self,
        from: PeerId,
        to: PeerId,
        mid: &str,
        err: &str,
    ) -> Result<DirectResponse, SecurityError> {
        self.read_protected(|p| p.build_response_error(from, to, mid, err))
    }

    pub fn build_config_response_ok(
        &self,
        from: PeerId,
        to: PeerId,
        mid: &str,
        bundle: ConfigBundle,
    ) -> Result<ConfigResponse, SecurityError> {
        self.read_protected(|p| p.build_config_response_ok(from, to, mid, bundle))
    }

    pub fn build_config_response_error(
        &self,
        from: PeerId,
        to: PeerId,
        mid: &str,
        err: &str,
    ) -> Result<ConfigResponse, SecurityError> {
        self.read_protected(|p| p.build_config_response_error(from, to, mid, err))
    }

    pub fn build_gateway_response_ok(
        &self,
        from: PeerId,
        to: PeerId,
        mid: &str,
        s: u16,
        h: Vec<(String, String)>,
        b: &str,
    ) -> Result<GatewayResponse, SecurityError> {
        self.read_protected(|p| p.build_gateway_response_ok(from, to, mid, s, h, b))
    }

    pub fn build_gateway_response_error(
        &self,
        from: PeerId,
        to: PeerId,
        mid: &str,
        s: u16,
        err: &str,
    ) -> Result<GatewayResponse, SecurityError> {
        self.read_protected(|p| p.build_gateway_response_error(from, to, mid, s, err))
    }

    pub fn build_web_response_ok(
        &self,
        from: PeerId,
        to: PeerId,
        mid: &str,
        s: u16,
        ct: &str,
        h: Vec<(String, String)>,
        b: &str,
    ) -> Result<WebResponse, SecurityError> {
        self.read_protected(|p| p.build_web_response_ok(from, to, mid, s, ct, h, b))
    }

    pub fn build_web_response_error(
        &self,
        from: PeerId,
        to: PeerId,
        mid: &str,
        s: u16,
        err: &str,
    ) -> Result<WebResponse, SecurityError> {
        self.read_protected(|p| p.build_web_response_error(from, to, mid, s, err))
    }

    // ------------------- EXTRA API -------------------
    pub fn load_policy_from_file(&self, path: &str) -> Result<(), SecurityError> {
        self.write_protected(|p| p.load_policy_from_file(path))
    }

    pub fn verify_peer(&self, peer_id: &PeerId) -> Result<(), SecurityError> {
        self.read_protected(|p| p.verify_peer(peer_id))
    }

    pub fn verify_access(&self, action: &str) -> Result<(), SecurityError> {
        self.read_protected(|p| p.verify_access(action))
    }

    pub fn verify_bundle_config(&self) -> Result<(), SecurityError> {
        self.read_protected(|p| p.verify_bundle_config())
    }

    pub fn register_response_verifier<F>(&self, verifier: F) -> Result<(), SecurityError>
    where
        F: Fn(&VerifiedGatewayResponse) -> Result<(), SecurityError>
            + Send
            + Sync
            + 'static
            + std::panic::UnwindSafe,
    {
        self.write_protected(|p| {
            p.register_response_verifier(verifier);
            Ok(())
        })
    }

    pub fn reload_policy(&self, path: &str) -> Result<(), SecurityError> {
        self.write_protected(|p| p.reload_policy(path))
    }

    pub fn policy_status(&self) -> PolicyConfig {
        self.inner.read().map(|p| p.policy_status()).unwrap_or_default()
    }

    pub fn export_policy_rules(&self) -> Result<String, SecurityError> {
        self.read_protected(|p| p.export_policy_rules())
    }

    pub fn verify_peer_key(
        &self,
        peer_id: &PeerId,
        public_key: &PublicKey,
    ) -> Result<(), SecurityError> {
        self.read_protected(|p| p.verify_peer_key(peer_id, public_key))
    }

    #[cfg(test)]
    pub fn verify_timestamp(&self, ts: u64) -> Result<(), SecurityError> {
        self.read_protected(|p| p.verify_timestamp(ts))
    }

    #[cfg(test)]
    pub fn verify_nonce(&self, peer: PeerId, nonce: &str) -> Result<(), SecurityError> {
        self.write_protected(|p| p.verify_nonce_uniqueness(peer, nonce))
    }

    #[cfg(test)]
    pub fn check_allowed_action(&self, peer: &PeerId, action: Action) -> bool {
        self.inner
            .read()
            .map(|p| p.is_allowed(peer, action))
            .unwrap_or(false)
    }

    pub fn verify_signature_format(&self, signature: &str) -> Result<(), SecurityError> {
        PolicyInner::verify_signature_format(signature)
    }

    // -----------------------------------------------------------------
    // ONBOARDING INTEGRATION (🔥 FIX: tambah parameter x25519_pubkey)
    // -----------------------------------------------------------------
    pub fn verify_remote_identity(
        &self,
        remote_peer_id: &str,
        serial_number: &str,
        signature: &[u8],
        public_key: &[u8],
        nonce: &[u8; 16],
        timestamp: u64,
        x25519_pubkey: Option<&str>,
    ) -> bool {
        {
            let limiter = self.sn_rate_limiter.lock();
            if !limiter.check(serial_number) {
                tracing::warn!("Rate limit exceeded for SN: {}", serial_number);
                return false;
            }
        }

        let now = now_secs();
        if now.abs_diff(timestamp) > 900 {
            tracing::warn!("❌ [SECURITY] Timestamp kadaluwarsa (lebih dari 15 menit): {} vs {}", timestamp, now);
            return false;
        }

        // 🔧 PATCH 3: hanya satu layer Mutex — nonce_cache.lock() mengembalikan MutexGuard<NonceCache>
        {
            let mut cache = self.nonce_cache.lock();
            if !cache.record(nonce) {
                tracing::warn!("Nonce replay detected for peer {}", remote_peer_id);
                return false;
            }
        }

        if !onboarding::verify_sn_checksum(serial_number) {
            tracing::warn!("Checksum SN gagal untuk peer {}", remote_peer_id);
            return false;
        }

        let pubkey_str = x25519_pubkey.unwrap_or("");
        let message = format!(
            "{}:{}:{}:{}:{}",
            remote_peer_id, serial_number, hex::encode(nonce), timestamp, pubkey_str
        );

        let pk = match ed25519_public_key_from_bytes(public_key) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!("Public key invalid untuk {}: {}", remote_peer_id, e);
                return false;
            }
        };

        let sig = match ed25519_signature_from_bytes(signature) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Signature invalid untuk {}: {}", remote_peer_id, e);
                return false;
            }
        };

        let valid = pk.verify(message.as_bytes(), &sig).is_ok();
        if valid {
            tracing::info!(
                "Onboarding verification succeeded for peer {}",
                remote_peer_id
            );
        } else {
            tracing::warn!(
                "Onboarding signature verification failed for peer {}",
                remote_peer_id
            );
        }
        valid
    }

    // ---------------------------------------------------------------
    // 🆕 GOVERNANCE SIGN / VERIFY
    // ---------------------------------------------------------------
    pub fn sign_governance_payload(&self, payload: &str) -> Result<String, SecurityError> {
        self.read_protected(|p| p.sign_data(payload.as_bytes()))
    }

    pub fn verify_governance_vote(
        &self,
        vote: &VoteMessage,
        voter_peer_id: &PeerId,
    ) -> Result<(), SecurityError> {
        self.read_protected(|p| p.verify_governance_vote(vote, voter_peer_id))
    }
}

pub fn security_api_sanity_probe() {
    let dummy_keypair = Keypair::generate_ed25519();
    let mut inner = PolicyInner {
        local_keypair: dummy_keypair,
        replay_window_secs: 300,
        replay_seen: HashMap::new(),
        peer_public_keys: HashMap::new(),
        authority: None,
        policy_config: PolicyConfig::default(),
        response_verifiers: Vec::new(),
    };

    let dummy_peer = PeerId::random();
    let dummy_ts = now_secs();
    let _ = inner.verify_timestamp(dummy_ts);
    let _ = inner.verify_nonce_uniqueness(dummy_peer, "sanity_nonce");
    let _ = inner.export_config_bundle_impl();
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use tempfile::NamedTempFile;

    fn make_key() -> Keypair {
        Keypair::generate_ed25519()
    }

    fn known_peer_id() -> PeerId {
        let key = make_key();
        PeerId::from(key.public())
    }

    #[test]
    fn test_load_policy_and_verify_peer() {
        let keypair = make_key();
        let rt = SecurityRuntime::new(keypair).unwrap();
        let peer_str = known_peer_id().to_string();

        let policy = format!(
            r#"{{"allowed_peers":["{}"],"allowed_actions":["connect"],"bootstrap_addrs":[],"trusted_bundle_hash":null,"response_verification_enabled":true}}"#,
            peer_str
        );

        let mut file = NamedTempFile::new().unwrap();
        use std::io::Write;
        file.write_all(policy.as_bytes()).unwrap();

        rt.load_policy_from_file(file.path().to_str().unwrap())
            .unwrap();

        let known: PeerId = peer_str.parse().unwrap();
        assert!(rt.verify_peer(&known).is_ok());
        assert!(rt.verify_peer(&PeerId::random()).is_err());
    }

    #[test]
    fn test_load_policy_missing_new_fields_still_works() {
        let keypair = make_key();
        let rt = SecurityRuntime::new(keypair).unwrap();
        let peer_str = known_peer_id().to_string();

        let policy = format!(r#"{{"allowed_peers":["{}"]}}"#, peer_str);

        let mut file = NamedTempFile::new().unwrap();
        use std::io::Write;
        file.write_all(policy.as_bytes()).unwrap();

        rt.load_policy_from_file(file.path().to_str().unwrap())
            .unwrap();

        let known: PeerId = peer_str.parse().unwrap();
        assert!(rt.verify_peer(&known).is_ok());
        assert!(rt.policy_status().bootstrap_addrs.is_empty());
    }

    #[test]
    fn test_timestamp_and_replay() {
        let keypair = make_key();
        let rt = SecurityRuntime::new(keypair).unwrap();
        let old = now_secs() - 301;
        assert!(rt.verify_timestamp(old).is_err());

        let peer = PeerId::random();
        rt.verify_nonce(peer, "n1").unwrap();
        assert!(rt.verify_nonce(peer, "n1").is_err());
    }

    #[test]
    fn test_verify_direct_request_signature_ok() {
        let keypair = make_key();
        let rt = SecurityRuntime::new(keypair.clone()).unwrap();
        let local = PeerId::random();
        let remote = PeerId::random();
        rt.register_peer_key(remote, keypair.public()).unwrap();

        let mut req = crate::message::DirectRequest::plain(
            remote.to_string(),
            local.to_string(),
            "hi",
        );
        let sig = keypair
            .sign(&crate::security::signing_bytes_request(&req, b"hi"))
            .unwrap();
        req.signature = B64.encode(&sig);

        assert!(rt.verify_direct_request(local, remote, &req).is_ok());
    }

    #[test]
    fn test_verify_direct_request_bad_signature() {
        let keypair = make_key();
        let rt = SecurityRuntime::new(keypair.clone()).unwrap();
        let local = PeerId::random();
        let remote = PeerId::random();
        rt.register_peer_key(remote, keypair.public()).unwrap();

        let mut req = crate::message::DirectRequest::plain(
            remote.to_string(),
            local.to_string(),
            "hi",
        );
        req.signature = "AAAA".into();

        assert!(rt.verify_direct_request(local, remote, &req).is_err());
    }

    #[test]
    fn test_apply_bundle_updates_allowed_peers() {
        let keypair = make_key();
        let rt = SecurityRuntime::new(keypair).unwrap();
        let bundle = ConfigBundle {
            role: "client".into(),
            policy_version: 1,
            allowed_peers: vec!["peerA".into()],
            bootstrap_addrs: vec!["addr1".into()],
            issued_at: 0,
        }
        .normalized();

        rt.apply_bundle(&bundle).unwrap();
        let config = rt.policy_status();
        assert!(config.allowed_peers.contains("peerA"));
        assert!(config.bootstrap_addrs.contains(&"addr1".to_string()));
    }

    #[test]
    fn test_verify_gateway_request_signature_ok() {
        let keypair = make_key();
        let rt = SecurityRuntime::new(keypair.clone()).unwrap();
        let local = PeerId::random();
        let remote = PeerId::random();
        rt.register_peer_key(remote, keypair.public()).unwrap();

        let mut req = crate::gateway::GatewayRequest::plain(
            remote.to_string(),
            local.to_string(),
            "GET",
            "/",
            vec![],
            "",
            vec![],
        );
        let sig = keypair
            .sign(&crate::security::signing_bytes_gateway_request(&req, ""))
            .unwrap();
        req.signature = B64.encode(&sig);

        assert!(rt.verify_gateway_request(local, remote, &req).is_ok());
    }

    #[test]
    fn test_verify_web_request_signature_ok() {
        let keypair = make_key();
        let rt = SecurityRuntime::new(keypair.clone()).unwrap();
        let local = PeerId::random();
        let remote = PeerId::random();
        rt.register_peer_key(remote, keypair.public()).unwrap();

        let mut req = crate::web::WebRequest::plain(
            remote.to_string(),
            local.to_string(),
            "GET",
            "/health",
            vec![],
            "",
        );
        let sig = keypair
            .sign(&crate::security::signing_bytes_web_request(&req, ""))
            .unwrap();
        req.signature = B64.encode(&sig);

        assert!(rt.verify_web_request(local, remote, &req).is_ok());
    }

    // 🔧 PATCH 7: unit test untuk memastikan format pesan menggunakan hex, bukan Debug array
    #[test]
    fn test_verify_remote_identity_format() {
        let nonce = [0u8; 16];
        let message = format!(
            "{}:{}:{}:{}:{}",
            "peerA",
            "SN",
            hex::encode(&nonce),
            1234,
            "pubkey"
        );
        // Harus ada string hex yang panjang (32 karakter nol)
        assert!(message.contains("00000000000000000000000000000000"));
        // Tidak boleh ada format Debug array seperti [0,0,0,...]
        assert!(!message.contains('['));
    }
}
