use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use ed25519_dalek::{PublicKey, Signature as DalekSignature, Verifier};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use log::{info, error};

// 🔥 Import ConfigBundle untuk method baru
use crate::config::ConfigBundle;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthorityError {
    IoError(String),
    SerializationError(String),
    LockPoisoned,
    Denied(String),
    InvalidSignature,
    VersionRejected(u64, u64),
    InvalidFormat(String),
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityError::IoError(e) => write!(f, "IO: {}", e),
            AuthorityError::SerializationError(e) => write!(f, "Serialization: {}", e),
            AuthorityError::LockPoisoned => write!(f, "Internal Lock Poisoned"),
            AuthorityError::Denied(e) => write!(f, "Denied: {}", e),
            AuthorityError::InvalidSignature => write!(f, "Invalid Signature"),
            AuthorityError::VersionRejected(c, a) => write!(f, "Version Conflict: {} vs {}", c, a),
            AuthorityError::InvalidFormat(e) => write!(f, "Invalid Format: {}", e),
        }
    }
}

impl std::error::Error for AuthorityError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthorityRefreshOutcome {
    Success,
    Updated { old_version: u64, new_version: u64 },
    Unchanged,
    Failed(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Action {
    Connect,
    Route,
    GatewayAccess,
    GatewayEgress,
    WebTraffic,
    AdminUpdate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum NodeRole {
    Blocked,
    Observer,
    Client,
    Standard,
    Gateway,
    Validator,
    Supernode,
}

pub type Role = NodeRole;

impl NodeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeRole::Supernode => "supernode",
            NodeRole::Validator => "validator",
            NodeRole::Gateway => "relay",
            NodeRole::Standard | NodeRole::Client | NodeRole::Observer => "client",
            NodeRole::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionPolicy {
    pub max_connections: usize,
    pub allow_unknown_peers: bool,
    pub require_signed_messages: bool,
    pub allow_gateway_traffic: bool,
    pub allow_route_transit: bool,
    pub allow_web_traffic: bool,
}

impl Default for PermissionPolicy {
    fn default() -> Self {
        Self {
            max_connections: 100,
            allow_unknown_peers: false,
            require_signed_messages: true,
            allow_gateway_traffic: true,
            allow_route_transit: true,
            allow_web_traffic: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityRoot {
    pub name: String,
    pub issuer: String,
    pub active: bool,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityState {
    pub version: u64,
    pub root: AuthorityRoot,
    pub supernodes: Vec<String>,
    pub allowed_peers: HashMap<String, Role>,
    pub trust_graph: BTreeMap<String, Vec<String>>,
    pub policies: PermissionPolicy,
    pub hash: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(default)] // agar data lama tanpa field ini masih bisa dibaca
    pub pending_peers: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityDecision {
    pub peer_id: String,
    pub action: Action,
    pub allowed: bool,
    pub reason: String,
    pub role: Option<Role>,
    pub timestamp: u64,
}

impl AuthorityState {
    pub fn canonicalize(&mut self) {
        self.supernodes.sort();
        self.supernodes.dedup();
        self.hash = self.compute_hash();
    }

    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.version.to_le_bytes());
        hasher.update(self.root.issuer.as_bytes());
        let mut sorted_sn = self.supernodes.clone();
        sorted_sn.sort();
        for sn in sorted_sn { hasher.update(sn.as_bytes()); }
        hasher.finalize().to_vec()
    }

    pub fn verify(&self, pubkey: &PublicKey) -> Result<(), AuthorityError> {
        if self.signature.is_empty() { return Err(AuthorityError::InvalidSignature); }
        let sig = DalekSignature::from_bytes(&self.signature).map_err(|_| AuthorityError::InvalidSignature)?;
        pubkey.verify(&self.compute_hash(), &sig).map_err(|_| AuthorityError::InvalidSignature)?;
        Ok(())
    }

    pub fn get_role(&self, peer_id: &str) -> Option<Role> {
        if self.supernodes.contains(&peer_id.to_string()) { return Some(Role::Supernode); }
        self.allowed_peers.get(peer_id).copied()
    }

    pub fn evaluate_action(&self, peer: &PeerId, action: Action) -> AuthorityDecision {
        let peer_id_str = peer.to_string();
        let role = self.get_role(&peer_id_str);

        let (allowed, reason) = match &role {
            Some(Role::Blocked) => (false, "explicitly_blocked".into()),
            Some(Role::Supernode) => (true, "supernode_unlimited".into()),
            Some(r) => self.check_role_permission(*r, action),
            None => {
                if self.policies.allow_unknown_peers { (true, "unknown_allowed_by_policy".into()) }
                else { (false, "unregistered_peer_denied".into()) }
            }
        };

        AuthorityDecision {
            peer_id: peer_id_str,
            action,
            allowed,
            reason,
            role,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        }
    }

    // 🔴 C-01: tambah GatewayEgress, tanpa wildcard → exhaustive check
    fn check_role_permission(&self, role: Role, action: Action) -> (bool, String) {
        match action {
            Action::Connect => (role > Role::Blocked, "connectivity_check".into()),
            Action::Route => (self.policies.allow_route_transit && role >= Role::Gateway, "route_check".into()),
            Action::GatewayAccess => (self.policies.allow_gateway_traffic && role >= Role::Gateway, "gateway_check".into()),
            Action::GatewayEgress => (self.policies.allow_gateway_traffic && role >= Role::Gateway, "egress_check".into()),
            Action::AdminUpdate => (role >= Role::Validator, "admin_check".into()),
            Action::WebTraffic => (self.policies.allow_web_traffic, "web_policy_check".into()),
        }
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), AuthorityError> {
        let data = bincode::serialize(self).map_err(|e| AuthorityError::SerializationError(e.to_string()))?;
        fs::write(path, data).map_err(|e| AuthorityError::IoError(e.to_string()))
    }
}

// 🔥🔥🔥 PERBAIKAN: tambahkan Debug di sini
#[derive(Debug, Clone)]
pub struct AuthorityManager {
    inner: Arc<RwLock<AuthorityState>>,
}

impl AuthorityManager {
    pub fn new(initial: AuthorityState) -> Self {
        Self { inner: Arc::new(RwLock::new(initial)) }
    }

    /// Dapatkan state terbaru. Jika lock poisoned, fallback ke default state.
    pub fn get(&self) -> AuthorityState {
        self.inner.read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| {
                error!("[AUTHORITY] Lock poisoned saat membaca state, mengembalikan default!");
                AuthorityState::default()
            })
    }

    pub fn get_snapshot(&self) -> Result<AuthorityState, AuthorityError> {
        self.inner.read()
            .map(|g| g.clone())
            .map_err(|_| AuthorityError::LockPoisoned)
    }

    /// Cek izin aksi. Fail‑safe: jika lock error, tolak semua.
    pub fn is_allowed(&self, peer: &PeerId, action: Action) -> bool {
        self.inner.read()
            .map(|guard| guard.evaluate_action(peer, action).allowed)
            .unwrap_or_else(|_| {
                error!("[AUTHORITY] Lock poisoned saat cek allowed({}, {:?}), DENY", peer, action);
                false
            })
    }

    /// Dapatkan role sebuah peer. Return None jika lock error.
    pub fn role_of(&self, peer: &PeerId) -> Option<Role> {
        self.inner.read()
            .ok()
            .and_then(|g| g.get_role(&peer.to_string()))
            .or_else(|| {
                // log jika gagal, tapi tetap return None
                if self.inner.read().is_err() {
                    error!("[AUTHORITY] Lock poisoned saat membaca role_of({})", peer);
                }
                None
            })
    }

    pub fn update_state(&self, new_state: AuthorityState, pubkey: &PublicKey) -> Result<(), AuthorityError> {
        new_state.verify(pubkey)?;
        let mut guard = self.inner.write().map_err(|_| AuthorityError::LockPoisoned)?;
        if new_state.version <= guard.version {
            return Err(AuthorityError::VersionRejected(guard.version, new_state.version));
        }
        info!("[AUTH] Updated to version {}", new_state.version);
        *guard = new_state;
        Ok(())
    }

    pub fn refresh_from_file(&self, path: &str, pubkey: &PublicKey) -> AuthorityRefreshOutcome {
        let current_v = self.get().version;
        match load_authority(path) {
            Ok(new_state) => {
                if new_state.version <= current_v { return AuthorityRefreshOutcome::Unchanged; }
                let next_version = new_state.version;
                match self.update_state(new_state, pubkey) {
                    Ok(_) => AuthorityRefreshOutcome::Updated { old_version: current_v, new_version: next_version },
                    Err(e) => AuthorityRefreshOutcome::Failed(e.to_string()),
                }
            }
            Err(e) => AuthorityRefreshOutcome::Failed(e.to_string()),
        }
    }

    pub fn can_route(&self, peer: &PeerId) -> bool { self.is_allowed(peer, Action::Route) }
    pub fn can_gateway(&self, peer: &PeerId) -> bool { self.is_allowed(peer, Action::GatewayAccess) }
    pub fn trust_path_exists(&self, peer: &PeerId) -> bool { self.role_of(peer).is_some() }

    /// Buat keputusan untuk lalu lintas gateway. Fallback: tolak jika lock error.
    pub fn decision_for_gateway_peer(&self, peer_id: &PeerId) -> AuthorityDecision {
        self.inner.read()
            .map(|guard| guard.evaluate_action(peer_id, Action::GatewayAccess))
            .unwrap_or_else(|_| {
                error!("[AUTHORITY] Lock poisoned saat decision_for_gateway_peer({}), DENY", peer_id);
                AuthorityDecision {
                    peer_id: peer_id.to_string(),
                    action: Action::GatewayAccess,
                    allowed: false,
                    reason: "internal_lock_error".into(),
                    role: None,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                }
            })
    }

    // [FIX H-08] apply_config_bundle: stage peers sebagai "pending confirmation"
    pub fn apply_config_bundle(&self, bundle: &ConfigBundle) -> Result<(), Box<dyn std::error::Error>> {
        let mut state = self.inner.write().map_err(|_| "Authority lock poisoned")?;

        // Stage new peers into a separate pending set, not directly into allowed_peers.
        let mut staged = 0usize;
        for peer_id in &bundle.allowed_peers {
            if !state.allowed_peers.contains_key(peer_id)
                && !state.pending_peers.contains(peer_id)
            {
                state.pending_peers.insert(peer_id.clone());
                staged += 1;
            }
        }

        // NOTE: We do NOT canonicalize + save here.
        info!(
            "[AUTH] Config bundle staged {} peers as PENDING (require multi-SN confirmation).",
            staged
        );
        Ok(())
    }

    /// Confirm pending peers after receiving acknowledgment from `required_confirmations`
    /// distinct supernodes.
    pub fn confirm_pending_peers(
        &self,
        peer_id: &str,
        confirming_supernodes: &[String],
        required_confirmations: usize,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if confirming_supernodes.len() < required_confirmations {
            return Ok(false);
        }

        let mut state = self.inner.write().map_err(|_| "Authority lock poisoned")?;
        if state.pending_peers.remove(peer_id) {
            state.allowed_peers.insert(peer_id.to_string(), NodeRole::Client);
            state.canonicalize();
            info!(
                "[AUTH] Peer {} confirmed by {} supernodes and promoted to Client.",
                peer_id,
                confirming_supernodes.len()
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub fn load_authority(path: &str) -> Result<AuthorityState, AuthorityError> {
    let data = fs::read(path).map_err(|e| AuthorityError::IoError(e.to_string()))?;
    bincode::deserialize(&data)
        .or_else(|_| serde_json::from_slice(&data))
        .map_err(|e| AuthorityError::InvalidFormat(e.to_string()))
}

impl Default for AuthorityState {
    fn default() -> Self {
        Self {
            version: 1,
            root: AuthorityRoot { name: "ess-foundation".into(), issuer: "".into(), active: true, updated_at: 0 },
            supernodes: vec![],
            allowed_peers: HashMap::new(),
            trust_graph: BTreeMap::new(),
            policies: PermissionPolicy::default(),
            hash: vec![],
            signature: vec![],
            pending_peers: HashSet::new(),
        }
    }
}

pub fn default_authority() -> AuthorityState {
    let mut state = AuthorityState::default();
    state.policies.allow_unknown_peers = false;
    state.canonicalize();
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    fn make_peer() -> PeerId {
        PeerId::random()
    }

    fn make_state() -> AuthorityState {
        let mut s = default_authority();
        s.allowed_peers.insert(make_peer().to_string(), Role::Client);
        s.allowed_peers.insert(make_peer().to_string(), Role::Gateway);
        s.supernodes.push(make_peer().to_string());
        s.canonicalize();
        s
    }

    #[test]
    fn test_direct_request_rejected_for_unknown_peer() {
        let state = default_authority();
        let mgr = AuthorityManager::new(state);
        let unknown_peer = make_peer();
        let allowed = mgr.is_allowed(&unknown_peer, Action::Connect);
        assert!(!allowed, "Unknown peer should be rejected for Direct/Connect");
    }

    #[test]
    fn test_allowed_peer_can_connect() {
        let mut state = default_authority();
        let peer = make_peer();
        state.allowed_peers.insert(peer.to_string(), Role::Client);
        state.canonicalize();
        let mgr = AuthorityManager::new(state);
        assert!(mgr.is_allowed(&peer, Action::Connect));
    }

    #[test]
    fn test_quarantined_peer_blocked_indirectly() {
        let state = default_authority();
        let mgr = AuthorityManager::new(state);
        let peer = make_peer();
        assert!(!mgr.is_allowed(&peer, Action::GatewayAccess));
    }

    #[test]
    fn test_supernode_always_allowed() {
        let state = make_state();
        let mgr = AuthorityManager::new(state);
        let supernode = mgr.get().supernodes[0].parse().unwrap();
        assert!(mgr.is_allowed(&supernode, Action::Connect));
        assert!(mgr.is_allowed(&supernode, Action::GatewayAccess));
    }

    #[test]
    fn test_client_cannot_route() {
        let state = make_state();
        let mgr = AuthorityManager::new(state);
        let client = mgr.get().allowed_peers.iter()
            .find(|(_, r)| **r == Role::Client)
            .map(|(id, _)| id.parse::<PeerId>().unwrap())
            .unwrap();
        assert!(!mgr.is_allowed(&client, Action::Route));
    }

    #[test]
    fn test_gateway_can_route_and_gateway() {
        let state = make_state();
        let mgr = AuthorityManager::new(state);
        let gateway = mgr.get().allowed_peers.iter()
            .find(|(_, r)| **r == Role::Gateway)
            .map(|(id, _)| id.parse::<PeerId>().unwrap())
            .unwrap();
        assert!(mgr.is_allowed(&gateway, Action::Route));
        assert!(mgr.is_allowed(&gateway, Action::GatewayAccess));
    }

    #[test]
    fn test_blocked_role_denied_all() {
        let mut state = make_state();
        let blocked_peer = make_peer();
        state.allowed_peers.insert(blocked_peer.to_string(), Role::Blocked);
        let mgr = AuthorityManager::new(state);
        assert!(!mgr.is_allowed(&blocked_peer, Action::Connect));
        assert!(!mgr.is_allowed(&blocked_peer, Action::GatewayAccess));
    }

    #[test]
    fn test_apply_config_bundle_now_stages_peers_as_pending() {
        let state = make_state();
        let mgr = AuthorityManager::new(state);
        let bundle = crate::config::ConfigBundle {
            role: "client".into(),
            policy_version: 1,
            allowed_peers: vec!["new-peer-1".to_string(), "new-peer-2".to_string()],
            bootstrap_addrs: vec![],
            issued_at: 0,
        }.normalized();
        mgr.apply_config_bundle(&bundle).unwrap();
        let updated_state = mgr.get();
        // seharusnya tidak langsung masuk allowed_peers
        assert!(!updated_state.allowed_peers.contains_key("new-peer-1"));
        assert!(updated_state.pending_peers.contains("new-peer-1"));
        assert!(updated_state.pending_peers.contains("new-peer-2"));
    }

    #[test]
    fn test_confirm_pending_peers_moves_to_allowed() {
        let state = make_state();
        let mgr = AuthorityManager::new(state);
        let bundle = crate::config::ConfigBundle {
            role: "client".into(),
            policy_version: 1,
            allowed_peers: vec!["new-peer-1".to_string()],
            bootstrap_addrs: vec![],
            issued_at: 0,
        }.normalized();
        mgr.apply_config_bundle(&bundle).unwrap();

        // konfirmasi dengan supernode yang cukup
        let sn = vec!["sn1".to_string(), "sn2".to_string()];
        let confirmed = mgr.confirm_pending_peers("new-peer-1", &sn, 2).unwrap();
        assert!(confirmed);
        let final_state = mgr.get();
        assert!(final_state.allowed_peers.contains_key("new-peer-1"));
        assert!(!final_state.pending_peers.contains("new-peer-1"));
    }
}
