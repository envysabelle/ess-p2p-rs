use crate::authority::{AuthorityState, Action};
use crate::network_controller::PeerReputation;
use crate::onboarding::LocalProfile;
use chrono::Utc;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::io;
use x25519_dalek::PublicKey as X25519PublicKey;

pub type SharedWorldState = Arc<RwLock<WorldState>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteScore {
    pub hop_count: u32,
    pub reliability: f64,
    pub last_used: u64,
    pub failure_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub timestamp: u64,
    pub action: Action,
    pub reason: String,
    pub severity: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityPolicySnapshot {
    pub version: u64,
    pub supernodes: Vec<String>,
    pub allowed_peer_count: usize,
    pub max_connections: usize,
    pub allow_unknown_peers: bool,
    pub require_signed_messages: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    pub peer_id: String,
    pub role: Option<String>,
    pub reputation: PeerReputation,
    pub routes: BTreeMap<String, RouteScore>,
    pub violations: Vec<PolicyViolation>,
    pub connected: bool,
    pub trusted: bool,
    pub last_seen: u64,
    /// Activation certificate (Patch 5) – disimpan setelah kuorum tercapai
    pub activation_cert: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceState {
    pub service_id: String,
    pub status: String,
    pub healthy: bool,
    pub last_signal: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GhostState {
    pub state: String,
    pub health_level: String,
    pub decision_count: u64,
    pub connected_count: usize,
    pub known_count: usize,
    pub route_count: usize,
    pub trusted_count: usize,
}

#[derive(Debug, Serialize)]
pub struct WorldState {
    pub revision: u64,
    pub last_updated: u64,
    pub authority: AuthorityPolicySnapshot,
    pub authority_hash: Option<String>,
    pub peer_registry: BTreeMap<String, PeerState>,
    pub service_registry: BTreeMap<String, ServiceState>,
    pub ghost: GhostState,
    pub event_log: VecDeque<WorldEvent>,
    pub network_status: String,

    pub local_profile: RwLock<Option<LocalProfile>>,
    // Patch 10a: no longer behind RwLock; protected by outer WorldState lock
    pub activated_peers: HashMap<String, bool>,

    /// Map PeerId → X25519 public key untuk onion routing (STEP 4)
    #[serde(skip)]
    pub peer_x25519_pubkeys: HashMap<PeerId, X25519PublicKey>,
}

impl Clone for WorldState {
    fn clone(&self) -> Self {
        Self {
            revision: self.revision,
            last_updated: self.last_updated,
            authority: self.authority.clone(),
            authority_hash: self.authority_hash.clone(),
            peer_registry: self.peer_registry.clone(),
            service_registry: self.service_registry.clone(),
            ghost: self.ghost.clone(),
            event_log: self.event_log.clone(),
            network_status: self.network_status.clone(),
            local_profile: RwLock::new(self.local_profile.read().unwrap().clone()),
            activated_peers: self.activated_peers.clone(),
            peer_x25519_pubkeys: self.peer_x25519_pubkeys.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldEvent {
    pub ts: String,
    pub source: String,
    pub signal: String,
    pub revision: u64,
}

impl WorldState {
    pub fn new(authority: AuthorityState) -> Self {
        let auth_hash = hex_string(&authority.compute_hash());
        let mut ws = Self {
            revision: 0,
            last_updated: Utc::now().timestamp() as u64,
            authority: authority_policy_snapshot(&authority),
            authority_hash: Some(auth_hash),
            peer_registry: BTreeMap::new(),
            service_registry: BTreeMap::new(),
            ghost: GhostState::default(),
            event_log: VecDeque::with_capacity(256),
            network_status: "booting".to_string(),
            local_profile: RwLock::new(None),
            activated_peers: HashMap::new(),
            peer_x25519_pubkeys: HashMap::new(),
        };
        if let Err(err) = ws.load_activated_peers() {
            eprintln!("WorldState::new: failed to load activated peers: {err}");
        }
        ws
    }

    pub fn register_peer_pubkey(&mut self, peer: PeerId, pk: X25519PublicKey) {
        self.peer_x25519_pubkeys.insert(peer, pk);
    }

    pub fn from_snapshot(snapshot: WorldStateSnapshot, authority: AuthorityState) -> Self {
        let mut state = Self::new(authority);
        state.apply_snapshot(snapshot);
        state
    }

    pub fn apply_snapshot(&mut self, snap: WorldStateSnapshot) {
        self.revision = snap.revision;
        self.ghost.state = snap.ghost_state;
        self.ghost.health_level = snap.health_level;
        self.network_status = snap.network_status;
        self.authority.version = snap.authority_version;
        self.bump();
    }

    pub fn snapshot(&self) -> WorldStateSnapshot {
        let (connected_peers, known_peers, route_peers, trusted_peers) =
            self.peer_counts_from_registry();

        WorldStateSnapshot {
            authority_version: self.authority.version,
            authority_hash: self.authority_hash.clone(),
            ghost_state: self.ghost.state.clone(),
            health_level: self.ghost.health_level.clone(),
            connected_peers,
            known_peers,
            route_peers,
            trusted_peers,
            peer_count: known_peers,
            service_count: self.service_registry.len(),
            network_status: self.network_status.clone(),
            last_signal: self.event_log.back().map(|e| e.signal.clone()),
            last_updated_at: Some(Utc::now().to_rfc3339()),
            revision: self.revision,
        }
    }

    pub fn observe_signal(&mut self, signal: impl Into<String>) {
        let event = WorldEvent {
            ts: Utc::now().to_rfc3339(),
            source: "system".into(),
            signal: signal.into(),
            revision: self.revision,
        };
        self.event_log.push_back(event);
        if self.event_log.len() > 256 {
            self.event_log.pop_front();
        }
        self.bump();
    }

    pub fn set_authority(&mut self, auth: AuthorityState) {
        self.authority = authority_policy_snapshot(&auth);
        self.authority_hash = Some(hex_string(&auth.compute_hash()));
        self.bump();
    }

    pub fn set_ghost_state(&mut self, state: &str) {
        self.ghost.state = state.to_string();
        self.bump();
    }

    pub fn set_health_level(&mut self, level: &str) {
        self.ghost.health_level = level.to_string();
        self.bump();
    }

    pub fn update_peers(&mut self, c: usize, k: usize, r: usize, t: usize) {
        self.ghost.connected_count = c;
        self.ghost.known_count = k;
        self.ghost.route_count = r;
        self.ghost.trusted_count = t;
        self.bump();
    }

    fn peer_counts_from_registry(&self) -> (usize, usize, usize, usize) {
        if self.peer_registry.is_empty() {
            return (
                self.ghost.connected_count,
                self.ghost.known_count,
                self.ghost.route_count,
                self.ghost.trusted_count,
            );
        }
        let connected = self.peer_registry.values().filter(|p| p.connected).count();
        let known = self.peer_registry.len();
        let route = self.peer_registry.values().filter(|p| !p.routes.is_empty()).count();
        let trusted = self.peer_registry.values().filter(|p| p.trusted).count();
        (connected, known, route, trusted)
    }

    pub fn sync_ghost_from_registry(&mut self) {
        let (c, k, r, t) = self.peer_counts_from_registry();
        self.ghost.connected_count = c;
        self.ghost.known_count = k;
        self.ghost.route_count = r;
        self.ghost.trusted_count = t;
    }

    pub fn active_supernode_count(&self) -> usize {
        self.peer_registry
            .values()
            .filter(|p| p.connected && p.role.as_deref().map(|r| r.trim().eq_ignore_ascii_case("supernode")).unwrap_or(false))
            .count()
    }

    pub fn upsert_peer_state(
        &mut self,
        peer_id: impl Into<String>,
        role: Option<String>,
        connected: bool,
        trusted: Option<bool>,
    ) {
        let peer_id = peer_id.into();
        let now = Utc::now().timestamp() as u64;
        let entry = self.peer_registry.entry(peer_id.clone()).or_insert_with(|| PeerState {
            peer_id: peer_id.clone(),
            role: None,
            reputation: PeerReputation::default(),
            routes: BTreeMap::new(),
            violations: Vec::new(),
            connected: false,
            trusted: false,
            last_seen: now,
            activation_cert: None,   // Patch 5: default None
        });
        if let Some(role) = role {
            entry.role = Some(role);
        }
        entry.connected = connected;
        if let Some(trusted) = trusted {
            entry.trusted = trusted;
        }
        entry.last_seen = now;
        self.sync_ghost_from_registry();
        self.bump();
    }

    pub fn set_peer_connected(&mut self, peer_id: &str, connected: bool) {
        let current_role = self.peer_registry.get(peer_id).and_then(|p| p.role.clone());
        let current_trusted = self.peer_registry.get(peer_id).map(|p| p.trusted);
        self.upsert_peer_state(peer_id.to_string(), current_role, connected, current_trusted);
    }

    pub fn set_peer_role(&mut self, peer_id: &str, role: impl Into<String>) {
        let role = role.into();
        let connected = self.peer_registry.get(peer_id).map(|p| p.connected).unwrap_or(false);
        let trusted = self.peer_registry.get(peer_id).map(|p| p.trusted);
        self.upsert_peer_state(peer_id.to_string(), Some(role), connected, trusted);
    }

    pub fn set_peer_trusted(&mut self, peer_id: &str, trusted: bool) {
        let current_role = self.peer_registry.get(peer_id).and_then(|p| p.role.clone());
        let connected = self.peer_registry.get(peer_id).map(|p| p.connected).unwrap_or(false);
        self.upsert_peer_state(peer_id.to_string(), current_role, connected, Some(trusted));
    }

    pub fn add_route(&mut self, peer_id: &str, via: &str) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(peer) = self.peer_registry.get_mut(peer_id) {
            peer.routes.insert(
                via.to_string(),
                RouteScore {
                    hop_count: 1,
                    reliability: 1.0,
                    last_used: now,
                    failure_count: 0,
                },
            );
        }
        self.sync_ghost_from_registry();
        self.bump();
    }

    pub fn remove_route(&mut self, peer_id: &str, via: &str) {
        if let Some(peer) = self.peer_registry.get_mut(peer_id) {
            peer.routes.remove(via);
        }
        self.sync_ghost_from_registry();
        self.bump();
    }

    // Patch 10a: set_local_profile now takes &mut self
    pub fn set_local_profile(&mut self, profile: LocalProfile) {
        self.local_profile = RwLock::new(Some(profile.clone()));
        self.activated_peers.insert(profile.peer_id.clone(), profile.is_activated);
        let _ = self.save_activated_peers();
    }

    /// Mengecek apakah peer sudah diaktivasi baik flag lokal maupun sertifikat aktivasi (Patch 5)
    pub fn is_peer_activated(&self, peer_id: &str) -> bool {
        let flag = self.activated_peers.get(peer_id).copied().unwrap_or(false);
        if !flag {
            return false;
        }
        self.peer_registry
            .get(peer_id)
            .map(|p| p.activation_cert.is_some())
            .unwrap_or(false)
    }

    // Patch 10a: mark_peer_activated now takes &mut self
    pub fn mark_peer_activated(&mut self, peer_id: &str) {
        self.activated_peers.insert(peer_id.to_string(), true);
        let _ = self.save_activated_peers();
    }

    pub fn save_activated_peers(&self) -> io::Result<()> {
        let path = "data/activated_peers.json";
        std::fs::create_dir_all("data").ok();
        let json = serde_json::to_string_pretty(&self.activated_peers)?;
        std::fs::write(path, json)
    }

    // Patch 10a: load_activated_peers now takes &mut self
    pub fn load_activated_peers(&mut self) -> io::Result<()> {
        let path = "data/activated_peers.json";
        if std::path::Path::new(path).exists() {
            let json = std::fs::read_to_string(path)?;
            let loaded: HashMap<String, bool> = serde_json::from_str(&json)?;
            self.activated_peers = loaded;
        }
        Ok(())
    }

    pub fn get_allowed_peers_list(&self) -> Vec<String> {
        self.peer_registry.keys().cloned().collect()
    }

    pub fn get_bootstrap_addrs(&self) -> Vec<String> {
        self.authority.supernodes.clone()
    }

    fn bump(&mut self) {
        self.revision += 1;
        self.last_updated = Utc::now().timestamp() as u64;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldStateSnapshot {
    pub authority_version: u64,
    pub authority_hash: Option<String>,
    pub ghost_state: String,
    pub health_level: String,
    pub connected_peers: usize,
    pub known_peers: usize,
    pub route_peers: usize,
    pub trusted_peers: usize,
    pub peer_count: usize,
    pub service_count: usize,
    pub network_status: String,
    pub last_signal: Option<String>,
    pub last_updated_at: Option<String>,
    pub revision: u64,
}

impl WorldStateSnapshot {
    pub fn authority_hash_short(&self) -> String {
        self.authority_hash.as_deref()
            .map(|h| h.chars().take(12).collect())
            .unwrap_or_else(|| "none".into())
    }
    pub fn last_updated_display(&self) -> String {
        self.last_updated_at.clone().unwrap_or_else(|| "unknown".into())
    }
    pub fn dashboard_summary(&self) -> String {
        format!("rev={} | ghost={} | net={}", self.revision, self.ghost_state, self.network_status)
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn authority_policy_snapshot(auth: &AuthorityState) -> AuthorityPolicySnapshot {
    AuthorityPolicySnapshot {
        version: auth.version,
        supernodes: auth.supernodes.clone(),
        allowed_peer_count: auth.allowed_peers.len(),
        max_connections: auth.policies.max_connections,
        allow_unknown_peers: auth.policies.allow_unknown_peers,
        require_signed_messages: auth.policies.require_signed_messages,
    }
}

pub fn prime_control_center(
    world_state: &SharedWorldState,
    authority: &AuthorityState,
    _node_id: &str,
    _role: &str,
    _gw: bool,
    _rt: bool,
) -> Option<WorldStateSnapshot> {
    if let Ok(mut guard) = world_state.write() {
        guard.set_authority(authority.clone());
        guard.observe_signal("control_center_primed");
        Some(guard.snapshot())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::default_authority;

    fn dummy_authority() -> AuthorityState {
        let mut a = default_authority();
        a.version = 1;
        a.canonicalize();
        a
    }

    #[test]
    fn test_new_world_state_initial_values() {
        let auth = dummy_authority();
        let ws = WorldState::new(auth);
        assert_eq!(ws.revision, 0);
        assert_eq!(ws.network_status, "booting");
        assert!(ws.ghost.state.is_empty());
    }

    #[test]
    fn test_update_peers_and_snapshot() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth);
        ws.update_peers(5, 10, 3, 2);
        let snap = ws.snapshot();
        assert_eq!(snap.connected_peers, 5);
        assert_eq!(snap.known_peers, 10);
        assert_eq!(snap.route_peers, 3);
        assert_eq!(snap.trusted_peers, 2);
    }

    #[test]
    fn test_upsert_and_snapshot_from_registry() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth);
        ws.upsert_peer_state("peer1", Some("supernode".into()), true, Some(true));
        ws.upsert_peer_state("peer2", Some("peer".into()), false, None);
        let snap = ws.snapshot();
        assert_eq!(snap.connected_peers, 1);
        assert_eq!(snap.known_peers, 2);
    }

    #[test]
    fn test_set_ghost_and_health() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth);
        ws.set_ghost_state("sleep");
        ws.set_health_level("degraded");
        let snap = ws.snapshot();
        assert_eq!(snap.ghost_state, "sleep");
        assert_eq!(snap.health_level, "degraded");
    }

    #[test]
    fn test_observe_signal_logged() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth);
        ws.observe_signal("test_event");
        let snap = ws.snapshot();
        assert_eq!(snap.last_signal, Some("test_event".into()));
    }

    #[test]
    fn test_apply_snapshot_consistency() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth.clone());
        ws.set_ghost_state("awake");
        ws.set_health_level("healthy");
        let snap = ws.snapshot();
        let ws2 = WorldState::from_snapshot(snap, auth);
        assert_eq!(ws2.ghost.state, "awake");
        assert_eq!(ws2.ghost.health_level, "healthy");
    }

    #[test]
    fn test_bump_increases_revision() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth);
        let rev_before = ws.revision;
        ws.update_peers(0, 0, 0, 0);
        assert!(ws.revision > rev_before);
    }

    #[test]
    fn test_clone_preserves_inner_state() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth);
        let profile = LocalProfile {
            name: "CloneTest".into(),
            email: "clone@syndicate.io".into(),
            peer_id: "clonePeer".into(),
            serial_number: "CLONE-0001".into(),
            is_activated: true,
            x25519_pubkey: "clone_x25519_key".into(),
        };
        ws.set_local_profile(profile);
        ws.mark_peer_activated("activatedClone");

        let cloned = ws.clone();
        let lp = cloned.local_profile.read().unwrap();
        assert_eq!(lp.as_ref().unwrap().peer_id, "clonePeer");
        // activated_peers sekarang langsung HashMap, tidak perlu lock
        assert!(cloned.activated_peers.get("activatedClone").copied().unwrap_or(false));
        // Untuk is_peer_activated perlu sertifikat, tapi di clone masih belum ada di registry, jadi false
        // Tetap test bahwa flag tersimpan
        assert!(cloned.activated_peers.contains_key("clonePeer"));
    }

    #[test]
    fn test_local_profile_and_activation() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth);
        let profile = LocalProfile {
            name: "Test".into(),
            email: "test@syndicate.io".into(),
            peer_id: "12D3KooWTest".into(),
            serial_number: "ESSBB-1234-ABCD".into(),
            is_activated: true,
            x25519_pubkey: "test_x25519_key".into(),
        };
        ws.set_local_profile(profile.clone());
        // Tambahkan sertifikat dummy di registry agar is_peer_activated true
        ws.upsert_peer_state("12D3KooWTest", None, true, Some(true));
        ws.peer_registry.get_mut("12D3KooWTest").unwrap().activation_cert = Some(vec![0u8; 32]);
        assert!(ws.is_peer_activated("12D3KooWTest"));
        assert!(!ws.is_peer_activated("unknown"));
    }

    #[test]
    fn test_save_and_load_activated_peers() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth);
        ws.mark_peer_activated("peer1");
        ws.mark_peer_activated("peer2");

        // Kosongkan manual untuk simulate
        ws.activated_peers.clear();
        assert!(!ws.is_peer_activated("peer1"));
        ws.load_activated_peers().unwrap();
        // Flag sudah kembali tapi sertifikat belum ada → tetap false
        assert!(!ws.is_peer_activated("peer1"));
        // Tambahkan sertifikat
        ws.upsert_peer_state("peer1", None, true, None);
        ws.peer_registry.get_mut("peer1").unwrap().activation_cert = Some(vec![1]);
        assert!(ws.is_peer_activated("peer1"));
        assert!(ws.is_peer_activated("peer2"));
    }

    #[test]
    fn test_add_and_remove_route() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth);
        ws.upsert_peer_state("peer1", Some("supernode".into()), true, Some(true));

        ws.add_route("peer1", "via-supernode");
        let snap = ws.snapshot();
        assert_eq!(snap.route_peers, 1);

        ws.remove_route("peer1", "via-supernode");
        let snap2 = ws.snapshot();
        assert_eq!(snap2.route_peers, 0);
    }

    #[test]
    fn test_register_peer_pubkey() {
        let auth = dummy_authority();
        let mut ws = WorldState::new(auth);
        let peer = PeerId::random();
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let pk = X25519PublicKey::from(&secret);
        ws.register_peer_pubkey(peer, pk);
        assert!(ws.peer_x25519_pubkeys.contains_key(&peer));
    }
}
