//! CRDT Distributed State — Whitepaper §7
//!
//! Implementasi empat primitive CRDT:
//! 1. LWW-Register (Last-Write-Wins)
//! 2. G-Set (Grow-Only Set)
//! 3. G-Counter (Grow-Only Counter)
//! 4. LWW-Map — untuk peer_registry
//! 5. OR-Set (Observed-Remove Set)
//!
//! Strong Eventual Consistency: semua node yang menerima set update yang sama
//! akan converge ke state yang sama, tanpa koordinasi central.
//!
//! MERGE RULE: merge(A, B) = state dengan timestamp terbaru menang (LWW)

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ==========================================
// 1. LWW-REGISTER (Last-Write-Wins)
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LwwRegister<T: Clone + PartialEq> {
    pub value: T,
    pub ts: u64,
    pub node_id: String,
}

impl<T: Clone + PartialEq + Default> LwwRegister<T> {
    pub fn new(value: T, node_id: impl Into<String>) -> Self {
        Self {
            value,
            ts: now_ms(),
            node_id: node_id.into(),
        }
    }

    pub fn set(&mut self, value: T, node_id: impl Into<String>) {
        self.value = value;
        self.ts = now_ms();
        self.node_id = node_id.into();
    }

    pub fn merge(&mut self, other: &Self) {
        if other.ts > self.ts
            || (other.ts == self.ts && other.node_id > self.node_id)
        {
            self.value = other.value.clone();
            self.ts = other.ts;
            self.node_id = other.node_id.clone();
        }
    }
}

// ==========================================
// 2. G-SET (Grow-Only Set)
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GSet<T: Ord + Clone> {
    pub items: BTreeMap<T, u64>,
}

impl<T: Ord + Clone> GSet<T> {
    pub fn insert(&mut self, item: T) {
        self.items.entry(item).or_insert_with(now_ms);
    }

    pub fn contains(&self, item: &T) -> bool {
        self.items.contains_key(item)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn merge(&mut self, other: &Self) {
        for (item, ts) in &other.items {
            self.items.entry(item.clone()).or_insert(*ts);
        }
    }
}

// ==========================================
// 3. G-COUNTER (Grow-Only Counter)
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GCounter {
    counters: BTreeMap<String, u64>,
}

impl GCounter {
    pub fn increment(&mut self, replica: &str, delta: u64) {
        let entry = self.counters.entry(replica.to_string()).or_insert(0);
        *entry += delta;
    }

    pub fn total(&self) -> u64 {
        self.counters.values().sum()
    }

    pub fn merge(&mut self, other: &Self) {
        for (replica, &value) in &other.counters {
            let own = self.counters.entry(replica.clone()).or_insert(0);
            *own = (*own).max(value);
        }
    }
}

// ==========================================
// 5. OR-SET (Observed-Remove Set)
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ORSet<T: Ord + Clone + Hash> {
    entries: BTreeMap<T, HashSet<u64>>,
    removed: HashSet<u64>,
}

impl<T: Ord + Clone + Hash> ORSet<T> {
    /// Penambahan elemen dengan tag unik UUID v4 untuk menghindari collision
    pub fn add(&mut self, item: T) {
        let tag = Uuid::new_v4().as_u64_pair().0 ^ Uuid::new_v4().as_u64_pair().1;
        self.entries
            .entry(item)
            .or_insert_with(HashSet::new)
            .insert(tag);
    }

    pub fn remove(&mut self, item: &T) {
        if let Some(tags) = self.entries.get(item) {
            for &tag in tags.iter() {
                self.removed.insert(tag);
            }
            self.entries.remove(item);
        }
    }

    pub fn contains(&self, item: &T) -> bool {
        self.entries.get(item).map_or(false, |tags| {
            tags.iter().any(|tag| !self.removed.contains(tag))
        })
    }

    pub fn elements(&self) -> impl Iterator<Item = &T> {
        self.entries.keys()
    }

    pub fn merge(&mut self, other: &Self) {
        for (item, other_tags) in &other.entries {
            let entry = self.entries
                .entry(item.clone())
                .or_insert_with(HashSet::new);
            for tag in other_tags {
                entry.insert(*tag);
            }
        }
        for tag in &other.removed {
            self.removed.insert(*tag);
        }
        self.entries.retain(|_, tags| {
            tags.iter().any(|tag| !self.removed.contains(tag))
        });
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl<T: Ord + Clone + Hash> Hash for ORSet<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for item in self.entries.keys() {
            item.hash(state);
        }
        for tag in &self.removed {
            tag.hash(state);
        }
    }
}

// ==========================================
// 4. LWW-MAP (untuk peer registry)
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerEntry {
    pub peer_id: String,
    pub role: String,
    pub connected: bool,
    pub trusted: bool,
    pub reputation_score: f32,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerRegistry {
    pub entries: BTreeMap<String, (PeerEntry, u64)>,
}

impl PeerRegistry {
    pub fn upsert(&mut self, entry: PeerEntry, ts: u64) {
        let peer_id = entry.peer_id.clone();
        match self.entries.get(&peer_id) {
            Some((_, existing_ts)) if *existing_ts >= ts => {}
            _ => {
                self.entries.insert(peer_id, (entry, ts));
            }
        }
    }

    pub fn upsert_now(&mut self, entry: PeerEntry) {
        let ts = now_ms();
        self.upsert(entry, ts);
    }

    pub fn merge(&mut self, other: &Self) {
        for (peer_id, (entry, ts)) in &other.entries {
            match self.entries.get(peer_id) {
                Some((_, existing_ts)) if *existing_ts >= *ts => {}
                _ => {
                    self.entries.insert(peer_id.clone(), (entry.clone(), *ts));
                }
            }
        }
    }

    pub fn get(&self, peer_id: &str) -> Option<&PeerEntry> {
        self.entries.get(peer_id).map(|(e, _)| e)
    }

    pub fn all_peers(&self) -> Vec<&PeerEntry> {
        self.entries.values().map(|(e, _)| e).collect()
    }

    pub fn connected_peers(&self) -> Vec<&PeerEntry> {
        self.entries
            .values()
            .filter(|(e, _)| e.connected)
            .map(|(e, _)| e)
            .collect()
    }
}

// ==========================================
// 5. CRDT WORLD STATE — Top-Level Container
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrdtWorldState {
    pub node_id: String,
    pub vector_clock: BTreeMap<String, u64>,
    pub peers: PeerRegistry,
    pub known_peer_ids: GSet<String>,
    pub network_status: LwwRegister<String>,
    pub ghost_state: LwwRegister<String>,
    #[serde(default)]
    pub finance_counter: GCounter,
    #[serde(default)]
    pub asset_ownership: ORSet<String>,
    #[serde(skip)]
    pub dag: crate::merkle_dag::MerkleDag,
}

impl CrdtWorldState {
    pub fn new(node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        Self {
            vector_clock: BTreeMap::from([(node_id.clone(), 0)]),
            peers: PeerRegistry::default(),
            known_peer_ids: GSet::default(),
            network_status: LwwRegister::new("initializing".to_string(), node_id.clone()),
            ghost_state: LwwRegister::new("init".to_string(), node_id.clone()),
            finance_counter: GCounter::default(),
            node_id,
            asset_ownership: ORSet::default(),
            dag: crate::merkle_dag::MerkleDag::new(),
        }
    }

    pub fn tick(&mut self) {
        let counter = self.vector_clock.entry(self.node_id.clone()).or_insert(0);
        *counter += 1;
    }

    pub fn merge(&mut self, other: &Self) {
        for (node, count) in &other.vector_clock {
            let entry = self.vector_clock.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(*count);
        }
        self.peers.merge(&other.peers);
        self.known_peer_ids.merge(&other.known_peer_ids);
        self.network_status.merge(&other.network_status);
        self.ghost_state.merge(&other.ghost_state);
        self.finance_counter.merge(&other.finance_counter);
        self.asset_ownership.merge(&other.asset_ownership);

        let json = serde_json::to_string(self).unwrap_or_default();
        self.dag.add_state_json(&json);
    }

    pub fn dominates(&self, other: &Self) -> bool {
        let mut at_least_one_greater = false;
        for (node, &our_count) in &self.vector_clock {
            let their_count = other.vector_clock.get(node).copied().unwrap_or(0);
            if our_count < their_count {
                return false;
            }
            if our_count > their_count {
                at_least_one_greater = true;
            }
        }
        at_least_one_greater
    }

    pub fn update_peer(&mut self, peer_id: String, role: String, connected: bool, trusted: bool) {
        self.tick();
        let ts = now_ms();
        self.known_peer_ids.insert(peer_id.clone());
        self.peers.upsert(
            PeerEntry {
                peer_id,
                role,
                connected,
                trusted,
                reputation_score: 1.0,
                last_seen: ts,
            },
            ts,
        );
        let json = serde_json::to_string(self).unwrap_or_default();
        self.dag.add_state_json(&json);
    }

    pub fn to_sync_payload(&self) -> Vec<u8> {
        bincode::serialize(self).expect("CRDT state serialization failed")
    }

    pub fn from_sync_payload(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("CRDT deserialization error: {}", e))
    }
}

// ==========================================
// 6. SYNC MESSAGE
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrdtSyncMessage {
    pub from_node: String,
    pub state: CrdtWorldState,
    pub ts: u64,
}

impl CrdtSyncMessage {
    pub fn new(node_id: String, state: CrdtWorldState) -> Self {
        Self {
            from_node: node_id,
            ts: now_ms(),
            state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lww_merge() {
        let mut a = LwwRegister::new("state_a".to_string(), "node-1");
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = LwwRegister::new("state_b".to_string(), "node-2");
        a.merge(&b);
        assert_eq!(a.value, "state_b");
    }

    #[test]
    fn test_gset_merge_commutative() {
        let mut s1 = GSet::<String>::default();
        let mut s2 = GSet::<String>::default();
        s1.insert("peer-a".into());
        s2.insert("peer-b".into());
        s1.merge(&s2);
        s2.merge(&s1);
        assert!(s1.contains(&"peer-a".to_string()));
        assert!(s1.contains(&"peer-b".to_string()));
        assert_eq!(s1.len(), s2.len());
    }

    #[test]
    fn test_crdt_world_state_merge() {
        let mut state_a = CrdtWorldState::new("node-a");
        let mut state_b = CrdtWorldState::new("node-b");
        state_a.update_peer("peer-1".into(), "supernode".into(), true, true);
        state_b.update_peer("peer-2".into(), "client".into(), true, false);
        state_a.merge(&state_b);
        assert!(state_a.peers.get("peer-1").is_some());
        assert!(state_a.peers.get("peer-2").is_some());
        assert_eq!(state_a.peers.all_peers().len(), 2);
        assert_eq!(state_a.finance_counter.total(), 0);
    }

    #[test]
    fn test_crdt_idempotent() {
        let mut state = CrdtWorldState::new("node-a");
        state.update_peer("peer-x".into(), "client".into(), true, true);
        let snapshot = state.clone();
        state.merge(&snapshot);
        assert_eq!(state.peers.all_peers().len(), 1);
    }

    #[test]
    fn test_gcounter_increment_and_merge() {
        let mut c1 = GCounter::default();
        let mut c2 = GCounter::default();
        c1.increment("node-1", 10);
        c1.increment("node-2", 5);
        c2.increment("node-2", 8);
        c2.increment("node-3", 2);
        c1.merge(&c2);
        assert_eq!(c1.total(), 10 + 8 + 2);
    }

    #[test]
    fn test_crdt_roundtrip_bincode() {
        let mut state = CrdtWorldState::new("node-test");
        state.update_peer("peer-1".into(), "supernode".into(), true, true);
        state.finance_counter.increment("node-test", 42);
        state.asset_ownership.add("asset-xyz".into());

        let payload = state.to_sync_payload();
        let restored = CrdtWorldState::from_sync_payload(&payload).expect("should deserialize");
        assert_eq!(restored.node_id, state.node_id);
        assert_eq!(restored.finance_counter.total(), state.finance_counter.total());
        assert!(restored.asset_ownership.contains(&"asset-xyz".to_string()));
    }
}
