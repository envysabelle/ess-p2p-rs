use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, fs, io, path::Path, str::FromStr};

const BOOTSTRAP_CACHE_FILE: &str = "data/bootstrap/peers.json";
const MAX_BOOTSTRAP_PEERS: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BootstrapPeerRecord {
    peer_id: String,
    addr: String,
}

fn is_public_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => {
            !ip.is_loopback() && !ip.is_private() && !ip.is_link_local()
        }
        libp2p::multiaddr::Protocol::Ip6(ip) => !ip.is_loopback() && !ip.is_unique_local(),
        libp2p::multiaddr::Protocol::Dns4(_) | libp2p::multiaddr::Protocol::Dns6(_) => true,
        _ => false,
    })
}

fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn canonicalize_addr_for_peer(addr: &Multiaddr, peer_id: PeerId) -> String {
    let s = addr.to_string();
    let suffix = format!("/p2p/{peer_id}");

    if s.ends_with(&suffix) {
        return s;
    }

    if let Some((head, _)) = s.rsplit_once("/p2p/") {
        return format!("{head}{suffix}");
    }

    format!("{s}{suffix}")
}

fn record_from_addr(addr: &Multiaddr) -> Option<BootstrapPeerRecord> {
    if !is_public_addr(addr) {
        return None;
    }

    let peer_id = peer_id_from_multiaddr(addr)?;
    Some(BootstrapPeerRecord {
        peer_id: peer_id.to_string(),
        addr: canonicalize_addr_for_peer(addr, peer_id),
    })
}

fn normalize_records(records: Vec<BootstrapPeerRecord>) -> Vec<BootstrapPeerRecord> {
    let mut by_peer: BTreeMap<String, BootstrapPeerRecord> = BTreeMap::new();

    for record in records {
        let peer_id_raw = record.peer_id.trim();
        let addr_raw = record.addr.trim();

        if peer_id_raw.is_empty() || addr_raw.is_empty() {
            continue;
        }

        let peer_id = match PeerId::from_str(peer_id_raw) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let addr = match addr_raw.parse::<Multiaddr>() {
            Ok(v) => v,
            Err(_) => continue,
        };

        if !is_public_addr(&addr) {
            continue;
        }

        let canonical = canonicalize_addr_for_peer(&addr, peer_id);
        by_peer.insert(
            peer_id.to_string(),
            BootstrapPeerRecord {
                peer_id: peer_id.to_string(),
                addr: canonical,
            },
        );
    }

    by_peer.into_values().collect()
}

fn migrate_legacy_cache(items: Vec<String>) -> Vec<BootstrapPeerRecord> {
    let mut by_peer: BTreeMap<String, BootstrapPeerRecord> = BTreeMap::new();

    for raw in items {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }

        let addr = match raw.parse::<Multiaddr>() {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(record) = record_from_addr(&addr) {
            by_peer.insert(record.peer_id.clone(), record);
        }
    }

    by_peer.into_values().collect()
}

fn read_cache_records() -> io::Result<Vec<BootstrapPeerRecord>> {
    let path = Path::new(BOOTSTRAP_CACHE_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = fs::read_to_string(path)?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(records) = serde_json::from_str::<Vec<BootstrapPeerRecord>>(&raw) {
        let normalized = normalize_records(records.clone());
        if normalized != records {
            let _ = write_cache_records(&normalized);
        }
        return Ok(normalized);
    }

    if let Ok(legacy_strings) = serde_json::from_str::<Vec<String>>(&raw) {
        let normalized = migrate_legacy_cache(legacy_strings);
        let _ = write_cache_records(&normalized);
        return Ok(normalized);
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unsupported bootstrap cache format",
    ))
}

fn write_cache_records(items: &[BootstrapPeerRecord]) -> io::Result<()> {
    let path = Path::new(BOOTSTRAP_CACHE_FILE);
    ensure_parent_dir(path)?;

    let mut normalized = normalize_records(items.to_vec());
    if normalized.len() > MAX_BOOTSTRAP_PEERS {
        normalized.truncate(MAX_BOOTSTRAP_PEERS);
    }

    let raw = serde_json::to_vec_pretty(&normalized)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    fs::write(path, raw)
}

pub fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    let s = addr.to_string();
    let peer = s.rsplit_once("/p2p/")?.1;
    PeerId::from_str(peer).ok()
}

pub fn load_bootstrap_addrs() -> Vec<Multiaddr> {
    let mut by_peer: BTreeMap<String, Multiaddr> = BTreeMap::new();

    let mut push_addr = |addr: Multiaddr| {
        if !is_public_addr(&addr) {
            return;
        }

        if let Some(peer_id) = peer_id_from_multiaddr(&addr) {
            by_peer.entry(peer_id.to_string()).or_insert(addr);
        }
    };

    if let Ok(env_addrs) = env::var("BOOTSTRAP_P2P_MULTIADDRS") {
        for raw in env_addrs
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Ok(addr) = raw.parse::<Multiaddr>() {
                push_addr(addr);
            }
        }
    }

    if let Ok(records) = read_cache_records() {
        for record in records {
            if let Ok(addr) = record.addr.parse::<Multiaddr>() {
                push_addr(addr);
            }
        }
    }

    by_peer.into_values().collect()
}

pub fn save_bootstrap_peer_addr(addr: &Multiaddr, peer_id: PeerId) -> io::Result<()> {
    if !is_public_addr(addr) {
        return Ok(());
    }

    let canonical = canonicalize_addr_for_peer(addr, peer_id);
    let peer_key = peer_id.to_string();

    let mut records = read_cache_records().unwrap_or_default();
    records.retain(|r| r.peer_id != peer_key);
    records.push(BootstrapPeerRecord {
        peer_id: peer_key,
        addr: canonical,
    });

    let normalized = normalize_records(records);
    write_cache_records(&normalized)
}
