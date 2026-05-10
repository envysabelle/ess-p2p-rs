use crate::bootstrap_cache::save_bootstrap_peer_addr;
use crate::security::SecurityError;
use crate::network::runtime::types::Behaviour;
use libp2p::{Multiaddr, PeerId, Swarm};
use std::collections::{HashMap, HashSet};
use log;

// ==========================================
// FUNGSI JARINGAN P2P (YANG MASIH DIPAKAI)
// ==========================================

pub fn is_public(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => !ip.is_loopback() && !ip.is_private() && !ip.is_link_local(),
        libp2p::multiaddr::Protocol::Ip6(ip) => !ip.is_loopback() && !ip.is_unique_local(),
        libp2p::multiaddr::Protocol::Dns4(_) | libp2p::multiaddr::Protocol::Dns6(_) => true,
        _ => false,
    })
}

pub fn register_peer_addr(
    swarm: &mut Swarm<Behaviour>,
    seen_addrs: &mut HashMap<PeerId, HashSet<String>>,
    peer_id: PeerId,
    addr: &Multiaddr,
) {
    if peer_id == *swarm.local_peer_id() || !is_public(addr) {
        return;
    }
    let entry = seen_addrs.entry(peer_id).or_default();
    if entry.insert(addr.to_string()) {
        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
        swarm.add_peer_address(peer_id, addr.clone());
        let _ = save_bootstrap_peer_addr(addr, peer_id);
    }
}

#[allow(dead_code)]
pub fn log_security_reject(peer: PeerId, err: &SecurityError) {
    log::warn!("[SEC] reject from {}: {}", peer, err);
}

pub fn inc_connection_count(counts: &mut HashMap<PeerId, usize>, peer: PeerId) -> usize {
    let entry = counts.entry(peer).or_insert(0);
    *entry += 1;
    *entry
}

pub fn dec_connection_count(counts: &mut HashMap<PeerId, usize>, peer: PeerId) -> usize {
    match counts.get_mut(&peer) {
        Some(count) if *count > 1 => {
            *count -= 1;
            *count
        }
        _ => {
            counts.remove(&peer);
            0
        }
    }
}
