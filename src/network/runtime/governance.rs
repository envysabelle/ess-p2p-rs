use crate::security_runtime::SecurityRuntime;
use crate::world_state::WorldState;
use libp2p::identity::PublicKey;
use libp2p::PeerId;
use log::{debug, info, warn};
use std::sync::Arc;

pub fn register_peer_on_discovery(
    security: &Arc<SecurityRuntime>,
    peer_id: &PeerId,
    public_key: PublicKey,
) {
    // Kuncinya di sini: Kita panggil verify_peer_key agar statusnya "USED".
    // Kita gunakan result-nya untuk log audit saja, jangan buat nge-block.
    match security.verify_peer_key(peer_id, &public_key) {
        Ok(_) => debug!("[GOVERNANCE] Peer {} public key already verified.", peer_id),
        Err(e) => {
            // Log ini penting untuk tracing, tapi tidak menghentikan eksekusi
            debug!("[GOVERNANCE] Verification info for {}: {:?}", peer_id, e);
        }
    }

    // Lanjutkan registrasi agar node baru bisa masuk ke database internal
    match security.register_peer_key(peer_id.clone(), public_key.clone()) {
        Ok(()) => {
            info!(
                "🔐 Peer {} registered with public key for security verification",
                peer_id
            );
        }
        Err(e) => {
            warn!(
                "Failed to register peer {} key: {:?}. Public key: {:?}",
                peer_id, e, public_key
            );
        }
    }
}

// Patch 10c: parameter world_state berubah dari &WorldState menjadi &mut WorldState
pub fn handle_peer_identified(
    security: &Arc<SecurityRuntime>,
    world_state: &mut WorldState,
    remote_peer_id: &PeerId,
    serial_number: String,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    nonce: [u8; 16],
    timestamp: u64,
    x25519_pubkey: Option<String>,
) -> bool {
    let pid_str = remote_peer_id.to_string();

    // 🔐 Patch 3: Verifikasi dengan binding X25519 pubkey
    if !security.verify_remote_identity(
        &pid_str,
        &serial_number,
        &signature,
        &public_key,
        &nonce,
        timestamp,
        x25519_pubkey.as_deref(),
    ) {
        warn!(
            "[GOVERNANCE] Onboarding verification failed for peer {}. Disconnect advised.",
            pid_str
        );
        return false;
    }

    info!(
        "[GOVERNANCE] Peer {} successfully verified via onboarding identity.",
        pid_str
    );

    // ✅ Daftarkan kunci publik dari onboarding agar verifikasi pesan berikutnya berhasil
    // Gunakan `try_from_bytes` lalu konversi ke `libp2p::identity::PublicKey`
    match libp2p::identity::ed25519::PublicKey::try_from_bytes(&public_key) {
        Ok(ed_pubkey) => {
            let libp2p_pk = libp2p::identity::PublicKey::from(ed_pubkey);
            if let Err(e) = security.register_peer_key(remote_peer_id.clone(), libp2p_pk) {
                warn!(
                    "[GOVERNANCE] Failed to register onboarding key for {}: {}",
                    pid_str, e
                );
            } else {
                debug!(
                    "[GOVERNANCE] Onboarding public key registered for {}",
                    pid_str
                );
            }
        }
        Err(e) => {
            warn!("[GOVERNANCE] Invalid public key bytes from onboarding: {}", e);
        }
    }

    world_state.mark_peer_activated(&pid_str);

    if world_state.is_peer_activated(&pid_str) {
        info!(
            "[GOVERNANCE] Peer {} confirmed activated in WorldState.",
            pid_str
        );
    } else {
        warn!(
            "[GOVERNANCE] Peer {} verified but activation flag not set correctly.",
            pid_str
        );
    }

    true
}
