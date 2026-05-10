//! Onion Routing dengan X25519 Ephemeral Diffie-Hellman + ChaCha20-Poly1305
//! Implementasi whitepaper §8: Omni-Modal Transmission (privacy layer)
//!
//! CARA KERJA:
//! 1. Sender generate ephemeral X25519 keypair per hop
//! 2. ECDH antara ephemeral privkey sender + pubkey penerima hop
//! 3. Shared secret → ChaCha20-Poly1305 key
//! 4. Payload dibungkus dari luar ke dalam (onion wrap)
//! 5. Setiap hop hanya tahu hop berikutnya
//!
//! ## PATCH 7: Verifikasi Kepemilikan Kunci (sekarang di-enforce)
//! Setiap `HopInfo` HARUS menyertakan `activation_cert` — tanda tangan Ed25519 dari
//! authority yang mengikat peer ID ke X25519 pubkey. `build_onion_packet` akan
//! menolak hop tanpa sertifikat atau sertifikat yang tidak valid.
//!
//! ## PATCH H-05: MAC field dihapus, autentikasi murni dari AEAD Poly1305.
//!
//! ## L-04: Opsional authority_pubkey hanya untuk debug
//! Saat build non-debug (release), `authority_pubkey` wajib ada; jika `None`,
//! `verify_hop_ownership` akan langsung gagal. Di debug, diizinkan untuk kemudahan
//! development.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{PublicKey as EdPublicKey, Signature as EdSignature, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// ==========================================
// 1. ERROR TYPES
// ==========================================
#[derive(Debug)]
pub enum OnionError {
    CryptoError(String),
    SerializationError(String),
    InvalidFormat(String),
    EmptyRoute,
    InvalidPublicKey(String),
    InvalidHops,
    EncryptionError,
    InvalidEphemeralKey,
    DecryptionFailed,
}

impl fmt::Display for OnionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OnionError::CryptoError(e) => write!(f, "Onion Crypto: {}", e),
            OnionError::SerializationError(e) => write!(f, "Onion Serde: {}", e),
            OnionError::InvalidFormat(e) => write!(f, "Onion Format: {}", e),
            OnionError::EmptyRoute => write!(f, "Empty route"),
            OnionError::InvalidPublicKey(e) => write!(f, "Bad pubkey: {}", e),
            OnionError::InvalidHops => write!(f, "Invalid hops"),
            OnionError::EncryptionError => write!(f, "Encryption error"),
            OnionError::InvalidEphemeralKey => write!(f, "Invalid ephemeral key"),
            OnionError::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}
impl Error for OnionError {}

// ==========================================
// 2. STRUCTURES
// ==========================================

/// Satu lapisan onion — dibawa oleh setiap hop.
///
/// # Note on MAC field (FIX H-05)
/// The `mac` field has been REMOVED. ChaCha20-Poly1305 is an AEAD cipher that
/// provides built-in 128-bit authentication (the Poly1305 tag). A separate MAC
/// field is redundant and the previous implementation was a dummy (just a copy of
/// the nonce), which created a dangerous false sense of security.
/// Authentication is now exclusively provided by the AEAD tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    pub payload: Vec<u8>,   // nonce(12) || ciphertext || poly1305_tag(16) — AEAD authenticated
    pub ephemeral_pk: String,
    #[serde(default)]
    pub next_hop: String, // PeerId tujuan berikutnya, "" = final hop
}

/// Node keypair untuk menerima onion — simpan static X25519 key
#[derive(Clone)]
pub struct OnionNodeKey {
    pub static_secret: StaticSecret,
    pub public_key: PublicKey,
    secret_bytes_cache: [u8; 32],
}

impl OnionNodeKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        let secret_bytes = secret.to_bytes();
        Self {
            static_secret: secret,
            public_key,
            secret_bytes_cache: secret_bytes,
        }
    }

    pub fn from_bytes(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public_key = PublicKey::from(&secret);
        Self {
            static_secret: secret,
            public_key,
            secret_bytes_cache: secret_bytes,
        }
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.public_key.as_bytes())
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret_bytes_cache
    }
}

// ==========================================
// 3. INTERNAL CRYPTO ENGINE
// ==========================================

fn derive_enc_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ESS-ONION-ENC-KEY-v1");
    hasher.update(shared_secret);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// [FIX H-05] encrypt_payload: removed dummy mac return value.
fn encrypt_payload(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, OnionError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| OnionError::EncryptionError)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| OnionError::EncryptionError)?;
    let mut result = nonce.to_vec(); // 12 bytes nonce
    result.append(&mut ciphertext); // ciphertext + 16-byte Poly1305 tag
    Ok(result)
}

// [FIX H-05] decrypt_payload: removed unused _mac parameter.
fn decrypt_payload(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, OnionError> {
    if ciphertext.len() < 12 {
        return Err(OnionError::DecryptionFailed);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| OnionError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    cipher
        .decrypt(nonce, &ciphertext[12..])
        .map_err(|_| OnionError::DecryptionFailed)
}

/// Enkripsi payload untuk satu hop
fn encrypt_layer(
    payload: &[u8],
    peer_pk: &PublicKey,
    next_hop: String,
) -> Result<OnionLayer, OnionError> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(peer_pk);
    let enc_key = derive_enc_key(shared_secret.as_bytes());
    if enc_key == [0u8; 32] {
        return Err(OnionError::CryptoError(
            "Derived enc_key is all-zero (weak DH)".into(),
        ));
    }
    let encrypted_payload = encrypt_payload(payload, &enc_key)?;
    Ok(OnionLayer {
        payload: encrypted_payload,
        ephemeral_pk: B64.encode(ephemeral_pk.as_bytes()),
        next_hop,
    })
}

// ==========================================
// 4. BUILDER — Bungkus dari destinasi ke sender (versi baru dengan verifikasi kepemilikan)
// ==========================================

/// Informasi hop: ID peer + kunci publik X25519 (base64) + activation certificate.
///
/// [FIX L-18] Ownership verification is now ENFORCED here, not just a comment.
/// The `activation_cert` field is required and must carry a valid Ed25519 signature
/// from the authority binding this peer's X25519 public key to its identity.
/// `build_onion_packet` will reject any hop with an unverified or missing cert
/// **only if `authority_pubkey` is provided**.
pub struct HopInfo {
    pub peer_id: String,
    pub pubkey_b64: String,
    /// Ed25519 signature (base64) from the authority confirming that `peer_id`
    /// owns `pubkey_b64`. Required when verification is active.
    pub activation_cert: String,
}

/// [FIX L-18 / L-04] Verify that a HopInfo's X25519 pubkey is bound to the peer identity
/// via a valid authority signature.
///
/// In **debug builds**, `authority_pubkey` may be `None` — the check is skipped.
/// In **release builds**, a `None` key immediately returns an error, forcing
/// the system to always use a real authority key in production.
pub fn verify_hop_ownership(
    hop: &HopInfo,
    authority_pubkey: Option<&EdPublicKey>,
) -> Result<(), OnionError> {
    let authority_pubkey = match authority_pubkey {
        Some(pk) => pk,
        None => {
            #[cfg(debug_assertions)]
            {
                eprintln!("[ONION] Warning: authority_pubkey is None, allowed only in debug builds.");
                return Ok(());
            }
            #[cfg(not(debug_assertions))]
            {
                return Err(OnionError::InvalidPublicKey(
                    "Authority public key is required for production".into(),
                ));
            }
        }
    };
    if hop.activation_cert.is_empty() {
        return Err(OnionError::InvalidPublicKey(
            format!("hop {} has no activation certificate — ownership not proven", hop.peer_id)
        ));
    }
    let sig_bytes = B64
        .decode(&hop.activation_cert)
        .map_err(|_| OnionError::InvalidPublicKey("cert base64 decode failed".into()))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| OnionError::InvalidPublicKey("cert wrong length".into()))?;
    let sig = EdSignature::from_bytes(&sig_arr)
        .map_err(|_| OnionError::InvalidPublicKey("invalid Ed25519 signature".into()))?;
    let msg = format!("ESS-HOP-BIND-v1:{}:{}", hop.peer_id, hop.pubkey_b64);
    authority_pubkey.verify(msg.as_bytes(), &sig)
        .map_err(|_| OnionError::InvalidPublicKey(
            format!("hop {} ownership verification FAILED — cert invalid", hop.peer_id)
        ))
}

/// Bangun onion packet penuh (berbasis HopInfo).
///
/// [FIX L-18] All hops are now verified against the authority public key before
/// the packet is built. If `authority_pubkey` is `None`, verification is skipped
/// in debug builds, but rejected in release builds (see `verify_hop_ownership`).
pub fn build_onion_packet(
    hops: &[HopInfo],
    payload: &[u8],
    padding_size: usize,
    authority_pubkey: Option<&EdPublicKey>,
) -> Result<OnionLayer, OnionError> {
    if hops.is_empty() {
        return Err(OnionError::EmptyRoute);
    }
    if hops.len() < 2 {
        return Err(OnionError::InvalidHops);
    }
    // [FIX L-18] Enforce ownership verification for every hop (if key provided)
    for hop in hops {
        verify_hop_ownership(hop, authority_pubkey)?;
    }

    let padded = pad_payload(payload, padding_size);
    let mut current_payload = padded;
    let mut outer_layer: Option<OnionLayer> = None;

    for (i, hop) in hops.iter().enumerate().rev() {
        let next_hop_id = if i + 1 < hops.len() {
            hops[i + 1].peer_id.clone()
        } else {
            String::new()
        };
        let their_pk_bytes = B64
            .decode(&hop.pubkey_b64)
            .map_err(|_| OnionError::InvalidPublicKey("decode error".into()))?;
        let their_pk_arr: [u8; 32] = their_pk_bytes
            .try_into()
            .map_err(|_| OnionError::InvalidPublicKey("length error".into()))?;
        let their_pk = PublicKey::from(their_pk_arr);

        let layer = encrypt_layer(&current_payload, &their_pk, next_hop_id)?;
        current_payload = serde_json::to_vec(&layer)
            .map_err(|_| OnionError::SerializationError("json error".into()))?;
        outer_layer = Some(layer);
    }
    outer_layer.ok_or(OnionError::InvalidHops)
}

// ==========================================
// 5. PEEL SINGLE LAYER
// ==========================================

/// Lepas satu lapis onion menggunakan private key node (StaticSecret).
/// Return (next_hop, inner_payload).
pub fn peel_onion_layer(
    layer: &OnionLayer,
    our_sk: &StaticSecret,
) -> Result<(String, Vec<u8>), OnionError> {
    let eph_pk_bytes = B64
        .decode(&layer.ephemeral_pk)
        .map_err(|_| OnionError::InvalidEphemeralKey)?;
    let eph_pk_arr: [u8; 32] = eph_pk_bytes
        .try_into()
        .map_err(|_| OnionError::InvalidEphemeralKey)?;
    let eph_pk = PublicKey::from(eph_pk_arr);

    let shared = our_sk.diffie_hellman(&eph_pk);
    let enc_key = derive_enc_key(shared.as_bytes());

    // FIX H-05: no more separate mac, payload is self-authenticating AEAD
    let plaintext = decrypt_payload(&layer.payload, &enc_key)?;
    Ok((layer.next_hop.clone(), plaintext))
}

// ==========================================
// 6. PADDING
// ==========================================

pub fn pad_payload(payload: &[u8], block_size: usize) -> Vec<u8> {
    let block_size = block_size.max(1);
    let pad_len = if payload.len() % block_size == 0 {
        0
    } else {
        block_size - (payload.len() % block_size)
    };
    let total = payload.len() + pad_len;
    let mut padded = Vec::with_capacity(total + 2);
    let orig_len = payload.len() as u16;
    padded.extend_from_slice(&orig_len.to_le_bytes());
    padded.extend_from_slice(payload);
    padded.extend(std::iter::repeat(0u8).take(pad_len));
    padded
}

pub fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>, OnionError> {
    if padded.len() < 2 {
        return Err(OnionError::InvalidFormat("Payload too short to unpad".into()));
    }
    let orig_len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    if 2 + orig_len > padded.len() {
        return Err(OnionError::InvalidFormat("Padding length mismatch".into()));
    }
    Ok(padded[2..2 + orig_len].to_vec())
}

// ==========================================
// 7. UNIT TESTS (diperbarui untuk L-18 dengan Option)
// ==========================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair as EdKeypair;
    use rand::rngs::OsRng;

    fn make_node() -> (OnionNodeKey, String) {
        let key = OnionNodeKey::generate();
        let pubkey_b64 = key.public_key_b64();
        (key, pubkey_b64)
    }

    fn sign_hop(hop_peer_id: &str, hop_pubkey_b64: &str, authority_key: &EdKeypair) -> String {
        let msg = format!("ESS-HOP-BIND-v1:{}:{}", hop_peer_id, hop_pubkey_b64);
        let sig = authority_key.sign(msg.as_bytes());
        B64.encode(sig.to_bytes())
    }

    fn make_authority() -> EdKeypair {
        EdKeypair::generate(&mut OsRng)
    }

    #[test]
    fn test_single_hop_onion_rejected() {
        let (_node_key, pubkey_b64) = make_node();
        let auth = make_authority();
        let hops = vec![HopInfo {
            peer_id: "dest".into(),
            pubkey_b64: pubkey_b64.clone(),
            activation_cert: sign_hop("dest", &pubkey_b64, &auth),
        }];
        let payload = b"Hello ESS Onion";
        // Harus error karena cuma 1 hop
        assert!(build_onion_packet(&hops, payload, 256, Some(&auth.public)).is_err());
    }

    #[test]
    fn test_multi_hop_onion() {
        let (relay1_key, relay1_pk) = make_node();
        let (relay2_key, relay2_pk) = make_node();
        let (dest_key, dest_pk) = make_node();

        let auth = make_authority();

        let hops = vec![
            HopInfo {
                peer_id: "relay1".into(),
                pubkey_b64: relay1_pk.clone(),
                activation_cert: sign_hop("relay1", &relay1_pk, &auth),
            },
            HopInfo {
                peer_id: "relay2".into(),
                pubkey_b64: relay2_pk.clone(),
                activation_cert: sign_hop("relay2", &relay2_pk, &auth),
            },
            HopInfo {
                peer_id: "dest".into(),
                pubkey_b64: dest_pk.clone(),
                activation_cert: sign_hop("dest", &dest_pk, &auth),
            },
        ];

        let original = b"Top secret ESS payload";
        let packet = build_onion_packet(&hops, original, 256, Some(&auth.public)).unwrap();

        let (next1, inner1) = peel_onion_layer(&packet, &relay1_key.static_secret).unwrap();
        assert_eq!(next1, "relay2");
        let layer2: OnionLayer = serde_json::from_slice(&inner1)
            .expect("Inner payload harus berupa OnionLayer");

        let (next2, inner2) = peel_onion_layer(&layer2, &relay2_key.static_secret).unwrap();
        assert_eq!(next2, "dest");
        let layer3: OnionLayer = serde_json::from_slice(&inner2)
            .expect("Inner payload harus berupa OnionLayer");

        let (next3, inner3) = peel_onion_layer(&layer3, &dest_key.static_secret).unwrap();
        assert_eq!(next3, "");
        let final_payload = unpad_payload(&inner3).unwrap();
        assert_eq!(&final_payload, original);
    }

    #[test]
    fn test_peel_onion_layer_new_api() {
        let (relay_key, relay_pk_b64) = make_node();
        let relay_pk_bytes = B64.decode(&relay_pk_b64).unwrap();
        let relay_pk: [u8; 32] = relay_pk_bytes.try_into().unwrap();
        let relay_pubkey = PublicKey::from(relay_pk);

        let plaintext = b"hello from new peel";
        let layer = encrypt_layer(plaintext, &relay_pubkey, String::new()).unwrap();

        let (next_hop, decrypted) =
            peel_onion_layer(&layer, &relay_key.static_secret).unwrap();
        assert_eq!(next_hop, "");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_build_onion_rejects_unverified_hop() {
        let (_node_key, pubkey_b64) = make_node();
        let auth = make_authority();
        let hops = vec![
            HopInfo {
                peer_id: "relay".into(),
                pubkey_b64: pubkey_b64.clone(),
                activation_cert: String::new(), // kosong!
            },
            HopInfo {
                peer_id: "dest".into(),
                pubkey_b64: pubkey_b64.clone(),
                activation_cert: sign_hop("dest", &pubkey_b64, &auth),
            },
        ];

        let result = build_onion_packet(&hops, b"data", 64, Some(&auth.public));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("has no activation certificate"));
    }

    #[test]
    fn test_build_onion_rejects_bad_cert() {
        let (_node_key, pubkey_b64) = make_node();
        let auth = make_authority();
        let wrong_auth = make_authority(); // authority lain

        let hops = vec![
            HopInfo {
                peer_id: "relay".into(),
                pubkey_b64: pubkey_b64.clone(),
                activation_cert: sign_hop("relay", &pubkey_b64, &wrong_auth),
            },
            HopInfo {
                peer_id: "dest".into(),
                pubkey_b64: pubkey_b64.clone(),
                activation_cert: sign_hop("dest", &pubkey_b64, &auth),
            },
        ];

        let result = build_onion_packet(&hops, b"data", 64, Some(&auth.public));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ownership verification FAILED"));
    }

    #[test]
    fn test_build_onion_skips_verification_when_no_authority_key() {
        let (_node_key, pubkey_b64) = make_node();
        // Tanpa authority key, hop tanpa cert tetap diterima (hanya di debug)
        let hops = vec![
            HopInfo {
                peer_id: "relay".into(),
                pubkey_b64: pubkey_b64.clone(),
                activation_cert: String::new(),
            },
            HopInfo {
                peer_id: "dest".into(),
                pubkey_b64: pubkey_b64.clone(),
                activation_cert: String::new(),
            },
        ];
        let result = build_onion_packet(&hops, b"data", 64, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_padding() {
        let payload = b"hello";
        let padded = pad_payload(payload, 128);
        assert!(padded.len() >= 2 + 5);
        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(&unpadded, payload);
    }
}
