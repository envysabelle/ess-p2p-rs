use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, Key, KeyExport},
    ml_kem_1024::{
        Ciphertext as MlKem1024Ciphertext,
        DecapsulationKey as MlKem1024DecapsulationKey,
        EncapsulationKey as MlKem1024EncapsulationKey,
    },
    MlKem1024, SharedKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use std::convert::TryInto;
use x25519_dalek::{
    EphemeralSecret,
    PublicKey as X25519PublicKey,
    StaticSecret as X25519StaticSecret,
};
use zeroize::{Zeroize, ZeroizeOnDrop};
use hkdf::Hkdf;

// ── Error types ────────────────────────────
// ── KDF internal utilities ──────────────────

#[derive(Debug)]
pub enum PqcError {
    EncapsulationFailed,
    DecapsulationFailed(String),
    InvalidPublicKey(String),
    InvalidCiphertext(String),
}

impl std::fmt::Display for PqcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqcError::EncapsulationFailed => write!(f, "ML-KEM encapsulation failed"),
            PqcError::DecapsulationFailed(e) => write!(f, "ML-KEM decapsulation failed: {}", e),
            PqcError::InvalidPublicKey(e) => write!(f, "Invalid public key: {}", e),
            PqcError::InvalidCiphertext(e) => write!(f, "Invalid ciphertext: {}", e),
        }
    }
}

impl std::error::Error for PqcError {}

// ── Public key container ──────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub ml_kem_ek: String,
    pub x25519_pk: String,
    pub node_id: String,
}

// ── Ciphertext container ──────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub ml_kem_ct: String,
    pub x25519_ephemeral_pk: String,
    pub context: String,
}

// ── Session key ───────────────────────────
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey {
    pub key: [u8; 32],
}

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

// ML-KEM-1024 public-key byte container
type MlKem1024EkBytes = Key<MlKem1024EncapsulationKey>;

// ── Bob's keypair ─────────────────────────
pub struct HybridKeyPair {
    pub public_key: HybridPublicKey,
    ml_kem_dk: MlKem1024DecapsulationKey,
    x25519_sk: X25519StaticSecret,
}

impl HybridKeyPair {
    pub fn generate(node_id: impl Into<String>) -> Self {
        // Requires ml-kem feature `getrandom`
        let (dk, ek) = MlKem1024::generate_keypair();

        let mut osrng = OsRng;
        let x25519_sk = X25519StaticSecret::random_from_rng(&mut osrng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        let ek_bytes: MlKem1024EkBytes = ek.to_bytes();
        let ek_slice: &[u8] = ek_bytes.as_ref();

        let public_key = HybridPublicKey {
            ml_kem_ek: B64.encode(ek_slice),
            x25519_pk: B64.encode(x25519_pk.as_bytes()),
            node_id: node_id.into(),
        };

        HybridKeyPair {
            public_key,
            ml_kem_dk: dk,
            x25519_sk,
        }
    }

    pub fn decapsulate(&self, ciphertext: &HybridCiphertext) -> Result<SessionKey, PqcError> {
        let ct_bytes = B64
            .decode(&ciphertext.ml_kem_ct)
            .map_err(|e| PqcError::InvalidCiphertext(e.to_string()))?;

        let ct: MlKem1024Ciphertext = ct_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PqcError::InvalidCiphertext("ML-KEM CT parse failed".into()))?;

        let ss_pq: SharedKey = self.ml_kem_dk.decapsulate(&ct);

        // ✅ Gunakan DecapsulationFailed: validasi shared secret tidak all-zero
        if ss_pq.as_slice() == [0u8; 32] {
            return Err(PqcError::DecapsulationFailed(
                "ML-KEM shared secret is all-zero — possible decapsulation failure".into(),
            ));
        }

        let epk_bytes = B64
            .decode(&ciphertext.x25519_ephemeral_pk)
            .map_err(|e| PqcError::InvalidPublicKey(e.to_string()))?;
        if epk_bytes.len() != 32 {
            return Err(PqcError::InvalidPublicKey("X25519 pk length".into()));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&epk_bytes);
        let alice_epk = X25519PublicKey::from(arr);
        let ss_x = self.x25519_sk.diffie_hellman(&alice_epk);

        let key = kdf(ss_pq.as_slice(), ss_x.as_bytes(), ciphertext.context.as_bytes())?;
        Ok(SessionKey { key })
    }
}

// ── Alice's side ──────────────────────────
pub fn encapsulate(
    bob_pubkey: &HybridPublicKey,
    context: impl Into<String>,
) -> Result<(HybridCiphertext, SessionKey), PqcError> {
    let context = context.into();

    let ek_bytes = B64
        .decode(&bob_pubkey.ml_kem_ek)
        .map_err(|e| PqcError::InvalidPublicKey(e.to_string()))?;

    let ek_key: MlKem1024EkBytes = ek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| PqcError::InvalidPublicKey("ML-KEM EK parse failed".into()))?;

    let ek = MlKem1024EncapsulationKey::new(&ek_key)
        .map_err(|_| PqcError::InvalidPublicKey("ML-KEM EK parse failed".into()))?;

    let (ct_pq, ss_pq) = ek.encapsulate();

    let bob_x_bytes = B64
        .decode(&bob_pubkey.x25519_pk)
        .map_err(|e| PqcError::InvalidPublicKey(e.to_string()))?;
    if bob_x_bytes.len() != 32 {
        return Err(PqcError::InvalidPublicKey("X25519 pk length".into()));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bob_x_bytes);
    let bob_x_pk = X25519PublicKey::from(arr);

    let mut osrng = OsRng;
    let alice_esk = EphemeralSecret::random_from_rng(&mut osrng);
    let alice_epk = X25519PublicKey::from(&alice_esk);
    let ss_x = alice_esk.diffie_hellman(&bob_x_pk);

    let key = kdf(ss_pq.as_slice(), ss_x.as_bytes(), context.as_bytes())?;

    // ✅ Gunakan EncapsulationFailed: validasi bahwa session key tidak all-zero
    if key == [0u8; 32] {
        return Err(PqcError::EncapsulationFailed);
    }

    let ct_slice: &[u8] = ct_pq.as_ref();

    let ciphertext = HybridCiphertext {
        ml_kem_ct: B64.encode(ct_slice),
        x25519_ephemeral_pk: B64.encode(alice_epk.as_bytes()),
        context,
    };

    Ok((ciphertext, SessionKey { key }))
}

/// HKDF extract-then-expand menggunakan crate hkdf (RFC 5869) dengan Sha3-256
fn hkdf_extract_expand(ikm: &[u8], info: &[u8], salt: &[u8]) -> Result<[u8; 32], PqcError> {
    let hk = Hkdf::<Sha3_256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| PqcError::EncapsulationFailed)?;
    Ok(okm)
}

/// KDF dengan concatenation (NIST SP 800-227 rekomendasi: IKM = ss_pq || ss_x)
fn kdf(ss_pq: &[u8], ss_x: &[u8], context: &[u8]) -> Result<[u8; 32], PqcError> {
    let mut ikm = Vec::with_capacity(ss_pq.len() + ss_x.len());
    ikm.extend_from_slice(ss_pq);
    ikm.extend_from_slice(ss_x);

    let salt = b"ESS-HYBRID-KEM-CONCAT-v1";
    hkdf_extract_expand(&ikm, context, salt)
}

// ── Tests ─────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let bob = HybridKeyPair::generate("bob");
        let (ct, alice_key) = encapsulate(&bob.public_key, "session-1").unwrap();
        let bob_key = bob.decapsulate(&ct).unwrap();
        assert_eq!(alice_key.key, bob_key.key);
    }

    #[test]
    fn test_different_contexts_different_keys() {
        let bob = HybridKeyPair::generate("bob");
        let (_, k1) = encapsulate(&bob.public_key, "ctx1").unwrap();
        let (_, k2) = encapsulate(&bob.public_key, "ctx2").unwrap();
        assert_ne!(k1.key, k2.key);
    }
}
