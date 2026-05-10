use crate::authority::NodeRole;
use libp2p::{identity, PeerId};
use sha2::{Digest, Sha256};
use std::{env, fs, io, path::Path};
use tokio;
use tracing;

#[derive(Clone)]
pub struct EssIdentity {
    keypair: identity::Keypair,
    peer_id: PeerId,
    ess_id: String,
    role: Option<NodeRole>,
    authority_peer_id: Option<String>,
    authority_hash: Option<String>,
    authority_signature: Option<String>,
}

impl EssIdentity {
    pub fn load_or_create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let keypair = if path.exists() {
            let bytes = fs::read(path)?;
            identity::Keypair::from_protobuf_encoding(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        } else {
            let keypair = identity::Keypair::generate_ed25519();
            let bytes = keypair
                .to_protobuf_encoding()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            fs::write(path, bytes)?;
            keypair
        };

        let peer_id = PeerId::from(keypair.public());
        let ess_id = sha256_hex(peer_id.to_string().as_bytes());

        // Baca role dari file terpisah jika ada
        let role_file = path.with_file_name("role.txt");
        let role = if role_file.exists() {
            let content = std::fs::read_to_string(&role_file).unwrap_or_default();
            let role_str = content.trim().to_lowercase();
            parse_role_env_inner(&role_str)
        } else {
            None
        };

        let mut identity = Self {
            keypair,
            peer_id,
            ess_id,
            role,
            authority_peer_id: None,
            authority_hash: None,
            authority_signature: None,
        };

        if identity.role.is_none() {
            identity.bind_role(NodeRole::Client);
        }

        if let Some(role) = parse_role_env("ESS_AUTHORITY_ROLE") {
            let authority_peer_id = env::var("ESS_AUTHORITY_PEER_ID").unwrap_or_default();
            let authority_hash = env::var("ESS_AUTHORITY_HASH").unwrap_or_default();
            let authority_signature = env::var("ESS_AUTHORITY_SIGNATURE").unwrap_or_default();

            if !authority_peer_id.is_empty()
                && !authority_hash.is_empty()
                && !authority_signature.is_empty()
            {
                identity.bind_authority(
                    role,
                    authority_peer_id,
                    authority_hash,
                    authority_signature,
                );
            }
        }

        if is_truthy_env("ESS_CLEAR_AUTHORITY_BINDING") {
            identity.clear_authority_binding();
        }

        identity.bootstrap_governance_self_check()?;

        tracing::debug!("[Identity] {}", identity.governance_summary());

        Ok(identity)
    }

    /// 🔥 Konstruktor langsung dari Keypair
    pub fn from_keypair(keypair: identity::Keypair) -> Self {
        let peer_id = PeerId::from(keypair.public());
        let ess_id = sha256_hex(peer_id.to_string().as_bytes());
        Self {
            keypair,
            peer_id,
            ess_id,
            role: None,
            authority_peer_id: None,
            authority_hash: None,
            authority_signature: None,
        }
    }

    /// Simpan keypair saja (format yang sudah ada)
    pub fn save_keypair(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = self
            .keypair
            .to_protobuf_encoding()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        fs::write(path, &bytes)
    }

    /// Simpan role ke file teks terpisah
    pub fn save_role(&self, identity_path: impl AsRef<Path>) -> io::Result<()> {
        let role_path = identity_path.as_ref().with_file_name("role.txt");
        let role_str = match &self.role {
            Some(r) => r.as_str().to_string(),
            None => String::from("client"),
        };
        fs::write(role_path, role_str)
    }

    pub fn keypair(&self) -> &identity::Keypair {
        &self.keypair
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn ess_id(&self) -> &str {
        &self.ess_id
    }

    pub fn role(&self) -> Option<&NodeRole> {
        self.role.as_ref()
    }

    pub fn authority_peer_id(&self) -> Option<&str> {
        self.authority_peer_id.as_deref()
    }

    pub fn authority_hash(&self) -> Option<&str> {
        self.authority_hash.as_deref()
    }

    pub fn authority_signature(&self) -> Option<&str> {
        self.authority_signature.as_deref()
    }

    pub fn bind_authority(
        &mut self,
        role: NodeRole,
        authority_peer_id: impl Into<String>,
        authority_hash: impl Into<String>,
        authority_signature: impl Into<String>,
    ) {
        self.role = Some(role);
        self.authority_peer_id = Some(authority_peer_id.into());
        self.authority_hash = Some(authority_hash.into());
        self.authority_signature = Some(authority_signature.into());
    }

    pub fn bind_role(&mut self, role: NodeRole) {
        self.role = Some(role);
    }

    pub fn clear_authority_binding(&mut self) {
        self.role = None;
        self.authority_peer_id = None;
        self.authority_hash = None;
        self.authority_signature = None;
    }

    pub fn is_authority_bound(&self) -> bool {
        self.role.is_some()
            && self.authority_peer_id.is_some()
            && self.authority_hash.is_some()
            && self.authority_signature.is_some()
    }

    pub fn governance_summary(&self) -> String {
        format!(
            "peer_id={}, ess_id={}, role={:?}, bound={}, authority_peer_id={:?}, authority_hash={:?}, authority_signature={:?}",
            self.peer_id(),
            self.ess_id(),
            self.role(),
            self.is_authority_bound(),
            self.authority_peer_id(),
            self.authority_hash(),
            self.authority_signature(),
        )
    }

    pub fn sign(&self, msg: &[u8]) -> io::Result<Vec<u8>> {
        self.keypair
            .sign(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.keypair.public().verify(msg, sig)
    }

    fn bootstrap_governance_self_check(&self) -> io::Result<()> {
        let probe = format!("ess-bootstrap:{}", self.peer_id()).into_bytes();
        let sig = self.sign(&probe)?;
        let _verified = self.verify(&probe, &sig);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fungsi baru untuk inisialisasi identitas sebelum onboarding
// ---------------------------------------------------------------------------

pub async fn initialize_identity(
    path: impl AsRef<Path>,
) -> io::Result<(identity::Keypair, String)> {
    let path = path.as_ref().to_owned();
    tokio::task::spawn_blocking(move || {
        let ess = EssIdentity::load_or_create(&path)?;
        let peer_id = ess.peer_id().to_string();
        let keypair_bytes = ess
            .keypair()
            .to_protobuf_encoding()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let keypair = identity::Keypair::from_protobuf_encoding(&keypair_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok((keypair, peer_id))
    })
    .await
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
}

// ---------------------------------------------------------------------------
// Helper functions (tidak diubah)
// ---------------------------------------------------------------------------

fn parse_role_env(name: &str) -> Option<NodeRole> {
    let raw = env::var(name).ok()?;
    parse_role_env_inner(&raw)
}

fn parse_role_env_inner(raw: &str) -> Option<NodeRole> {
    let role = raw.trim().to_ascii_lowercase();
    match role.as_str() {
        "supernode" => Some(NodeRole::Supernode),
        "validator" => Some(NodeRole::Validator),
        "client" => Some(NodeRole::Client),
        "gateway" => Some(NodeRole::Gateway),
        "standard" => Some(NodeRole::Standard),
        "observer" => Some(NodeRole::Observer),
        "blocked" => Some(NodeRole::Blocked),
        _ => None,
    }
}

fn is_truthy_env(name: &str) -> bool {
    matches!(
        env::var(name)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_identity_sign_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_id.bin");
        let ess = EssIdentity::load_or_create(path.to_str().unwrap()).unwrap();
        let msg = b"hello";
        let sig = ess.sign(msg).unwrap();
        assert!(ess.verify(msg, &sig));
    }

    #[test]
    fn test_identity_bind_role() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_id2.bin");
        let mut ess = EssIdentity::load_or_create(path.to_str().unwrap()).unwrap();
        ess.bind_role(NodeRole::Supernode);
        assert_eq!(ess.role(), Some(&NodeRole::Supernode));
    }
}
