// src/keystore.rs
use aes_gcm::{
    aead::Aead,
    Aes256Gcm, Nonce,
    KeyInit,
};
use rand::RngCore;
use sha2::Sha256;
use hkdf::Hkdf;
use std::{fs, path::Path, env};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const KEYSTORE_PATH: &str = "data/keystore.enc";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

pub struct SoftwareKeystore {
    master_key: [u8; 32],
}

impl SoftwareKeystore {
    pub fn initialize() -> Result<Self, Box<dyn std::error::Error>> {
        // 🔴 Patch 2: Hapus password default, env wajib ada
        let password = env::var("ESS_KEYSTORE_PASSWORD")
            .or_else(|_| env::var("ESS_MASTER_SECRET"))
            .map_err(|_| "ESS_KEYSTORE_PASSWORD or ESS_MASTER_SECRET must be set")?;

        if Path::new(KEYSTORE_PATH).exists() {
            let data = fs::read(KEYSTORE_PATH)?;
            if data.len() < SALT_LEN + NONCE_LEN {
                return Err("Keystore file corrupted (too short)".into());
            }
            let (salt, rest) = data.split_at(SALT_LEN);
            let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

            // [FIX C-01] Use proper PBKDF2 via the pbkdf2 crate
            let key = derive_key_from_password(password.as_bytes(), salt);
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|_| "Decryption failed: invalid key length")?;
            let nonce = Nonce::from_slice(nonce_bytes);
            let plaintext = cipher.decrypt(nonce, ciphertext)
                .map_err(|_| "Decryption failed: wrong password or corrupted data")?;
            let mut master_key = [0u8; 32];
            master_key.copy_from_slice(&plaintext[..32]);
            Ok(Self { master_key })
        } else {
            let mut master_key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut master_key);

            let mut salt = [0u8; SALT_LEN];
            rand::thread_rng().fill_bytes(&mut salt);

            let key = derive_key_from_password(password.as_bytes(), &salt);
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|_| "Encryption failed: invalid key length")?;
            let mut nonce_bytes = [0u8; NONCE_LEN];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher.encrypt(nonce, master_key.as_ref())
                .expect("encryption failed");

            let mut store = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
            store.extend_from_slice(&salt);
            store.extend_from_slice(&nonce_bytes);
            store.extend_from_slice(&ciphertext);

            if let Some(parent) = Path::new(KEYSTORE_PATH).parent() {
                fs::create_dir_all(parent)?;
            }

            // [FIX M-14 companion] Write keystore with 0600 permissions (owner-only)
            #[cfg(unix)]
            {
                use std::fs::OpenOptions;
                use std::io::Write;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(KEYSTORE_PATH)?;
                file.write_all(&store)?;
            }
            #[cfg(not(unix))]
            {
                fs::write(KEYSTORE_PATH, store)?;
            }

            Ok(Self { master_key })
        }
    }

    pub fn load_or_create() -> Result<Self, Box<dyn std::error::Error>> {
        Self::initialize()
    }

    pub fn master_key(&self) -> [u8; 32] {
        self.master_key
    }

    // [FIX H-10] Replace SHA256 naive derivation with proper HKDF (RFC 5869)
    pub fn derive_key(&self, purpose: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.master_key);
        let info = format!("ESS-DERIVE-v2:{}", purpose);
        let mut okm = [0u8; 32];
        hk.expand(info.as_bytes(), &mut okm)
            .expect("HKDF expand failed: output length too large");
        okm
    }
}

// [FIX C-01] Correct PBKDF2 using the pbkdf2 crate (RFC 8018 compliant)
// Password is the HMAC key, salt+counter is input — as per standard.
fn derive_key_from_password(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, 600_000, &mut key);
    key
}
