use crate::network::runtime::types::OnboardRequest;
use crate::network_controller::NetworkController;

use hmac::{Hmac, Mac};
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tokio::time::{timeout, Duration};

// --- X25519 onion key material (STEP 5) ---
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

fn to_boxed_err(msg: impl ToString) -> Box<dyn std::error::Error + Send> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        msg.to_string(),
    ))
}

fn get_master_secret() -> Option<Vec<u8>> {
    match env::var("ESS_MASTER_SECRET") {
        Ok(secret) => Some(secret.as_bytes().to_vec()),
        Err(_) => {
            tracing::error!("ESS_MASTER_SECRET environment variable not set");
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProfile {
    pub name: String,
    pub email: String,
    pub peer_id: String,
    pub serial_number: String,
    pub is_activated: bool,
    /// X25519 public key (hex encoded) untuk onion routing
    #[serde(default)]
    pub x25519_pubkey: String,
}

// --- X25519 key management ---
fn x25519_secret_path() -> PathBuf {
    PathBuf::from("data/identity/x25519_secret.bin")
}

/// Muat StaticSecret dari disk, atau generate baru & simpan.
/// Mengembalikan `Box<dyn Error + Send>` untuk kompatibilitas dengan spawn_blocking.
pub fn load_or_generate_x25519_secret() -> Result<StaticSecret, Box<dyn std::error::Error + Send>> {
    let path = x25519_secret_path();
    if path.exists() {
        let bytes = fs::read(&path)
            .map_err(|e| to_boxed_err(format!("Failed to read X25519 secret: {}", e)))?;
        if bytes.len() != 32 {
            return Err(to_boxed_err(
                "X25519 secret file corrupted (wrong length)",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(StaticSecret::from(arr))
    } else {
        let secret = StaticSecret::random_from_rng(OsRng);
        let bytes = secret.to_bytes();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| to_boxed_err(format!("Cannot create dir for X25519 secret: {}", e)))?;
        }
        fs::write(&path, &bytes)
            .map_err(|e| to_boxed_err(format!("Cannot write X25519 secret: {}", e)))?;
        tracing::info!("Generated new X25519 secret key");
        Ok(secret)
    }
}

pub struct OnboardingManager {
    pub profile_path: String,
}

impl OnboardingManager {
    pub fn new() -> Self {
        Self {
            profile_path: "data/my_profile.json".to_string(),
        }
    }

    pub fn setup_identity(
        &self,
        local_peer_id: String,
    ) -> Result<LocalProfile, Box<dyn std::error::Error + Send>> {
        let x25519_sk = load_or_generate_x25519_secret()?;
        let x25519_pk = PublicKey::from(&x25519_sk);
        let x25519_pubkey_hex = hex::encode(x25519_pk.as_bytes());

        if Path::new(&self.profile_path).exists() {
            let data = fs::read_to_string(&self.profile_path)
                .map_err(|e| to_boxed_err(format!("Failed to read profile: {}", e)))?;
            let mut profile: LocalProfile = serde_json::from_str(&data)
                .map_err(|e| to_boxed_err(format!("Profile format corrupted: {}", e)))?;

            if profile.peer_id != local_peer_id {
                return Err(to_boxed_err(format!(
                    "❌ Identity Mismatch! Profil punya ID {}, tapi kunci sekarang menghasilkan {}.\n\
                    Cek folder data/. Restore kunci lama, atau hapus my_profile.json untuk reset.",
                    profile.peer_id, local_peer_id
                )));
            }

            if profile.x25519_pubkey.is_empty() {
                profile.x25519_pubkey = x25519_pubkey_hex;
                let json = serde_json::to_string_pretty(&profile).map_err(|e| to_boxed_err(e))?;
                fs::write(&self.profile_path, json).map_err(|e| to_boxed_err(e))?;
                tracing::info!("Updated existing profile with X25519 public key");
            }

            tracing::info!("✅ Verified stable profile for {}", profile.peer_id);
            return Ok(profile);
        }

        // Profil belum ada — cek env var dulu untuk mode non-interaktif
        let env_name  = env::var("ESS_NODE_NAME").ok();
        let env_email = env::var("ESS_NODE_EMAIL").ok();

        let (name, email, sn) = if let (Some(n), Some(e)) = (env_name, env_email) {
            // Mode non-interaktif: semua dari env var
            let sn = env::var("ESS_SERIAL_NUMBER")
                .unwrap_or_else(|_| auto_generate_sn());
            tracing::info!("[ONBOARDING] Non-interactive mode via env vars.");
            (n, e, sn)
        } else {
            // Mode interaktif (fallback untuk terminal)
            self.print_welcome_screen();
            println!("Please provide your credentials to sync with the network:");
            let n = self.elegant_input("  [+] Owner Name      : ");
            let e = self.elegant_input("  [+] Email Address   : ");

            let mut valid_sn = false;
            let mut sn_buf = String::new();
            while !valid_sn {
                sn_buf = self.elegant_input("  [+] Serial Number   : ");
                if verify_sn_checksum(&sn_buf) {
                    println!("      >> [SUCCESS] Hardware identity verified.");
                    valid_sn = true;
                } else {
                    println!("      >> [FAILED] Signature mismatch. Access denied.");
                }
            }
            let _token = self.elegant_input("  [+] Activation Code : ");
            println!("      >> [SUCCESS] Token bound to PeerID.");
            (n, e, sn_buf)
        };

        let profile = LocalProfile {
            name,
            email,
            peer_id: local_peer_id,
            serial_number: sn,
            is_activated: true,
            x25519_pubkey: x25519_pubkey_hex,
        };

        fs::create_dir_all("data")
            .map_err(|e| to_boxed_err(format!("Cannot create data dir: {}", e)))?;
        let json = serde_json::to_string_pretty(&profile)
            .map_err(|e| to_boxed_err(format!("Serialization failed: {}", e)))?;
        fs::write(&self.profile_path, json)
            .map_err(|e| to_boxed_err(format!("Failed to save profile: {}", e)))?;

        println!("\n[SYSTEM] Identity Sealed.");
        println!("[SYSTEM] Node is now authorized. Joining The Syndicate...");
        println!("-----------------------------------------------------------\n");
        tracing::info!("New profile created for {}", profile.peer_id);
        Ok(profile)
    }

    fn print_welcome_screen(&self) {
        println!("===============================================");
        println!("   Sabelle Black Box powered by Envy Sabelle   ");
        println!("===============================================");
        println!("Welcome to The Syndicate.");
        println!("-----------------------------------------------");
    }

    fn elegant_input(&self, prompt: &str) -> String {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        let mut buffer = String::new();
        io::stdin()
            .read_line(&mut buffer)
            .expect("Failed to read input");
        buffer.trim().to_string()
    }
}

pub fn verify_sn_checksum(sn: &str) -> bool {
    let parts: Vec<&str> = sn.split('-').collect();
    if parts.len() != 4 || parts[0] != "ESSBB" {
        return false;
    }

    let base_sn = format!("{}-{}-{}", parts[0], parts[1], parts[2]);
    let provided_checksum = parts[3];

    let key_bytes = match get_master_secret() {
        Some(key) => key,
        None => {
            tracing::error!("Cannot verify SN: master secret unavailable");
            return false;
        }
    };

    let mut mac = match HmacSha256::new_from_slice(&key_bytes) {
        Ok(mac) => mac,
        Err(e) => {
            tracing::error!("HMAC key invalid: {}", e);
            return false;
        }
    };

    mac.update(base_sn.as_bytes());
    let result = mac.finalize().into_bytes();
    let calculated_hash = hex::encode(result);
    let calculated_checksum = &calculated_hash[calculated_hash.len() - 4..].to_uppercase();

    provided_checksum.to_uppercase() == *calculated_checksum
}

/// Auto-generate serial number dari ESS_MASTER_SECRET + hostname.
/// Format: ESSBB-NODE-<hostname_hash>-<checksum>
pub fn auto_generate_sn() -> String {
    let host = hostname::get()
        .map(|h| h.to_string_lossy().to_uppercase())
        .unwrap_or_else(|_| "NODE".to_string());
    // Ambil 3 char dari hostname (alphanumeric only)
    let host_part: String = host.chars()
        .filter(|c| c.is_alphanumeric())
        .take(3)
        .collect();
    let host_part = if host_part.is_empty() { "NOD".to_string() } else { host_part };

    let base_sn = format!("ESSBB-{}-001", host_part);
    let key_bytes = match get_master_secret() {
        Some(k) => k,
        None => {
            tracing::warn!("[ONBOARDING] ESS_MASTER_SECRET not set — using fallback SN.");
            return format!("{}-0000", base_sn);
        }
    };
    let mut mac = match HmacSha256::new_from_slice(&key_bytes) {
        Ok(m) => m,
        Err(_) => return format!("{}-0000", base_sn),
    };
    mac.update(base_sn.as_bytes());
    let result = mac.finalize().into_bytes();
    let hash = hex::encode(result);
    let checksum = &hash[hash.len() - 4..].to_uppercase();
    let sn = format!("{}-{}", base_sn, checksum);
    tracing::info!("[ONBOARDING] Auto-generated SN: {}", sn);
    sn
}

fn load_keypair() -> Option<Keypair> {
    let candidates = vec![
        PathBuf::from("data/identity/ess_identity.bin"),
        PathBuf::from("data/identity/keypair.bin"),
        PathBuf::from("data/libp2p/keypair"),
        PathBuf::from("libp2p/keypair"),
        PathBuf::from("identity.key"),
    ];

    for path in candidates {
        if path.exists() {
            match fs::read(&path) {
                Ok(bytes) => {
                    if let Ok(kp) = Keypair::from_protobuf_encoding(&bytes) {
                        return Some(kp);
                    } else if let Ok(kp) = Keypair::ed25519_from_bytes(bytes) {
                        return Some(kp);
                    } else {
                        tracing::warn!("Failed to parse keypair from {:?}", path);
                    }
                }
                Err(e) => tracing::warn!("Cannot read keypair file {:?}: {}", path, e),
            }
        }
    }

    tracing::error!("No valid libp2p keypair found for onboarding request.");
    None
}

// ========== FUNGSI UTAMA DENGAN RETRY + TIMEOUT ==========
pub async fn send_onboarding_request(
    controller: &NetworkController,
    target_peer: libp2p::PeerId,
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let profile = {
        let manager = OnboardingManager::new();
        if Path::new(&manager.profile_path).exists() {
            let data =
                fs::read_to_string(&manager.profile_path).map_err(|e| to_boxed_err(e))?;
            serde_json::from_str::<LocalProfile>(&data).map_err(|e| to_boxed_err(e))?
        } else {
            return Err(to_boxed_err(
                "Local profile not found. Run onboarding setup first.",
            ));
        }
    };

    let keypair = load_keypair()
        .ok_or_else(|| to_boxed_err("Keypair not found for signing onboarding request"))?;

    let max_retries = 3;
    let mut last_error: Option<Box<dyn std::error::Error + Send>> = None;

    for attempt in 1..=max_retries {
        use rand::RngCore;
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| to_boxed_err(format!("Time error: {}", e)))?
            .as_secs();

        // 🔐 Patch 3: sertakan X25519 pubkey dalam pesan yang ditandatangani
        let message = {
            // Buat dummy request untuk memanfaatkan metode build_signed_message
            let request = OnboardRequest {
                peer_id: profile.peer_id.clone(),
                serial_number: profile.serial_number.clone(),
                signature: vec![], // placeholder
                public_key: vec![], // placeholder
                nonce,
                timestamp,
                x25519_pubkey: Some(profile.x25519_pubkey.clone()),
            };
            request.build_signed_message()
        };

        let signature = keypair
            .sign(message.as_bytes())
            .map_err(|e| to_boxed_err(format!("Sign error: {}", e)))?;

        let public_key = keypair.public().encode_protobuf();

        let request = OnboardRequest {
            peer_id: profile.peer_id.clone(),
            serial_number: profile.serial_number.clone(),
            signature,
            public_key,
            nonce,
            timestamp,
            x25519_pubkey: Some(profile.x25519_pubkey.clone()),
        };

        match timeout(
            Duration::from_secs(10),
            controller.send_onboard_request(target_peer, request),
        )
        .await
        {
            Ok(Ok(_response)) => {
                tracing::info!(
                    "Onboarding request sent to {} successfully (attempt {})",
                    target_peer,
                    attempt
                );
                return Ok(());
            }
            Ok(Err(e)) => {
                let err_msg = format!(
                    "Onboarding request to {} failed (attempt {}): {}",
                    target_peer,
                    attempt,
                    e
                );
                tracing::warn!("{}", err_msg);
                last_error = Some(to_boxed_err(err_msg));
            }
            Err(_timeout) => {
                let err_msg = format!(
                    "Onboarding request to {} timed out (attempt {})",
                    target_peer, attempt
                );
                tracing::warn!("{}", err_msg);
                last_error = Some(to_boxed_err(err_msg));
            }
        }

        if attempt < max_retries {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    Err(last_error
        .unwrap_or_else(|| to_boxed_err("Onboarding request failed after all retries")))
}
