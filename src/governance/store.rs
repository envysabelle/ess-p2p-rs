use crate::governance::engine::{GovernanceEngine, GovernanceSnapshot};
use hmac::{Hmac, Mac};
use log::{info, warn};
use sha2::Sha256;
use std::path::Path;
use subtle::ConstantTimeEq;

const GOV_FILE: &str = "data/governance.json";
const GOV_HMAC_DOMAIN: &[u8] = b"ESS-GOVERNANCE-HMAC-v1";

type HmacSha256 = Hmac<Sha256>;

/// [FIX H-07] Compute HMAC-SHA256 over governance JSON using a node-derived key.
/// The key should come from the keystore — caller supplies it.
fn compute_governance_hmac(json: &str, hmac_key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .expect("HMAC accepts any key length");
    mac.update(GOV_HMAC_DOMAIN);
    mac.update(json.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn save_governance(engine: &GovernanceEngine, hmac_key: &[u8]) {
    // Patch 2 (M-04): Wajib punya HMAC key sebelum menulis ke disk
    if hmac_key.is_empty() {
        warn!("[GOVERNANCE] HMAC key not set – governance will NOT be saved to disk for security.");
        return;
    }

    let snapshot = engine.snapshot();
    match serde_json::to_string_pretty(&snapshot) {
        Ok(json) => {
            // [FIX H-07] Compute HMAC and store alongside data
            let mac = compute_governance_hmac(&json, hmac_key);
            let protected = serde_json::json!({ "data": json, "hmac": mac });
            let protected_str = serde_json::to_string(&protected)
                .expect("serialization of protected governance cannot fail");
            if let Err(e) = std::fs::write(GOV_FILE, protected_str) {
                warn!("[GOVERNANCE] Failed to save to {}: {}", GOV_FILE, e);
            } else {
                info!("[GOVERNANCE] State saved and HMAC-protected to {}", GOV_FILE);
            }
        }
        Err(e) => warn!("[GOVERNANCE] Serialize error: {}", e),
    }
}

pub fn load_governance(hmac_key: &[u8]) -> Option<GovernanceEngine> {
    if !Path::new(GOV_FILE).exists() {
        return None;
    }
    let content = std::fs::read_to_string(GOV_FILE).ok()?;

    // [FIX H-07] Parse protected envelope and verify HMAC before trusting data
    let envelope: serde_json::Value = serde_json::from_str(&content).ok()?;
    let stored_data = envelope.get("data")?.as_str()?;
    let stored_mac = envelope.get("hmac")?.as_str()?;

    let expected_mac = compute_governance_hmac(stored_data, hmac_key);

    // Constant-time comparison to prevent timing oracle
    let mac_valid: bool = expected_mac.as_bytes().ct_eq(stored_mac.as_bytes()).into();
    if !mac_valid {
        warn!(
            "[GOVERNANCE] CRITICAL: governance file HMAC verification FAILED — \
             file may have been tampered with. Starting with fresh governance state."
        );
        return None;
    }

    let snapshot: GovernanceSnapshot = serde_json::from_str(stored_data).ok()?;
    let mut engine = GovernanceEngine::new(vec![], 0.66);
    engine.restore_from_snapshot(snapshot);
    info!("[GOVERNANCE] State loaded and HMAC verified from {}", GOV_FILE);
    Some(engine)
}
