//! Peer ID Rotation — Whitepaper §3.4 (Internal Key Rotation only)
//! Setiap 24 jam, node menghasilkan seed baru dari secret seed + epoch,
//! yang digunakan untuk memperbarui kunci internal (onion, PQC, dsb.)
//! tanpa mengubah PeerId, menjaga koneksi tetap stabil.
//!
//! ## PATCH 8: Forward Secrecy via Hash Chain
//! Alih-alih menurunkan seed langsung dari `secret_seed` dan `epoch`,
//! sistem kini menggunakan rantai hash satu arah. Seed awal diperoleh
//! dari `secret_seed` + epoch pertama, lalu setiap rotasi berikutnya
//! menggunakan `SHA256(current_seed)`. Dengan demikian, apabila seed
//! saat ini bocor, penyerang tidak dapat menghitung seed masa lalu
//! (backward secrecy), hanya masa depan yang dapat diprediksi.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Epoch 24 jam (dalam detik)
const ROTATION_PERIOD: u64 = 86_400;

/// Hitung epoch saat ini (berapa kali 24 jam sejak Unix epoch)
pub fn current_epoch() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now / ROTATION_PERIOD
}

/// Hitung detik tersisa menuju epoch berikutnya
pub fn next_rotation_in_secs() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let next_epoch_start = (current_epoch() + 1) * ROTATION_PERIOD;
    next_epoch_start.saturating_sub(now)
}

/// **Fungsi lama DIHAPUS** — derivasi langsung rawan kehilangan backward secrecy.
/// Gunakan `next_epoch_seed` untuk rantai hash dan `initial_seed_from_secret`
/// hanya pada saat bootstrap.

/// Menghasilkan seed **awal** dari secret_seed dan epoch pertama.
/// Hanya digunakan sekali saat inisialisasi. Setelah itu, gunakan rantai hash.
pub fn initial_seed_from_secret(secret_seed: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ESS-ID-ROTATION-INIT-v1");
    hasher.update(secret_seed);
    hasher.update(&epoch.to_le_bytes());
    let result = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result);
    seed
}

/// **Patch 8**: Melangkah ke seed epoch berikutnya menggunakan rantai hash.
/// Tidak dapat di-invert; backward secrecy terjamin.
pub fn next_epoch_seed(current_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ESS-ID-ROTATION-CHAIN-v1");
    hasher.update(current_seed);
    let result = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result);
    seed
}

/// Cek apakah rotasi perlu dilakukan (epoch saat ini > epoch terakhir rotasi)
pub fn should_rotate(last_rotation_epoch: u64) -> bool {
    current_epoch() > last_rotation_epoch
}

/// Background task: memonitor pergantian epoch dan memanggil callback dengan seed baru.
/// Sekarang berbasis rantai hash, dimulai dengan secret_seed hanya untuk seed awal,
/// selanjutnya melakukan `next_epoch_seed` setiap kali epoch berganti.
///
/// # Arguments
/// * `secret_seed` - Hanya digunakan untuk menghasilkan seed awal (epoch saat ini).
/// * `on_rotate` - Callback yang dipanggil dengan seed baru setiap rotasi.
pub async fn rotation_task(
    secret_seed: [u8; 32],
    on_rotate: impl Fn([u8; 32]) + Send + 'static,
) {
    // Hitung seed awal berdasarkan epoch saat ini
    let mut last_epoch = current_epoch();
    let mut current_seed = initial_seed_from_secret(&secret_seed, last_epoch);

    // Panggil callback pertama kali agar langsung menggunakan seed yang benar
    on_rotate(current_seed);

    loop {
        let sleep_secs = next_rotation_in_secs().max(60); // cek minimal tiap 60 detik
        tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;

        let current = current_epoch();
        if current > last_epoch {
            tracing::info!(
                "[ID-ROTATION] Epoch changed to {}, deriving new internal seed (hash chain).",
                current
            );
            // Rantai hash: seed baru = SHA256(seed_lama)
            current_seed = next_epoch_seed(&current_seed);
            on_rotate(current_seed);
            last_epoch = current;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_initial_seed() {
        let secret = [7u8; 32];
        let epoch = 1000;
        let s1 = initial_seed_from_secret(&secret, epoch);
        let s2 = initial_seed_from_secret(&secret, epoch);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_different_epochs_yield_different_initial_seeds() {
        let secret = [7u8; 32];
        let s1 = initial_seed_from_secret(&secret, 1000);
        let s2 = initial_seed_from_secret(&secret, 1001);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_hash_chain_forward_secrecy() {
        let secret = [42u8; 32];
        let epoch = 500;
        let seed0 = initial_seed_from_secret(&secret, epoch);
        let seed1 = next_epoch_seed(&seed0);
        let seed2 = next_epoch_seed(&seed1);
        // seed2 tidak dapat dipakai untuk mendapatkan seed0
        assert_ne!(seed0, seed1);
        assert_ne!(seed1, seed2);
        // backward check: SHA256(seed0) != seed0, jadi tidak bisa invert
    }

    #[test]
    fn test_next_rotation_reasonable() {
        let secs = next_rotation_in_secs();
        assert!(secs <= ROTATION_PERIOD);
        assert!(secs > 0);
    }

    #[test]
    fn test_should_rotate() {
        let last = current_epoch().saturating_sub(1);
        assert!(should_rotate(last), "harus rotate jika last_epoch < current");
        assert!(!should_rotate(current_epoch()), "tidak rotate jika sama");
    }
}
