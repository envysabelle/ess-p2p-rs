//! Shamir's Secret Sharing over GF(2⁸) — Whitepaper §5
//! Skema threshold (k, n) — k shards cukup untuk rekonstruksi dari n shards total
//!
//! GF(2⁸) menggunakan irreducible polynomial: x⁸ + x⁴ + x³ + x + 1 (0x11B)
//! — ini polynomial yang sama seperti digunakan AES.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ==========================================
// 1. GF(2⁸) ARITHMETIC
// ==========================================

/// Irreducible polynomial untuk GF(2⁸): x⁸ + x⁴ + x³ + x + 1
const POLY: u16 = 0x11B;

/// Tabel eksponensial dan logaritma GF(2⁸) untuk operasi cepat
struct GF256Tables {
    exp: [u8; 512], // exp[i] = g^i mod poly, dengan g = 0x03 sebagai generator
    log: [u8; 256], // log[x] = i sehingga g^i = x
}

impl GF256Tables {
    fn generate() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255u8 {
            exp[i as usize] = x as u8;
            log[x as usize] = i;
            x = gf256_raw_mul(x, 3);
        }
        // Duplikasi tabel exp untuk modular wrapping
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        GF256Tables { exp, log }
    }
}

// Pre-compute di startup
fn tables() -> &'static GF256Tables {
    use std::sync::OnceLock;
    static TABLES: OnceLock<GF256Tables> = OnceLock::new();
    TABLES.get_or_init(GF256Tables::generate)
}

fn gf256_raw_mul(a: u16, b: u16) -> u16 {
    let mut result: u16 = 0;
    let mut a = a;
    let mut b = b;
    while b > 0 {
        if b & 1 == 1 {
            result ^= a;
        }
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= POLY;
        }
        b >>= 1;
    }
    result & 0xFF
}

/// Penjumlahan di GF(2⁸) = XOR
pub fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Pengurangan di GF(2⁸) = XOR (sama dengan penjumlahan)
pub fn gf_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Perkalian di GF(2⁸) menggunakan tabel logaritma
pub fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    let log_a = t.log[a as usize] as usize;
    let log_b = t.log[b as usize] as usize;
    t.exp[(log_a + log_b) % 255]
}

/// Pembagian di GF(2⁸) = perkalian dengan invers.
/// **Patch 9**: Mengembalikan Result, tidak panic pada pembagian nol.
pub fn gf_div(a: u8, b: u8) -> Result<u8, SssError> {
    if b == 0 {
        return Err(SssError::DivisionByZero);
    }
    if a == 0 {
        return Ok(0);
    }
    let t = tables();
    let log_a = t.log[a as usize] as usize;
    let log_b = t.log[b as usize] as usize;
    // (log_a - log_b + 255) mod 255 — tambah 255 untuk hindari underflow
    Ok(t.exp[(log_a + 255 - log_b) % 255])
}

/// Evaluasi polynomial p(x) di titik x dalam GF(2⁸)
/// `coeffs[0]` = koefisien konstanta (secret), `coeffs[i]` = koefisien x^i
fn poly_eval(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method: p(x) = c[0] + c[1]*x + c[2]*x^2 + ...
    let mut result = 0u8;
    let mut x_pow = 1u8; // x^0 = 1
    for &coeff in coeffs {
        result = gf_add(result, gf_mul(coeff, x_pow));
        x_pow = gf_mul(x_pow, x);
    }
    result
}

// ==========================================
// 2. SHARD STRUCT
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Shard {
    /// x-koordinat (1..=255, tidak boleh 0 karena itu = secret)
    pub x: u8,
    /// y-koordinat = p(x) — satu byte per byte secret
    pub y: Vec<u8>,
}

#[derive(Debug)]
pub enum SssError {
    InvalidThreshold,
    NotEnoughShards,
    DuplicateX,
    EmptySecret,
    /// **Patch 9**: Pembagian nol di GF(256)
    DivisionByZero,
}

impl std::fmt::Display for SssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SssError::InvalidThreshold => write!(f, "k must be 2 ≤ k ≤ n ≤ 255"),
            SssError::NotEnoughShards => write!(f, "Need at least k shards"),
            SssError::DuplicateX => write!(f, "Duplicate x-coordinates in shards"),
            SssError::EmptySecret => write!(f, "Secret cannot be empty"),
            SssError::DivisionByZero => write!(f, "Division by zero in GF(256)"),
        }
    }
}
impl std::error::Error for SssError {}

// ==========================================
// 3. SPLIT & RECONSTRUCT
// ==========================================

/// Bagi `secret` menjadi `n` shard dengan threshold `k`.
/// Butuh minimal `k` shard untuk rekonstruksi.
///
/// # Contoh
/// ```
/// let key = b"my_secret_32byte_symmetric_key!!";
/// let shards = split(key, 2, 3).unwrap(); // k=2, n=3
/// // Butuh minimal 2 shard dari 3 untuk rekonstruksi
/// ```
pub fn split(secret: &[u8], k: usize, n: usize) -> Result<Vec<Shard>, SssError> {
    if k < 2 || k > n || n > 255 {
        return Err(SssError::InvalidThreshold);
    }
    if secret.is_empty() {
        return Err(SssError::EmptySecret);
    }

    // Untuk setiap byte secret, bangun polynomial derajat (k-1)
    // coeffs[0] = secret_byte, coeffs[1..k-1] = random
    let mut rng = OsRng;

    // Transpose: kita proses semua bytes secret sekaligus
    // polynomial_coeffs[byte_idx][coeff_idx]
    let num_bytes = secret.len();
    let mut all_coeffs: Vec<Vec<u8>> = Vec::with_capacity(num_bytes);

    for &secret_byte in secret {
        let mut coeffs = vec![0u8; k];
        coeffs[0] = secret_byte; // koefisien konstanta = secret
        // Random koefisien untuk x^1 sampai x^(k-1)
        let mut rand_coeffs = vec![0u8; k - 1];
        rng.fill_bytes(&mut rand_coeffs);
        coeffs[1..].copy_from_slice(&rand_coeffs);
        all_coeffs.push(coeffs);
    }

    // Evaluasi setiap polynomial di x = 1..=n
    let mut shards: Vec<Shard> = Vec::with_capacity(n);
    for i in 1..=(n as u8) {
        let y: Vec<u8> = all_coeffs
            .iter()
            .map(|coeffs| poly_eval(coeffs, i))
            .collect();
        shards.push(Shard { x: i, y });
    }

    Ok(shards)
}

/// Rekonstruksi secret dari minimal `k` shard menggunakan Lagrange interpolation.
pub fn reconstruct(shards: &[Shard]) -> Result<Vec<u8>, SssError> {
    if shards.is_empty() {
        return Err(SssError::NotEnoughShards);
    }

    // Validasi tidak ada duplikat x
    let mut xs: Vec<u8> = shards.iter().map(|s| s.x).collect();
    let orig_len = xs.len();
    xs.sort();
    xs.dedup();
    if xs.len() != orig_len {
        return Err(SssError::DuplicateX);
    }

    let num_bytes = shards[0].y.len();

    // Lagrange interpolation di x=0 (titik secret)
    // secret[byte_idx] = Σ y_i * Π (0 - x_j) / (x_i - x_j) untuk j≠i
    let mut secret = vec![0u8; num_bytes];

    for byte_idx in 0..num_bytes {
        let mut value = 0u8;

        for (i, shard_i) in shards.iter().enumerate() {
            let yi = shard_i.y[byte_idx];
            let xi = shard_i.x;

            // Hitung Lagrange basis polynomial L_i(0)
            let mut numerator = 1u8;
            let mut denominator = 1u8;

            for (j, shard_j) in shards.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = shard_j.x;
                // numerator *= (0 - xj) = xj (di GF karena -x = x)
                numerator = gf_mul(numerator, xj);
                // denominator *= (xi - xj) = xi XOR xj
                denominator = gf_mul(denominator, gf_sub(xi, xj));
            }

            // basis = numerator / denominator — gunakan gf_div yang aman dari panic
            let basis = gf_div(numerator, denominator)?;
            // tambah kontribusi shard ini
            value = gf_add(value, gf_mul(yi, basis));
        }

        secret[byte_idx] = value;
    }

    Ok(secret)
}

// ==========================================
// 4. KEY SPLITTING HELPER (PATCH 6)
// ==========================================

/// Split secret key menjadi n shards dengan threshold k, simpan ke files.
/// Output: `{output_dir}/shard_0.bin`, `shard_1.bin`, dst.
pub fn split_key_to_files(
    secret: &[u8],
    k: usize,
    n: usize,
    output_dir: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let shards = split(secret, k, n)?;
    let mut paths = Vec::new();

    for (i, shard) in shards.iter().enumerate() {
        let path = format!("{}/shard_{}.bin", output_dir, i);
        let data = serde_json::to_vec(shard)?;

        // [FIX M-14] Write shard file with 0600 permissions (owner-read/write only).
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600) // owner r/w only — no group, no world
                .open(&path)?;
            file.write_all(&data)?;
        }
        #[cfg(not(unix))]
        {
            // On non-Unix platforms, fall back to normal write and log a warning.
            tracing::warn!(
                "[SSS] Cannot set 0600 permissions on non-Unix platform — \
                 shard file {} may be readable by other users.",
                path
            );
            std::fs::write(&path, &data)?;
        }

        paths.push(path);
    }

    Ok(paths)
}

/// Rekonstruksi secret dari shard files.
/// Minimal k file harus diberikan.
pub fn reconstruct_from_files(
    paths: &[&str],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut shards = Vec::new();
    for path in paths {
        if !Path::new(path).exists() {
            return Err(format!("Shard file not found: {}", path).into());
        }
        let data = std::fs::read(path)?;
        let shard: Shard = serde_json::from_slice(&data)?;
        shards.push(shard);
    }
    let secret = reconstruct(&shards)?;
    Ok(secret)
}

// ==========================================
// 5. TESTS
// ==========================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul() {
        // 0x53 * 0xCA = 0x01 dalam GF(256) AES polynomial
        // Test dasar
        assert_eq!(gf_mul(1, 1), 1);
        assert_eq!(gf_mul(0, 123), 0);
        assert_eq!(gf_mul(2, 2), 4); // 2*2 = 4 tanpa wrap
    }

    #[test]
    fn test_gf_div_by_zero() {
        let result = gf_div(5, 0);
        assert!(result.is_err());
        match result {
            Err(SssError::DivisionByZero) => {}
            _ => panic!("Harusnya DivisionByZero"),
        }
    }

    #[test]
    fn test_split_reconstruct_k2_n3() {
        let secret = b"ESS_Master_Key_32bytes_exactly!!";
        let shards = split(secret, 2, 3).unwrap();
        assert_eq!(shards.len(), 3);

        // Test dengan 2 shard pertama
        let recovered = reconstruct(&shards[0..2]).unwrap();
        assert_eq!(&recovered, secret);

        // Test dengan 2 shard terakhir
        let recovered2 = reconstruct(&shards[1..3]).unwrap();
        assert_eq!(&recovered2, secret);

        // Test dengan semua 3 shard
        let recovered3 = reconstruct(&shards).unwrap();
        assert_eq!(&recovered3, secret);
    }

    #[test]
    fn test_split_reconstruct_k3_n5() {
        let secret = b"short";
        let shards = split(secret, 3, 5).unwrap();
        assert_eq!(shards.len(), 5);

        let combo = vec![shards[0].clone(), shards[2].clone(), shards[4].clone()];
        let recovered = reconstruct(&combo).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_insufficient_shards_returns_garbage() {
        // Dengan k-1 shard, hasil rekonstruksi BUKAN secret asli
        // Ini adalah properti information-theoretic SSS
        let secret = b"secret_key";
        let shards = split(secret, 3, 5).unwrap();
        let partial = reconstruct(&shards[0..2]).unwrap(); // hanya 2, butuh 3
        assert_ne!(&partial, secret); // harus berbeda (hampir pasti)
    }
}
