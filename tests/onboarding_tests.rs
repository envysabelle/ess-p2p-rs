use ess_p2p_rs::onboarding::verify_sn_checksum;

#[test]
fn test_valid_sn() {
    // Gunakan SN yang dihasilkan dengan secret default (pastikan ENV ter-set)
    // Contoh: ESSBB-ABCD-1234 dengan checksum yang benar
    std::env::set_var("ESS_MASTER_SECRET", "Sabelle_Syndicate_Syndicate_2026_Top_Secret");
    // SN yang dihitung dari script atau manual, di sini kita pakai dummy yang seharusnya valid
    // Karena kita tidak punya generator, kita test format dan fungsi saja.
    // Untuk mempermudah, kita test dengan SN yang memang valid dari kode yang berjalan.
    // Namun kita bisa menangkap return boolean, tidak perlu memvalidasi checksum sesungguhnya.
    // Tapi sesuai instruksi, kita perlu assert true untuk SN valid.
    // Jadi kita akan generate satu dengan fungsi yang sama, lalu verifikasi hasilnya.
    // Untuk keperluan test, kita buat valid SN menggunakan kode yang sama:
    let sn = "ESSBB-ABCD-1234"; // ini hanya contoh, belum tentu valid
    // Agar test bermakna, kita bisa menggunakan verify_sn_checksum secara langsung dengan
    // secret yang sama, dan menghitung checksum yang benar.
    // Tetapi karena kita tidak bisa menghitungnya di sini, kita lakukan pendekatan:
    // Gunakan secret yang sama, lalu pastikan fungsi memproses tanpa error.
    // Kita cukup test format dan path normal.
    // Kita bisa memanggil verify_sn_checksum dua kali, satu dengan SN yang sudah dijamin valid
    // (kita bisa meniru dari file my_profile.json jika ada), tapi itu sulit.
    // Lebih praktis: test bahwa fungsi tidak panic dan mengembalikan false untuk format salah.
    // Namun instruksi meminta test valid_sn. Saya akan implementasikan dengan menyertakan
    // SN yang di-hardcode untuk test ini (dengan secret yang sama, kita bisa hitung manual).
    // Di sini saya akan membuat sebuah SN yang pasti valid dengan menghitung checksum
    // menggunakan fungsi yang sama secara internal.
    // Karena kita sudah punya fungsi verify_sn_checksum, kita bisa membuat test yang
    // memastikan bahwa SN yang dihasilkan dengan benar akan lolos.
    // Simulasi: hitung checksum dari base "ESSBB-ABCD-1234" dengan secret, lalu gabung.
    // Karena fungsi verify_sn_checksum tidak mengekspos penghitungan, kita bisa melakukan
    // perhitungan manual di sini.
    use sha2::Sha256;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let secret = b"Sabelle_Syndicate_Syndicate_2026_Top_Secret";
    let base = "ESSBB-ABCD-1234";
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(base.as_bytes());
    let result = mac.finalize().into_bytes();
    let hash_hex = hex::encode(result);
    let checksum = &hash_hex[hash_hex.len()-4..].to_uppercase();
    let full_sn = format!("{}-{}", base, checksum);
    assert!(verify_sn_checksum(&full_sn));
}

#[test]
fn test_invalid_sn_checksum() {
    assert!(!verify_sn_checksum("ESSBB-ABCD-1234-WRONG"));
}

#[test]
fn test_wrong_format() {
    assert!(!verify_sn_checksum("ESSBB-ABCD"));
}
