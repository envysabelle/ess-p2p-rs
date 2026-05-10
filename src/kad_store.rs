use sled::Db;
use libp2p::kad::{Record, RecordKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use base64::Engine as _;               // <-- wajib untuk encode/decode

// ----------------------------------------------------------------
// Representasi yang bisa disimpan di sled
// ----------------------------------------------------------------
#[derive(Debug, Serialize, Deserialize)]
struct StoredRecord {
    key: String,           // hex encoded
    value: String,         // base64 encoded
    publisher: Option<String>,
    expires_secs: Option<u64>, // perkiraan UNIX timestamp
}

pub struct KadPersistence {
    db: Db,
}

impl KadPersistence {
    pub fn open(path: &str) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// Baca semua record dari sled, kembalikan sebagai Vec<Record>
    pub fn load_records(&self) -> Vec<Record> {
        let mut records = Vec::new();
        for item in self.db.iter() {
            if let Ok((_k, v)) = item {
                if let Ok(stored) = serde_json::from_slice::<StoredRecord>(&v) {
                    let key_bytes = hex::decode(&stored.key).unwrap_or_default();
                    let key = RecordKey::new(&key_bytes);

                    let value = base64::engine::general_purpose::STANDARD
                        .decode(&stored.value)
                        .unwrap_or_default();

                    let publisher = stored
                        .publisher
                        .and_then(|p| libp2p::PeerId::from_str(&p).ok());

                    // Untuk kesederhanaan, kita set expires = None saat load.
                    // Record akan tetap bisa digunakan karena MemoryStore tidak
                    // mengharuskan expires persisten.
                    let expires = None;

                    records.push(Record {
                        key,
                        value,
                        publisher,
                        expires,
                    });
                }
            }
        }
        records
    }

    /// Simpan satu record ke sled
    pub fn save_record(&self, record: &Record) {
        let key_hex = hex::encode(record.key.as_ref());
        let value_b64 =
            base64::engine::general_purpose::STANDARD.encode(&record.value);

        let publisher_str = record
            .publisher
            .as_ref()
            .map(|p| p.to_base58());

        // Konversi Option<Instant> → Option<u64> (perkiraan UNIX)
        let expires_secs = record.expires.and_then(|exp_instant| {
            let now_instant = std::time::Instant::now();
            if exp_instant > now_instant {
                let remaining = exp_instant - now_instant;
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?
                    .as_secs();
                Some(now_unix + remaining.as_secs())
            } else {
                None // expired, tidak perlu disimpan
            }
        });

        let stored = StoredRecord {
            key: key_hex.clone(),
            value: value_b64,
            publisher: publisher_str,
            expires_secs,
        };

        if let Ok(json) = serde_json::to_vec(&stored) {
            let _ = self.db.insert(key_hex.as_bytes(), json);
        }
    }

    /// Hapus record berdasarkan key
    pub fn remove_record(&self, key: &RecordKey) {
        let key_hex = hex::encode(key.as_ref());
        let _ = self.db.remove(key_hex.as_bytes());
    }
}
