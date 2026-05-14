//! Persistent metadata store for storage layer using sled.
use sled::{Db, Tree};
use std::sync::Arc;
use crate::storage_layer::object::ObjectMetadata;

const METADATA_DB_PATH: &str = "data/storage_metadata";

#[derive(Debug, Clone)]
pub struct MetadataStore {
    db: Arc<Db>,
    objects: Tree,
}

impl MetadataStore {
    /// Inisialisasi koneksi database Sled dengan penanganan error yang aman (non-panic)
    pub fn open() -> Result<Self, String> {
        let db = sled::open(METADATA_DB_PATH).map_err(|e| format!("Failed to open sled db: {}", e))?;
        let objects = db.open_tree("objects").map_err(|e| format!("Failed to open tree: {}", e))?;
        
        Ok(Self {
            db: Arc::new(db),
            objects,
        })
    }

    /// Menyimpan metadata ke disk dan memaksakan flush
    pub async fn save_metadata(&self, meta: &ObjectMetadata) -> Result<(), String> {
        let key = meta.object_id.as_bytes();
        let value = bincode::serialize(meta).map_err(|e| format!("Serialization error: {}", e))?;
        
        self.objects.insert(key, value).map_err(|e| format!("DB insert error: {}", e))?;
        self.db.flush_async().await.map_err(|e| format!("DB flush error: {}", e))?;
        
        Ok(())
    }

    /// Membaca metadata dari disk, mengembalikan None jika tidak ada
    pub async fn load_metadata(&self, object_id: &str) -> Result<Option<ObjectMetadata>, String> {
        let key = object_id.as_bytes();
        
        match self.objects.get(key).map_err(|e| format!("DB read error: {}", e))? {
            Some(bytes) => {
                let meta = bincode::deserialize(&bytes).map_err(|e| format!("Deserialization error: {}", e))?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }
}

