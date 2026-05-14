use ess_p2p_rs::storage_layer::{StorageLayer, StorageLayerConfig, store::MetadataStore, object::ObjectMetadata};
use tempfile::tempdir;
use std::sync::Arc;

#[tokio::test]
async fn test_metadata_persistence_and_sled_io() {
    // Gunakan tempdir agar tidak mengotori /data local saat testing
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("storage_metadata");
    
    // Override path via env variable atau mocking jika memungkinkan
    // Untuk keperluan test, kita instansiasi MetadataStore secara langsung
    let db = sled::open(&db_path).unwrap();
    let objects = db.open_tree("objects").unwrap();
    
    let store = MetadataStore { db: Arc::new(db), objects };
    
    let dummy_meta = ObjectMetadata {
        object_id: "obj-test-001".to_string(),
        total_chunks: 5,
        owner: "user_a".to_string(),
        content_type: "application/json".to_string(),
    };

    // Test Save
    let save_result = store.save_metadata(&dummy_meta).await;
    assert!(save_result.is_ok(), "Gagal menyimpan metadata ke sled");

    // Test Load
    let load_result = store.load_metadata("obj-test-001").await.unwrap();
    assert!(load_result.is_some(), "Metadata tidak ditemukan setelah di-save");
    
    let loaded_meta = load_result.unwrap();
    assert_eq!(loaded_meta.total_chunks, 5);
    assert_eq!(loaded_meta.owner, "user_a");
}

