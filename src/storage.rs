use crate::ghost_store::GhostSnapshot;
use crate::world_state::{WorldState, WorldStateSnapshot};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use chrono::Utc;
use log::{debug, warn};

// ==========================================
// 1. ATOMIC JSON ENGINE
// ==========================================

pub fn save_json<T: Serialize>(path: impl AsRef<Path>, data: &T) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let bytes = serde_json::to_vec_pretty(data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let tmp_path = temp_path(path);
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        warn!("[STORAGE] Atomic rename failed: {}. Fallback to direct write.", e);
        fs::write(path, &bytes)?;
        let _ = fs::remove_file(&tmp_path);
    }
    Ok(())
}

pub fn load_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> io::Result<Option<T>> {
    let p = path.as_ref();
    if !p.exists() { return Ok(None); }
    let raw = fs::read_to_string(p)?;
    let data = serde_json::from_str(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(Some(data))
}

// ==========================================
// 2. WORLD STATE STORE (The Archivist)
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecoveryManifest {
    pub recovered_at: String,
    pub world_snapshot_path: String,
    pub ghost_snapshot_path: String,
    pub world_recovered: bool,
    pub ghost_recovered: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WorldStateStore {
    root: PathBuf,
}

impl WorldStateStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn snapshot_paths(&self) -> (PathBuf, PathBuf, PathBuf) {
        (
            self.root.join("world_state.json"),
            self.root.join("ghost_state.json"),
            self.root.join("recovery_manifest.json")
        )
    }

    pub fn persist(&self, world: &WorldState, ghost: Option<&GhostSnapshot>) -> io::Result<()> {
        let (wp, gp, _) = self.snapshot_paths();
        save_json(wp, &world.snapshot())?;
        if let Some(gs) = ghost {
            save_json(gp, gs)?;
        }
        debug!("[STORAGE] Data persisted at Revision: {}", world.revision);
        Ok(())
    }

    pub fn recover_bundle(&self, auth_fallback: crate::authority::AuthorityState) -> io::Result<RecoveryBundle> {
        let (wp, gp, mp) = self.snapshot_paths();
        let world_snap: Option<WorldStateSnapshot> = load_json(&wp)?;
        let ghost_exists = gp.exists();

        let world = match world_snap {
            Some(s) => {
                let mut state = WorldState::from_snapshot(s, auth_fallback);
                state.observe_signal("recovered_from_disk");
                state
            },
            None => WorldState::new(auth_fallback),
        };

        let manifest = RecoveryManifest {
            recovered_at: Utc::now().to_rfc3339(),
            world_snapshot_path: wp.display().to_string(),
            ghost_snapshot_path: gp.display().to_string(),
            world_recovered: wp.exists(),
            ghost_recovered: ghost_exists,
            notes: vec![format!("rev_{}", world.revision)],
        };

        let _ = save_json(mp, &manifest);

        Ok(RecoveryBundle { world })
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryBundle {
    pub world: WorldState,
}

fn temp_path(path: &Path) -> PathBuf {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".tmp-{stamp}"));
    PathBuf::from(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_save_and_load_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.json");
        let data = vec![1,2,3];
        save_json(&path, &data).unwrap();
        let loaded: Option<Vec<i32>> = load_json(&path).unwrap();
        assert_eq!(loaded, Some(data));
    }
}
