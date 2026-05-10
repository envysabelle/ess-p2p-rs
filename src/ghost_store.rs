use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhostSnapshot {
    pub node_id: String,
    pub role: String,
    pub policy_version: u64,
    pub connected_peers: usize,
    pub known_peers: usize,
    pub route_peers: usize,
    pub trusted_peers: usize,
    pub last_beacon_ts: Option<u64>,
    pub last_sync_ts: Option<u64>,
    pub last_failure_reason: Option<String>,
    pub health_history: Vec<String>,
    pub decision_history: Vec<String>,
    pub anomalies: Vec<String>,
}

pub struct GhostStore {
    path: PathBuf,
}

impl GhostStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self, snapshot: &GhostSnapshot) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = fs::File::create(&self.path)?;
        writeln!(file, "node_id={}", snapshot.node_id)?;
        writeln!(file, "role={}", snapshot.role)?;
        writeln!(file, "policy_version={}", snapshot.policy_version)?;
        writeln!(file, "connected_peers={}", snapshot.connected_peers)?;
        writeln!(file, "known_peers={}", snapshot.known_peers)?;
        writeln!(file, "route_peers={}", snapshot.route_peers)?;
        writeln!(file, "trusted_peers={}", snapshot.trusted_peers)?;
        writeln!(file, "last_beacon_ts={}", snapshot.last_beacon_ts.map(|v| v.to_string()).unwrap_or_default())?;
        writeln!(file, "last_sync_ts={}", snapshot.last_sync_ts.map(|v| v.to_string()).unwrap_or_default())?;
        writeln!(file, "last_failure_reason={}", snapshot.last_failure_reason.clone().unwrap_or_default())?;
        for item in &snapshot.health_history {
            writeln!(file, "health_history={}", escape_line(item))?;
        }
        for item in &snapshot.decision_history {
            writeln!(file, "decision_history={}", escape_line(item))?;
        }
        for item in &snapshot.anomalies {
            writeln!(file, "anomaly={}", escape_line(item))?;
        }
        Ok(())
    }

    pub fn load(&self) -> io::Result<Option<GhostSnapshot>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let raw = fs::read_to_string(&self.path)?;
        let mut snapshot = GhostSnapshot::default();

        for line in raw.lines() {
            let mut parts = line.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let value = parts.next().unwrap_or("").trim();

            match key {
                "node_id" => snapshot.node_id = value.to_string(),
                "role" => snapshot.role = value.to_string(),
                "policy_version" => snapshot.policy_version = value.parse().unwrap_or(0),
                "connected_peers" => snapshot.connected_peers = value.parse().unwrap_or(0),
                "known_peers" => snapshot.known_peers = value.parse().unwrap_or(0),
                "route_peers" => snapshot.route_peers = value.parse().unwrap_or(0),
                "trusted_peers" => snapshot.trusted_peers = value.parse().unwrap_or(0),
                "last_beacon_ts" => {
                    snapshot.last_beacon_ts = if value.is_empty() { None } else { value.parse().ok() }
                }
                "last_sync_ts" => {
                    snapshot.last_sync_ts = if value.is_empty() { None } else { value.parse().ok() }
                }
                "last_failure_reason" => {
                    snapshot.last_failure_reason = if value.is_empty() {
                        None
                    } else {
                        Some(unescape_line(value))
                    }
                }
                "health_history" => snapshot.health_history.push(unescape_line(value)),
                "decision_history" => snapshot.decision_history.push(unescape_line(value)),
                "anomaly" => snapshot.anomalies.push(unescape_line(value)),
                _ => {}
            }
        }

        Ok(Some(snapshot))
    }

    pub fn append_health(&self, snapshot: &GhostSnapshot, line: impl Into<String>) -> io::Result<()> {
        let mut updated = snapshot.clone();
        updated.health_history.push(line.into());
        self.save(&updated)
    }

    pub fn append_decision(&self, snapshot: &GhostSnapshot, line: impl Into<String>) -> io::Result<()> {
        let mut updated = snapshot.clone();
        updated.decision_history.push(line.into());
        self.save(&updated)
    }

    pub fn append_anomaly(&self, snapshot: &GhostSnapshot, line: impl Into<String>) -> io::Result<()> {
        let mut updated = snapshot.clone();
        updated.anomalies.push(line.into());
        self.save(&updated)
    }

    pub fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

fn escape_line(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n").replace('=', "\\=")
}

fn unescape_line(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('=') => out.push('='),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }

    out
}

pub fn run_maintenance(db_path: &PathBuf) -> io::Result<()> {
    let store = GhostStore::new(db_path);
    let _ = store.path();
    
    let current_ts = GhostStore::now_ts();
    
    let snapshot = store.load()?.unwrap_or_default();
    
    let mut new_snapshot = snapshot.clone();
    new_snapshot.last_beacon_ts = Some(current_ts);
    
    store.save(&new_snapshot)?;
    store.append_health(&new_snapshot, "maintenance_health_check")?;
    store.append_decision(&new_snapshot, "maintenance_decision_check")?;
    store.append_anomaly(&new_snapshot, "maintenance_anomaly_check")?;
    
    Ok(())
}

