use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use crate::governance::messages::*;
use crate::security_runtime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub proposal_id: String,
    pub proposal_type: ProposalType,
    pub target: String,
    pub created_at: u64,
    pub supernode_count: usize,
    pub votes: HashMap<String, bool>,
    pub executed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceSnapshot {
    pub proposals: Vec<Proposal>,
    pub quorum_percent: f64,
    pub bootstrap_exited: bool,
}

pub struct GovernanceEngine {
    proposals: HashMap<String, Proposal>,
    supernodes: HashSet<String>,
    quorum_ratio: f64,
    pub is_bootstrap_mode: bool,
    pub bootstrap_exited: bool,
    hmac_key: Vec<u8>, // [FIX H-07] HMAC key for on-disk protection

    // 🔴 M-03: hard deadline for bootstrap mode (default 1 hour from creation)
    pub bootstrap_deadline: u64,
}

impl GovernanceEngine {
    pub fn new(supernodes: Vec<String>, quorum_ratio: f64) -> Self {
        let mut set = HashSet::new();
        for s in supernodes {
            set.insert(s);
        }
        let bootstrap = set.len() < 2;

        // Inisialisasi deadline 1 jam dari sekarang
        let deadline = security_runtime::now_secs() + 3600;

        Self {
            proposals: HashMap::new(),
            supernodes: set,
            quorum_ratio,
            is_bootstrap_mode: bootstrap,
            bootstrap_exited: false,
            hmac_key: Vec::new(),
            bootstrap_deadline: deadline,
        }
    }

    /// [FIX H-07] Set the HMAC key (derived from keystore) to enable integrity protection
    pub fn set_hmac_key(&mut self, key: Vec<u8>) {
        self.hmac_key = key;
    }

    /// Cek apakah HMAC key sudah diset
    pub fn has_hmac_key(&self) -> bool {
        !self.hmac_key.is_empty()
    }

    pub fn supernode_count(&self) -> usize {
        self.supernodes.len()
    }

    /// 🔴 M-03: Paksa keluar dari bootstrap jika deadline terlewati
    fn evaluate_bootstrap(&mut self) {
        if self.is_bootstrap_mode && security_runtime::now_secs() > self.bootstrap_deadline {
            self.is_bootstrap_mode = false;
            self.bootstrap_exited = true;
            log::info!("[GOV] Bootstrap deadline exceeded. Switching to normal mode.");
        }
    }

    /// Helper untuk menyimpan hanya jika HMAC key sudah ada
    fn save_if_possible(&self) {
        if self.hmac_key.is_empty() {
            log::warn!("[GOV] HMAC key not set – governance state NOT persisted.");
            return;
        }
        crate::governance::store::save_governance(self, &self.hmac_key);
    }

    pub fn create_proposal(&mut self, ptype: ProposalType, target: &str) -> String {
        self.evaluate_bootstrap(); // cek deadline sebelum buat proposal

        let id = format!(
            "{:?}-{}-{}",
            ptype,
            target,
            uuid::Uuid::new_v4()
        );

        if self.is_bootstrap_mode && !self.bootstrap_exited {
            self.proposals.insert(
                id.clone(),
                Proposal {
                    proposal_id: id.clone(),
                    proposal_type: ptype,
                    target: target.to_string(),
                    created_at: security_runtime::now_secs(),
                    supernode_count: 1,
                    votes: HashMap::new(),
                    executed: true,
                },
            );
            self.save_if_possible();
            return id;
        }

        let supernode_count = self.supernodes.len();
        self.proposals.insert(
            id.clone(),
            Proposal {
                proposal_id: id.clone(),
                proposal_type: ptype,
                target: target.to_string(),
                created_at: security_runtime::now_secs(),
                supernode_count,
                votes: HashMap::new(),
                executed: false,
            },
        );
        self.save_if_possible();
        id
    }

    pub fn record_vote(&mut self, proposal_id: &str, voter: &str, approve: bool) -> Result<(), &str> {
        self.evaluate_bootstrap(); // cek deadline sebelum merekam vote

        let prop = self.proposals.get_mut(proposal_id).ok_or("proposal not found")?;
        if prop.executed {
            return Err("already executed");
        }
        if !self.supernodes.contains(voter) {
            return Err("voter is not a supernode");
        }
        prop.votes.insert(voter.to_string(), approve);
        self.save_if_possible();
        Ok(())
    }

    pub fn check_quorum(&self, proposal_id: &str, timeout_secs: u64) -> Option<bool> {
        // Cek quorum tidak mengubah state, jadi tidak perlu evaluate_bootstrap di sini
        let prop = self.proposals.get(proposal_id)?;
        if prop.executed {
            return None;
        }

        let total = prop.supernode_count as f64;
        if total == 0.0 {
            return Some(false);
        }

        let yes = prop.votes.values().filter(|&&v| v).count() as f64;
        let no = prop.votes.len() as f64 - yes;

        if yes / total >= self.quorum_ratio {
            return Some(true);
        }
        if no / total >= self.quorum_ratio {
            return Some(false);
        }

        if total == 2.0 && prop.votes.len() == 1 {
            let elapsed = security_runtime::now_secs() - prop.created_at;
            if elapsed > timeout_secs {
                return Some(true);
            }
        }

        None
    }

    pub fn mark_executed(&mut self, proposal_id: &str) {
        self.evaluate_bootstrap(); // meskipun hanya menandai eksekusi, aman untuk dicek
        if let Some(p) = self.proposals.get_mut(proposal_id) {
            p.executed = true;
            self.save_if_possible();
        }
    }

    pub fn get_proposal(&self, proposal_id: &str) -> Option<&Proposal> {
        self.proposals.get(proposal_id)
    }

    pub fn update_supernodes(&mut self, new_list: Vec<String>) {
        self.evaluate_bootstrap(); // cek deadline sebelum update daftar supernode

        let old_len = self.supernodes.len();
        self.supernodes.clear();
        for s in new_list {
            self.supernodes.insert(s);
        }
        let count = self.supernodes.len();

        // Jika jumlah supernode sudah memenuhi syarat, atau deadline sudah lewat (yang akan diubah oleh evaluate_bootstrap),
        // kita pastikan bootstrap mode diatur sesuai kondisi terbaru.
        if count >= 2 && old_len < 2 {
            self.is_bootstrap_mode = false;
            self.bootstrap_exited = true;
        } else if count < 2 && !self.bootstrap_exited {
            self.is_bootstrap_mode = true;
        } else {
            self.is_bootstrap_mode = false;
        }
    }

    pub fn snapshot(&self) -> GovernanceSnapshot {
        GovernanceSnapshot {
            proposals: self.proposals.values().cloned().collect(),
            quorum_percent: self.quorum_ratio,
            bootstrap_exited: self.bootstrap_exited,
        }
    }

    pub fn restore_from_snapshot(&mut self, snapshot: GovernanceSnapshot) {
        // restore biasanya dilakukan saat startup, deadline mungkin perlu di-reset?
        // Tapi biarkan saja, tidak perlu evaluate_bootstrap.
        for p in snapshot.proposals {
            self.proposals.insert(p.proposal_id.clone(), p);
        }
        self.quorum_ratio = snapshot.quorum_percent;
        self.bootstrap_exited = snapshot.bootstrap_exited;
    }
}
