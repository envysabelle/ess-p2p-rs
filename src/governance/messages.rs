use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalType {
    ActivatePeer(String),
    BanPeer(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalAnnouncement {
    pub proposal_id: String,
    pub proposer: String,
    pub proposal_type: ProposalType,
    pub target: String,
    pub supernode_count_at_creation: usize,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteMessage {
    pub proposal_id: String,
    pub voter: String,
    pub approve: bool,
    pub nonce: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationCertificate {
    pub proposal_id: String,
    pub target: String,
    pub approved: bool,
    pub signers: Vec<String>,
}
