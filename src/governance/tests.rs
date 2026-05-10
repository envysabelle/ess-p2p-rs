#[cfg(test)]
mod governance_tests {
    use crate::governance::engine::{GovernanceEngine, ProposalType};

    fn make_engine() -> GovernanceEngine {
        GovernanceEngine::new(
            vec!["sn1".into(), "sn2".into()],
            0.66,
        )
    }

    #[test]
    fn test_bootstrap_auto_execute() {
        // Hanya 1 SN → bootstrap mode, proposal auto‑executed
        let mut engine = GovernanceEngine::new(vec!["sn1".into()], 0.66);
        assert!(engine.is_bootstrap_mode);
        let id = engine.create_proposal(ProposalType::ActivatePeer("peerA".into()), "peerA");
        let prop = engine.get_proposal(&id).unwrap();
        assert!(prop.executed, "Proposal in bootstrap must be auto-executed");
    }

    #[test]
    fn test_quorum_approval() {
        let mut engine = make_engine();
        let id = engine.create_proposal(ProposalType::ActivatePeer("peerB".into()), "peerB");
        // kedua supernode vote setuju
        engine.record_vote(&id, "sn1", true).unwrap();
        engine.record_vote(&id, "sn2", true).unwrap();
        assert!(engine.check_quorum(&id, 60).unwrap(), "Quorum should be reached");
    }

    #[test]
    fn test_quorum_rejection() {
        let mut engine = make_engine();
        let id = engine.create_proposal(ProposalType::ActivatePeer("peerC".into()), "peerC");
        engine.record_vote(&id, "sn1", false).unwrap();
        engine.record_vote(&id, "sn2", false).unwrap();
        assert!(!engine.check_quorum(&id, 60).unwrap(), "Quorum should reject when all vote no");
    }

    #[test]
    fn test_mark_executed() {
        let mut engine = make_engine();
        let id = engine.create_proposal(ProposalType::ActivatePeer("peerD".into()), "peerD");
        engine.mark_executed(&id);
        assert!(engine.get_proposal(&id).unwrap().executed);
    }
}
