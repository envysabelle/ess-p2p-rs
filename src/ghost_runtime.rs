use crate::ghost::GhostHandle;
use crate::ghost_health::GhostHealthSnapshot;
use crate::ghost_policy::{GhostDecision, GhostPolicy};
use crate::world_state::SharedWorldState;
use crate::system_event::SystemEventKind;

use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::{self, MissedTickBehavior};
use log::{info, warn, error, debug};

pub trait GhostActionSink: Send + Sync {
    fn drop_peer(&self, peer_id: &str);
    fn limit_peer(&self, peer_id: &str);

    fn quarantine_peer(&self, peer_id: &str);
    fn reroute_traffic(&self, peer_id: &str, alt_nodes: &[String]);
    fn adjust_reputation_score(&self, peer_id: &str, delta: f64);
}

#[derive(Debug, Clone)]
pub struct GhostRuntimeConfig {
    pub policy: GhostPolicy,
    pub scheduler_tick: Duration,
    pub sync_every_ticks: u64,
    pub sleep_after_idle_ticks: u64,
    pub wake_on_activity: bool,
    pub enable_scheduler: bool,
}

impl Default for GhostRuntimeConfig {
    fn default() -> Self {
        Self {
            policy: GhostPolicy::default(),
            scheduler_tick: Duration::from_secs(10),
            sync_every_ticks: 6,
            sleep_after_idle_ticks: 6,
            wake_on_activity: true,
            enable_scheduler: true,
        }
    }
}

#[derive(Debug, Default)]
struct GhostSchedulerState {
    tick_count: u64,
    idle_ticks: u64,
    last_event: Option<String>,
    last_assessment: Option<crate::ghost_health::GhostHealthAssessment>,
}

#[derive(Clone)]
pub struct GhostRuntimeHandle {
    ghost: GhostHandle,
    node_id: String,
    role: String,
    world: SharedWorldState,
    policy: Arc<RwLock<GhostPolicy>>,
    action_sink: Arc<RwLock<Option<Arc<dyn GhostActionSink>>>>,
    scheduler: Arc<RwLock<GhostSchedulerState>>,
    config: GhostRuntimeConfig,
}

impl std::fmt::Debug for GhostRuntimeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GhostRuntimeHandle")
            .field("ghost", &self.ghost)
            .field("node_id", &self.node_id)
            .field("role", &self.role)
            .field("world", &self.world)
            .field("policy", &self.policy)
            .field("scheduler", &self.scheduler)
            .field("config", &self.config)
            .finish()
    }
}

impl GhostRuntimeHandle {
    pub fn set_action_sink(&self, sink: Arc<dyn GhostActionSink>) {
        if let Ok(mut guard) = self.action_sink.write() { *guard = Some(sink); }
    }

    fn set_world_state(&self, state: &str) {
        if let Ok(mut w) = self.world.write() { w.set_ghost_state(state); }
    }

    pub fn apply_decision(&self, decision: GhostDecision) {
        if decision == GhostDecision::Noop { return; }
        info!("[GHOST-ACT] Executing Autonomous Decision: {:?}", decision);
        let sink = self.action_sink.read().ok().and_then(|g| g.clone());

        match decision {
            GhostDecision::Wake => {
                self.set_world_state("waking");
                let g = self.ghost.clone();
                tokio::spawn(async move { let _ = g.wake().await; });
            }
            GhostDecision::Sleep => {
                self.set_world_state("sleeping");
                let g = self.ghost.clone();
                tokio::spawn(async move { let _ = g.sleep().await; });
            }
            GhostDecision::Beacon => {
                let g = self.ghost.clone();
                tokio::spawn(async move { let _ = g.trigger_beacon().await; });
            }
            GhostDecision::Sync => {
                let g = self.ghost.clone();
                tokio::spawn(async move { let _ = g.trigger_sync().await; });
            }
            GhostDecision::Panic => {
                error!("[CRITICAL] AUTONOMOUS PANIC triggered by Ghost Engine!");
                self.set_world_state("panic");
                let g = self.ghost.clone();
                tokio::spawn(async move { let _ = g.panic("autonomous_panic").await; });
            }
            GhostDecision::Degrade => {
                warn!("[GHOST] Resource protection: Entering Degraded mode.");
                self.set_world_state("degraded");
            }
            GhostDecision::DropPeer(peer_id) => {
                warn!("[GHOST] Dropping peer: {}", peer_id);
                if let Some(s) = sink { s.drop_peer(&peer_id); }
            }
            GhostDecision::Throttle(peer_id) => {
                warn!("[GHOST] Throttling peer: {}", peer_id);
                if let Some(s) = sink { s.limit_peer(&peer_id); }
            }
            GhostDecision::IsolatePeer(peer_id) => {
                warn!("[GHOST] Quarantining peer: {}", peer_id);
                if let Some(s) = sink {
                    s.quarantine_peer(&peer_id);
                }
            }
            GhostDecision::Retry(peer_id) => {
                let g = self.ghost.clone();
                tokio::spawn(async move { let _ = g.enqueue_sync(format!("retry:{}", peer_id)).await; });
            }
            GhostDecision::Reroute(peer_id) => {
                if let Some(s) = sink {
                    let alt_nodes: Vec<String> = vec![];
                    s.reroute_traffic(&peer_id, &alt_nodes);
                }
                let g = self.ghost.clone();
                tokio::spawn(async move {
                    let _ = g.enqueue_sync(format!("reroute:{}", peer_id)).await;
                    let _ = g.trigger_beacon().await;
                });
            }
            GhostDecision::AdjustReputation(peer_id, delta) => {
                if let Some(s) = sink {
                    s.adjust_reputation_score(&peer_id, delta);
                }
            }
            GhostDecision::Noop => {}
        }
    }

    pub async fn publish_event(&self, kind: &SystemEventKind) -> Result<(), ()> {
        let decision = {
            let policy = self.policy.read().unwrap();
            policy.evaluate_event(kind)
        };

        if decision != GhostDecision::Noop {
            self.apply_decision(decision);
        }

        if self.config.wake_on_activity {
            if let SystemEventKind::PeerConnected { .. } = kind {
                debug!("[GHOST-AUTO] Activity detected, waking system.");
                self.apply_decision(GhostDecision::Wake);
            }
        }

        let _ = self.observe_signal(format!("{:?}", kind)).await;
        Ok(())
    }

    pub async fn assess(&self) -> Result<(), ()> {
        self.set_world_state("assessing");
        let snapshot = self.build_real_snapshot();

        {
            if let Ok(w) = self.world.read() {
                let policy = self.policy.read().unwrap();
                for (peer_id, state) in &w.peer_registry {
                    let decision = policy.evaluate_reputation(peer_id, state.reputation.score);
                    if decision != GhostDecision::Noop { self.apply_decision(decision); }
                }
            }
        }

        let assessment = crate::ghost_health::assess(&snapshot, crate::ghost::GhostState::Idle);
        let _ = self.observe_signal(format!("ghost:assess:{}", assessment.reason)).await;

        if let Ok(mut sched) = self.scheduler.write() {
            sched.last_event = Some(assessment.reason.clone());
            sched.last_assessment = Some(assessment.clone());
        }
        Ok(())
    }

    async fn scheduler_tick(&self) {
        let snapshot = self.build_real_snapshot();
        let (tick_count, idle_ticks) = {
            let mut guard = match self.scheduler.write() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.tick_count = guard.tick_count.saturating_add(1);
            if snapshot.connected_peers == 0 { guard.idle_ticks += 1; } else { guard.idle_ticks = 0; }
            (guard.tick_count, guard.idle_ticks)
        };

        if tick_count % self.config.sync_every_ticks == 0 {
            let _ = self.trigger_sync().await;
        }

        if idle_ticks >= self.config.sleep_after_idle_ticks && snapshot.connected_peers == 0 {
             self.apply_decision(GhostDecision::Sleep);
        }

        let load_decision = {
            let policy = self.policy.read().unwrap();
            policy.evaluate_load(snapshot.connected_peers)
        };
        self.apply_decision(load_decision);

        if let Ok(decision) = self.decide().await {
            debug!("[GHOST-TICK] Autonomous decision: {:?}", decision);
            self.apply_decision(decision);
        } else {
            warn!("[GHOST-TICK] Failed to get decision");
        }

        info!("[GHOST-TICK] #{} | Connected Peers: {}", tick_count, snapshot.connected_peers);

        let _ = self.assess().await;
        let _ = self.act().await;
        let _ = self.update_metrics(snapshot.connected_peers, snapshot.known_peers, snapshot.route_peers).await;
    }

    pub async fn decide(&self) -> Result<GhostDecision, ()> {
        let assessment = self.scheduler.read().ok().and_then(|s| s.last_assessment.clone());
        let policy = self.policy.read().unwrap().clone();
        if let Some(assess) = assessment {
            Ok(crate::ghost_policy::decide(&policy, crate::ghost::GhostState::Idle, &assess))
        } else {
            Ok(GhostDecision::Noop)
        }
    }

    pub async fn act(&self) -> Result<(), ()> {
        let decision = self.decide().await?;
        self.apply_decision(decision);
        self.set_world_state("ready");
        Ok(())
    }

    fn build_real_snapshot(&self) -> GhostHealthSnapshot {
        let snap = self.world.read().ok().map(|w| w.snapshot());
        if let Some(s) = snap {
            GhostHealthSnapshot {
                node_id: self.node_id.clone(),
                role: self.role.clone(),
                connected_peers: s.connected_peers,
                known_peers: s.known_peers,
                route_peers: s.route_peers,
                trusted_peers: s.trusted_peers,
                bootstrap_ok: s.trusted_peers > 0,
                gateway_ok: true, web_ok: true, config_ok: true,
                tamper_detected: false,
                last_failure_reason: s.last_signal,
            }
        } else { GhostHealthSnapshot::default() }
    }

    pub async fn tick(&self) -> Result<(), ()> {
        self.scheduler_tick().await;
        Ok(())
    }

    pub async fn health(&self, snapshot: GhostHealthSnapshot) -> Result<(), ()> {
        self.observe_signal(format!("health_check:peers={}", snapshot.connected_peers)).await
    }

    // ✅ PERBAIKAN: sinkronkan registry ke ghost agar metrik akurat
    pub async fn update_metrics(&self, c: usize, k: usize, r: usize) -> Result<(), ()> {
        if let Ok(mut w) = self.world.write() {
            w.update_peers(c, k, r, r);
            w.sync_ghost_from_registry();   // <-- tambahan ini
        }
        self.ghost.update_metrics(c, k, r).await.map_err(|_| ())
    }

    pub async fn observe_signal<S: Into<String>>(&self, signal: S) -> Result<(), ()> {
        self.ghost.observe_signal(signal.into()).await.map_err(|_| ())
    }

    pub async fn set_tamper(&self, tamper: bool) -> Result<(), ()> {
        self.ghost.set_tamper(tamper).await.map_err(|_| ())
    }

    pub async fn trigger_sync(&self) -> Result<(), ()> {
        self.apply_decision(GhostDecision::Sync);
        Ok(())
    }

    pub async fn trigger_beacon(&self) -> Result<(), ()> {
        self.apply_decision(GhostDecision::Beacon);
        Ok(())
    }

    pub async fn zeroize(&self) -> Result<(), ()> {
        self.set_world_state("zeroized");
        self.ghost.zeroize().await.map_err(|_| ())
    }

    pub async fn sleep(&self) -> Result<(), ()> {
        self.apply_decision(GhostDecision::Sleep);
        Ok(())
    }

    pub async fn wake(&self) -> Result<(), ()> {
        self.apply_decision(GhostDecision::Wake);
        Ok(())
    }

    pub async fn policy_update(&self, policy: GhostPolicy) -> Result<(), ()> {
        if let Ok(mut guard) = self.policy.write() { *guard = policy; }
        let _ = self.assess().await;
        Ok(())
    }
}

pub fn spawn_ghost_runtime(
    ghost: GhostHandle, node_id: String, role: String,
    config: GhostRuntimeConfig, world: SharedWorldState,
) -> GhostRuntimeHandle {
    let handle = GhostRuntimeHandle {
        ghost, node_id, role, world,
        policy: Arc::new(RwLock::new(config.policy.clone())),
        action_sink: Arc::new(RwLock::new(None)),
        scheduler: Arc::new(RwLock::new(GhostSchedulerState::default())),
        config: config.clone(),
    };

    if config.enable_scheduler {
        let h = handle.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(config.scheduler_tick);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                h.scheduler_tick().await;
            }
        });
    }
    handle
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::{GhostEngine, GhostConfig};
    use crate::ghost_policy::{GhostDecision, GhostPolicy};
    use crate::world_state::WorldState;
    use crate::authority::default_authority;
    use std::sync::Mutex;
    use std::collections::VecDeque;

    struct MockSink {
        actions: Mutex<VecDeque<String>>,
    }

    impl MockSink {
        fn new() -> Self { Self { actions: Mutex::new(VecDeque::new()) } }
        fn pop(&self) -> Option<String> { self.actions.lock().unwrap().pop_front() }
    }

    impl GhostActionSink for MockSink {
        fn drop_peer(&self, id: &str) { self.actions.lock().unwrap().push_back(format!("drop:{}", id)); }
        fn limit_peer(&self, id: &str) { self.actions.lock().unwrap().push_back(format!("limit:{}", id)); }
        fn quarantine_peer(&self, id: &str) { self.actions.lock().unwrap().push_back(format!("quarantine:{}", id)); }
        fn reroute_traffic(&self, id: &str, _alts: &[String]) { self.actions.lock().unwrap().push_back(format!("reroute:{}", id)); }
        fn adjust_reputation_score(&self, id: &str, delta: f64) { self.actions.lock().unwrap().push_back(format!("adjust:{} {}", id, delta)); }
    }

    fn make_handle() -> (GhostRuntimeHandle, Arc<MockSink>) {
        let world = Arc::new(RwLock::new(WorldState::new(default_authority())));
        let (ghost_handle, _) = GhostEngine::spawn_with_world_state("node", "client", GhostConfig::default(), world.clone());
        let handle = GhostRuntimeHandle {
            ghost: ghost_handle,
            node_id: "node".into(),
            role: "client".into(),
            world,
            policy: Arc::new(RwLock::new(GhostPolicy::default())),
            action_sink: Arc::new(RwLock::new(None)),
            scheduler: Arc::new(RwLock::new(GhostSchedulerState::default())),
            config: GhostRuntimeConfig::default(),
        };
        let mock = Arc::new(MockSink::new());
        handle.set_action_sink(mock.clone());
        (handle, mock)
    }

    #[tokio::test]
    async fn test_apply_decision_drop_peer() {
        let (handle, mock) = make_handle();
        handle.apply_decision(GhostDecision::DropPeer("peer123".into()));
        assert_eq!(mock.pop(), Some("drop:peer123".into()));
    }

    #[tokio::test]
    async fn test_apply_decision_quarantine() {
        let (handle, mock) = make_handle();
        handle.apply_decision(GhostDecision::IsolatePeer("bad".into()));
        assert_eq!(mock.pop(), Some("quarantine:bad".into()));
    }

    #[tokio::test]
    async fn test_apply_decision_adjust_reputation() {
        let (handle, mock) = make_handle();
        handle.apply_decision(GhostDecision::AdjustReputation("peer".into(), 0.1));
        assert_eq!(mock.pop(), Some("adjust:peer 0.1".into()));
    }
}
