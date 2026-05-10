use crate::world_state::SharedWorldState;
use std::{
    collections::VecDeque,
    env,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tokio::time::{self, MissedTickBehavior};

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn simple_fingerprint(parts: &[&str]) -> String {
    // NOT cryptographically secure – hanya untuk display/logging
    let mut acc: u128 = 0x9E3779B97F4A7C15u128;
    for part in parts {
        for &b in part.as_bytes() {
            acc ^= b as u128;
            acc = acc.wrapping_mul(0x100000001B3u128);
            acc ^= acc >> 33;
        }
    }
    format!("{acc:032x}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhostState {
    Init,
    Sleep,
    Wake,
    Beacon,
    Sync,
    Idle,
    Panic,
    Zeroized,
}

impl fmt::Display for GhostState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            GhostState::Init => "init",
            GhostState::Sleep => "sleep",
            GhostState::Wake => "wake",
            GhostState::Beacon => "beacon",
            GhostState::Sync => "sync",
            GhostState::Idle => "idle",
            GhostState::Panic => "panic",
            GhostState::Zeroized => "zeroized",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone)]
pub struct GhostConfig {
    pub beacon_interval: Duration,
    pub sync_interval: Duration,
    pub idle_to_sleep_after_cycles: usize,
    pub sync_batch_limit: usize,
    pub zeroize_on_panic: bool,
    pub auto_sleep_when_idle: bool,
}

impl Default for GhostConfig {
    fn default() -> Self {
        let cycles = env::var("GHOST_MIN_AWAKE_CYCLES")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<usize>()
            .unwrap_or(10);

        Self {
            beacon_interval: Duration::from_secs(30),
            sync_interval: Duration::from_secs(120),
            idle_to_sleep_after_cycles: cycles,
            sync_batch_limit: 32,
            zeroize_on_panic: true,
            auto_sleep_when_idle: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct GhostMetrics {
    pub connected_peers: usize,
    pub known_peers: usize,
    pub route_peers: usize,
    pub last_beacon_ts: Option<u64>,
    pub last_sync_ts: Option<u64>,
    pub last_pulse_ts: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum GhostCommand {
    Wake,
    Sleep,
    EnqueueSync(String),
    TriggerSync,
    TriggerBeacon,
    TriggerPanic(String),
    Zeroize,
    UpdateMetrics {
        connected_peers: usize,
        known_peers: usize,
        route_peers: usize,
    },
    SetTamper(bool),
    ObserveSignal(String),
}

#[derive(Debug, Clone)]
pub enum GhostEvent {
    StateChanged {
        node_id: String,
        from: GhostState,
        to: GhostState,
    },
    Beacon {
        node_id: String,
        role: String,
        state: GhostState,
        fingerprint: String,
        connected_peers: usize,
        known_peers: usize,
        route_peers: usize,
        ts: u64,
    },
    SyncBatch {
        node_id: String,
        batch: Vec<String>,
        ts: u64,
    },
    Panic {
        node_id: String,
        reason: String,
        ts: u64,
    },
    Zeroized {
        node_id: String,
        ts: u64,
    },
    Log {
        node_id: String,
        message: String,
        ts: u64,
    },
}

#[derive(Debug, Clone)]
pub struct GhostHandle {
    cmd_tx: mpsc::Sender<GhostCommand>,
}

impl GhostHandle {
    pub async fn wake(&self) -> Result<(), String> {
        self.cmd_tx.send(GhostCommand::Wake).await.map_err(|e| e.to_string())
    }
    pub async fn sleep(&self) -> Result<(), String> {
        self.cmd_tx.send(GhostCommand::Sleep).await.map_err(|e| e.to_string())
    }
    pub async fn enqueue_sync<S: Into<String>>(&self, item: S) -> Result<(), String> {
        self.cmd_tx.send(GhostCommand::EnqueueSync(item.into())).await.map_err(|e| e.to_string())
    }
    pub async fn trigger_sync(&self) -> Result<(), String> {
        self.cmd_tx.send(GhostCommand::TriggerSync).await.map_err(|e| e.to_string())
    }
    pub async fn trigger_beacon(&self) -> Result<(), String> {
        self.cmd_tx.send(GhostCommand::TriggerBeacon).await.map_err(|e| e.to_string())
    }
    pub async fn panic<S: Into<String>>(&self, reason: S) -> Result<(), String> {
        self.cmd_tx.send(GhostCommand::TriggerPanic(reason.into())).await.map_err(|e| e.to_string())
    }
    pub async fn zeroize(&self) -> Result<(), String> {
        self.cmd_tx.send(GhostCommand::Zeroize).await.map_err(|e| e.to_string())
    }
    pub async fn update_metrics(&self, connected: usize, known: usize, route: usize) -> Result<(), String> {
        self.cmd_tx.send(GhostCommand::UpdateMetrics { connected_peers: connected, known_peers: known, route_peers: route })
            .await.map_err(|e| e.to_string())
    }
    pub async fn set_tamper(&self, tamper: bool) -> Result<(), String> {
        self.cmd_tx.send(GhostCommand::SetTamper(tamper)).await.map_err(|e| e.to_string())
    }
    pub async fn observe_signal<S: Into<String>>(&self, signal: S) -> Result<(), String> {
        self.cmd_tx.send(GhostCommand::ObserveSignal(signal.into())).await.map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone)]
struct GhostObservation {
    state: GhostState,
    tamper_detected: bool,
    connected_peers: usize,
    known_peers: usize,
    route_peers: usize,
    pending_sync: usize,
    wake_cycles_left: usize,
    last_beacon_ts: Option<u64>,
    last_sync_ts: Option<u64>,
    last_pulse_ts: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GhostHealthBand {
    Init,
    Ready,
    Active,
    Degraded,
    Critical,
    Offline,
}

#[derive(Debug, Clone)]
struct GhostAssessment {
    health: GhostHealthBand,
    reasons: Vec<String>,
}

#[derive(Debug, Clone)]
enum GhostDecision {
    Beacon,
    Sync { force: bool },
    Panic(String),
    Sleep,
    Idle,
}

pub struct GhostEngine {
    node_id: String,
    role: String,
    config: GhostConfig,
    state: GhostState,
    metrics: GhostMetrics,
    pending_sync: VecDeque<String>,
    wake_cycles_left: usize,
    tamper_detected: bool,
    world_state: Option<SharedWorldState>,
}

impl GhostEngine {
    pub fn spawn_with_world_state<N: Into<String>, R: Into<String>>(
        node_id: N, role: R, config: GhostConfig, world_state: SharedWorldState,
    ) -> (GhostHandle, mpsc::Receiver<GhostEvent>) {
        Self::spawn_inner(node_id, role, config, Some(world_state))
    }

    fn spawn_inner<N: Into<String>, R: Into<String>>(
        node_id: N, role: R, config: GhostConfig, world_state: Option<SharedWorldState>,
    ) -> (GhostHandle, mpsc::Receiver<GhostEvent>) {
        tokio::spawn(async move {
            let path = std::path::PathBuf::from(".ghost_store_maintenance.tmp");
            let _ = crate::ghost_store::run_maintenance(&path);
            let _ = std::fs::remove_file(path);
        });

        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (event_tx, event_rx) = mpsc::channel(256);
        let initial_wake_cycles = config.idle_to_sleep_after_cycles;

        let engine = GhostEngine {
            node_id: node_id.into(), role: role.into(), config,
            state: GhostState::Init, metrics: GhostMetrics::default(),
            pending_sync: VecDeque::new(), wake_cycles_left: initial_wake_cycles,
            tamper_detected: false, world_state,
        };

        tokio::spawn(async move { engine.run(cmd_rx, event_tx).await });
        (GhostHandle { cmd_tx }, event_rx)
    }

    async fn run(mut self, mut cmd_rx: mpsc::Receiver<GhostCommand>, event_tx: mpsc::Sender<GhostEvent>) {
        self.transition(GhostState::Sleep, &event_tx).await;
        self.publish("ghost_boot", &event_tx).await;

        let mut beacon_tick = time::interval(self.config.beacon_interval);
        beacon_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut sync_tick = time::interval(self.config.sync_interval);
        sync_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = beacon_tick.tick() => {
                    self.metrics.last_pulse_ts = Some(unix_ts());
                    if self.state != GhostState::Sleep && self.state != GhostState::Zeroized {
                        self.run_cycle(CycleTrigger::Pulse, &event_tx).await;
                    } else {
                        self.publish("ghost_beacon_tick_sleep", &event_tx).await;
                    }
                }
                _ = sync_tick.tick() => {
                    if self.state != GhostState::Sleep && self.state != GhostState::Zeroized {
                        self.run_cycle(CycleTrigger::SyncTick, &event_tx).await;
                    } else {
                        self.publish("ghost_sync_tick_sleep", &event_tx).await;
                    }
                }
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(GhostCommand::Wake) => {
                            if self.state != GhostState::Zeroized && self.state != GhostState::Panic {
                                self.wake_cycles_left = self.config.idle_to_sleep_after_cycles;
                                self.transition(GhostState::Wake, &event_tx).await;
                                self.run_cycle(CycleTrigger::Wake, &event_tx).await;
                            }
                        }
                        Some(GhostCommand::Sleep) => {
                            if self.state != GhostState::Zeroized {
                                self.wake_cycles_left = 0;
                                self.transition(GhostState::Sleep, &event_tx).await;
                                self.publish("ghost_cmd_sleep", &event_tx).await;
                            }
                        }
                        Some(GhostCommand::EnqueueSync(item)) => {
                            if self.state != GhostState::Zeroized {
                                self.pending_sync.push_back(item);
                                let _ = event_tx.send(GhostEvent::Log {
                                    node_id: self.node_id.clone(),
                                    message: format!("sync item queued; pending={}", self.pending_sync.len()),
                                    ts: unix_ts(),
                                }).await;
                                self.publish("ghost_enqueue_sync", &event_tx).await;
                                self.run_cycle(CycleTrigger::Manual, &event_tx).await;
                            }
                        }
                        Some(GhostCommand::TriggerSync) => {
                            if self.state != GhostState::Zeroized {
                                self.run_cycle(CycleTrigger::ForceSync, &event_tx).await;
                            }
                        }
                        Some(GhostCommand::TriggerBeacon) => {
                            if self.state != GhostState::Zeroized {
                                self.run_cycle(CycleTrigger::ForceBeacon, &event_tx).await;
                            }
                        }
                        Some(GhostCommand::TriggerPanic(reason)) => {
                            if self.state != GhostState::Zeroized {
                                self.run_cycle(CycleTrigger::Panic(reason), &event_tx).await;
                            }
                        }
                        Some(GhostCommand::Zeroize) => {
                            self.perform_zeroize(&event_tx).await;
                            self.publish("ghost_cmd_zeroize", &event_tx).await;
                            break;
                        }
                        Some(GhostCommand::UpdateMetrics { connected_peers, known_peers, route_peers }) => {
                            self.metrics.connected_peers = connected_peers;
                            self.metrics.known_peers = known_peers;
                            self.metrics.route_peers = route_peers;
                            self.publish("ghost_metrics_update", &event_tx).await;
                            self.run_cycle(CycleTrigger::Manual, &event_tx).await;
                        }
                        Some(GhostCommand::SetTamper(tamper)) => {
                            self.tamper_detected = tamper;
                            self.publish(format!("ghost_tamper:{tamper}"), &event_tx).await;
                            if tamper && self.state != GhostState::Zeroized {
                                self.run_cycle(CycleTrigger::Panic("tamper_flag_set".to_string()), &event_tx).await;
                            }
                        }
                        Some(GhostCommand::ObserveSignal(signal)) => {
                            self.publish(format!("ghost_observe:{signal}"), &event_tx).await;
                            self.run_cycle(CycleTrigger::Manual, &event_tx).await;
                        }
                        None => break,
                    }
                }
            }
        }
    }

    fn observe(&self) -> GhostObservation {
        GhostObservation {
            state: self.state,
            tamper_detected: self.tamper_detected,
            connected_peers: self.metrics.connected_peers,
            known_peers: self.metrics.known_peers,
            route_peers: self.metrics.route_peers,
            pending_sync: self.pending_sync.len(),
            wake_cycles_left: self.wake_cycles_left,
            last_beacon_ts: self.metrics.last_beacon_ts,
            last_sync_ts: self.metrics.last_sync_ts,
            last_pulse_ts: self.metrics.last_pulse_ts,
        }
    }

    fn assess(&self, obs: &GhostObservation) -> GhostAssessment {
        let mut reasons = Vec::new();
        let health = if obs.state == GhostState::Zeroized {
            GhostHealthBand::Offline
        } else if obs.state == GhostState::Init {
            reasons.push("booting".to_string());
            GhostHealthBand::Init
        } else if obs.state == GhostState::Panic || obs.tamper_detected {
            reasons.push("tamper_or_panic".to_string());
            GhostHealthBand::Critical
        } else if obs.connected_peers == 0 && self.config.auto_sleep_when_idle {
            reasons.push("no_connected_peers".to_string());
            GhostHealthBand::Degraded
        } else if obs.pending_sync > 0 {
            reasons.push("pending_sync_items".to_string());
            GhostHealthBand::Active
        } else if obs.state == GhostState::Sleep {
            GhostHealthBand::Ready
        } else {
            GhostHealthBand::Active
        };
        if obs.known_peers == 0 { reasons.push("no_known_peers".to_string()); }
        if obs.route_peers == 0 { reasons.push("no_route_peers".to_string()); }
        if obs.last_pulse_ts.is_none() { reasons.push("pulse_not_started".to_string()); }
        if obs.last_beacon_ts.is_none() { reasons.push("no_beacon_yet".to_string()); }
        if obs.last_sync_ts.is_none() { reasons.push("no_sync_yet".to_string()); }
        GhostAssessment { health, reasons }
    }

    fn decide(&self, obs: &GhostObservation, assessment: &GhostAssessment, trigger: &CycleTrigger) -> Vec<GhostDecision> {
        if obs.state == GhostState::Zeroized { return vec![]; }
        match trigger {
            CycleTrigger::Panic(reason) => return vec![GhostDecision::Panic(reason.clone())],
            CycleTrigger::ForceBeacon => return vec![GhostDecision::Beacon],
            CycleTrigger::ForceSync => return vec![GhostDecision::Sync { force: true }],
            CycleTrigger::Wake => return vec![GhostDecision::Beacon],
            CycleTrigger::Manual | CycleTrigger::Pulse | CycleTrigger::SyncTick => {}
        }
        if obs.tamper_detected || assessment.health == GhostHealthBand::Critical {
            return vec![GhostDecision::Panic("tamper_detected".to_string())];
        }
        if obs.state == GhostState::Sleep { return vec![GhostDecision::Sleep]; }
        if obs.pending_sync > 0 || matches!(trigger, CycleTrigger::SyncTick) {
            return vec![GhostDecision::Sync { force: obs.pending_sync > 0 }];
        }
        if matches!(trigger, CycleTrigger::Pulse) { return vec![GhostDecision::Beacon]; }
        if self.config.auto_sleep_when_idle && obs.wake_cycles_left == 0 {
            if obs.connected_peers == 0 { return vec![GhostDecision::Sleep]; }
            else { return vec![GhostDecision::Idle]; }
        }
        vec![GhostDecision::Idle]
    }

    async fn act(&mut self, decision: GhostDecision, event_tx: &mpsc::Sender<GhostEvent>) {
        match decision {
            GhostDecision::Beacon => self.perform_beacon(event_tx).await,
            GhostDecision::Sync { force } => self.perform_sync_if_needed(force, event_tx).await,
            GhostDecision::Panic(reason) => self.perform_panic(&reason, event_tx).await,
            GhostDecision::Sleep => if self.state != GhostState::Zeroized { self.transition(GhostState::Sleep, event_tx).await; }
            GhostDecision::Idle => if self.state != GhostState::Zeroized && self.state != GhostState::Sleep { self.transition(GhostState::Idle, event_tx).await; }
        }
    }

    async fn run_cycle(&mut self, trigger: CycleTrigger, event_tx: &mpsc::Sender<GhostEvent>) {
        if self.state == GhostState::Zeroized { return; }
        let obs = self.observe();
        let assessment = self.assess(&obs);
        for reason in &assessment.reasons { self.publish(format!("ghost_assess:{reason}"), event_tx).await; }
        let decisions = self.decide(&obs, &assessment, &trigger);
        if decisions.is_empty() {
            self.publish("ghost_decision:none", event_tx).await;
            self.sync_world_state(Some("ghost_decision:none".to_string()));
            return;
        }
        for decision in decisions {
            self.publish(format!("ghost_decision:{:?}", decision_name(&decision)), event_tx).await;
            self.act(decision, event_tx).await;
        }
        self.after_active_pulse(event_tx).await;
        self.sync_world_state(Some("ghost_cycle_complete".to_string()));
    }

    fn health_label(&self) -> &'static str {
        match self.state {
            GhostState::Zeroized => "offline",
            GhostState::Panic | GhostState::Wake | GhostState::Beacon | GhostState::Sync => "active",
            GhostState::Sleep => "sleeping",
            _ => "ready",
        }
    }

    // ─────────────────────────────────────────────────────────
    // REVISI FINAL: Ghost HANYA update ghost_state & health_level
    //               Metrik koneksi DIKELOLA OLEH NETWORK
    // ─────────────────────────────────────────────────────────
    fn sync_world_state(&self, signal: Option<String>) {
        let Some(world_state) = &self.world_state else { return; };
        if let Ok(mut guard) = world_state.write() {
            // Hanya update state ghost, jangan sentuh metrik koneksi
            guard.set_ghost_state(&self.state.to_string());
            guard.set_health_level(self.health_label());

            // Biarkan network yang mengelola connected/known/route peers
            // melalui peer_registry & sync_ghost_from_registry()

            if let Some(signal) = signal {
                guard.observe_signal(signal);
            }
        }
    }

    async fn publish<S: Into<String>>(&self, message: S, event_tx: &mpsc::Sender<GhostEvent>) {
        let message = message.into();
        let _ = event_tx.send(GhostEvent::Log {
            node_id: self.node_id.clone(),
            message: message.clone(),
            ts: unix_ts(),
        }).await;

        // Hanya sinkronisasi state ghost untuk sinyal penting
        if !message.starts_with("ghost_stay_awake_with_peers")
            && !message.starts_with("ghost_observe:")
            && !message.starts_with("ghost_metrics_update")
        {
            self.sync_world_state(Some(message));
        }
    }

    async fn after_active_pulse(&mut self, event_tx: &mpsc::Sender<GhostEvent>) {
        if self.state == GhostState::Zeroized || self.state == GhostState::Panic { return; }
        if self.wake_cycles_left > 0 { self.wake_cycles_left -= 1; }
        if self.metrics.connected_peers > 0 {
            self.wake_cycles_left = self.config.idle_to_sleep_after_cycles;
            if self.state != GhostState::Idle && self.state != GhostState::Beacon {
                self.transition(GhostState::Idle, event_tx).await;
            }
            self.publish("ghost_stay_awake_with_peers", event_tx).await;
            return;
        }
        if self.wake_cycles_left == 0 && self.config.auto_sleep_when_idle {
            self.transition(GhostState::Sleep, event_tx).await;
            self.publish("ghost_auto_sleep", event_tx).await;
        }
    }

    async fn perform_beacon(&mut self, event_tx: &mpsc::Sender<GhostEvent>) {
        if self.state == GhostState::Zeroized { return; }
        self.transition(GhostState::Beacon, event_tx).await;
        let fingerprint = simple_fingerprint(&[
            &self.node_id, &self.role, &self.state.to_string(),
            &self.metrics.connected_peers.to_string(), &self.metrics.known_peers.to_string(),
            &self.metrics.route_peers.to_string(), &self.pending_sync.len().to_string(),
            &unix_ms().to_string(),
        ]);
        self.metrics.last_beacon_ts = Some(unix_ts());
        let _ = event_tx.send(GhostEvent::Beacon {
            node_id: self.node_id.clone(), role: self.role.clone(), state: self.state,
            fingerprint, connected_peers: self.metrics.connected_peers,
            known_peers: self.metrics.known_peers, route_peers: self.metrics.route_peers,
            ts: unix_ts(),
        }).await;
    }

    async fn perform_sync_if_needed(&mut self, force: bool, event_tx: &mpsc::Sender<GhostEvent>) {
        if self.state == GhostState::Zeroized || self.state == GhostState::Panic { return; }
        if self.pending_sync.is_empty() && !force { return; }
        self.transition(GhostState::Sync, event_tx).await;
        let mut batch = Vec::new();
        while batch.len() < self.config.sync_batch_limit {
            match self.pending_sync.pop_front() {
                Some(item) => batch.push(item),
                None => break,
            }
        }
        self.metrics.last_sync_ts = Some(unix_ts());
        if !batch.is_empty() || force {
            let _ = event_tx.send(GhostEvent::SyncBatch {
                node_id: self.node_id.clone(), batch, ts: unix_ts(),
            }).await;
        }
        self.transition(GhostState::Idle, event_tx).await;
    }

    async fn perform_panic(&mut self, reason: &str, event_tx: &mpsc::Sender<GhostEvent>) {
        if self.state == GhostState::Zeroized { return; }
        self.transition(GhostState::Panic, event_tx).await;
        let _ = event_tx.send(GhostEvent::Panic {
            node_id: self.node_id.clone(), reason: reason.to_string(), ts: unix_ts(),
        }).await;
        self.sync_world_state(Some(format!("ghost_panic:{reason}")));
        if self.config.zeroize_on_panic { self.perform_zeroize(event_tx).await; }
    }

    async fn perform_zeroize(&mut self, event_tx: &mpsc::Sender<GhostEvent>) {
        self.pending_sync.clear();
        self.metrics = GhostMetrics::default();
        self.wake_cycles_left = 0;
        self.tamper_detected = false;
        self.transition(GhostState::Zeroized, event_tx).await;
        let _ = event_tx.send(GhostEvent::Zeroized {
            node_id: self.node_id.clone(), ts: unix_ts(),
        }).await;
        self.sync_world_state(Some("ghost_zeroized".to_string()));
    }

    // ============================================================
    // 🔧 PATCH 5: transition guard
    async fn transition(&mut self, to: GhostState, event_tx: &mpsc::Sender<GhostEvent>) {
        let from = self.state;
        // Validasi transisi yang tidak diizinkan
        match (from, to) {
            (GhostState::Zeroized, _) => {
                tracing::warn!("Ghost: cannot leave Zeroized state");
                return; // tidak bisa keluar dari Zeroized
            }
            (GhostState::Panic, GhostState::Beacon) => {
                tracing::warn!("Ghost: Panic → Beacon not allowed");
                return; // panic tidak boleh langsung beacon
            }
            _ => {}
        }
        if from != to {
            self.state = to;
            let _ = event_tx.send(GhostEvent::StateChanged {
                node_id: self.node_id.clone(), from, to,
            }).await;
        }
    }
}

#[derive(Debug, Clone)]
enum CycleTrigger {
    Pulse, SyncTick, Wake, ForceSync, ForceBeacon, Panic(String), Manual,
}

fn decision_name(decision: &GhostDecision) -> &'static str {
    match decision {
        GhostDecision::Beacon => "beacon",
        GhostDecision::Sync { .. } => "sync",
        GhostDecision::Panic(_) => "panic",
        GhostDecision::Sleep => "sleep",
        GhostDecision::Idle => "idle",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::world_state::WorldState;
    use crate::authority::default_authority;
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    #[tokio::test]
    async fn test_ghost_panic_triggers_zeroize() {
        let world = Arc::new(RwLock::new(WorldState::new(default_authority())));
        let (handle, mut events) = GhostEngine::spawn_with_world_state(
            "test-node", "client", GhostConfig::default(), world,
        );
        handle.panic("test_panic_reason").await.expect("panic should work");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut zeroized = false;
        while let Ok(event) = events.try_recv() {
            if matches!(event, GhostEvent::Zeroized { .. }) {
                zeroized = true;
                break;
            }
        }
        assert!(zeroized, "Ghost should emit Zeroized event after panic");
    }
}
