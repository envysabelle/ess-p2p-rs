use crate::authority::AuthorityManager;
use crate::crdt_state;
use crate::dashboard_bridge::DashboardBridgeInput;
use crate::ghost_runtime::GhostRuntimeHandle;
use crate::governance::engine::GovernanceEngine;
use crate::identity::EssIdentity;
use crate::network::runtime::swarm;
use crate::network::runtime::types::TelemetryEvent;
use crate::network_controller::NetworkController;
use crate::security_runtime::SecurityRuntime;
use crate::system_event::SystemEvent;
use crate::world_state::SharedWorldState;
use crate::onboarding::send_onboarding_request;
use crate::sync_policy_with_supernode;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::PublicKey as DalekPublicKey;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use log::{info, warn};
use std::env;
use std::error::Error;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;

use crate::config::NetworkConfig;
use crate::onboarding::load_or_generate_x25519_secret;
use dashmap::DashMap;
use libp2p::PeerId;
use x25519_dalek::PublicKey as X25519PublicKey;
use x25519_dalek::StaticSecret;

pub struct RuntimeContext {
    pub onion_hops: usize,
    pub onion_payload_size: usize,
    pub local_x25519_sk: StaticSecret,
    pub peer_pubkey_store: Arc<DashMap<PeerId, X25519PublicKey>>,
    pub authority_pubkey: Option<DalekPublicKey>, // [FIX L-18] Authority key for onion hop verification
}

pub async fn run_with_dashboard_and_authority(
    ess: EssIdentity,
    ghost: GhostRuntimeHandle,
    dashboard_tx: mpsc::Sender<DashboardBridgeInput>,
    authority: AuthorityManager,
    world: SharedWorldState,
    security: Arc<SecurityRuntime>,
    crdt_world: Option<Arc<tokio::sync::RwLock<crdt_state::CrdtWorldState>>>,
    network_config: NetworkConfig,
) -> Result<(), Box<dyn Error>> {
    info!("[DEBUG] Runner started...");

    let (event_tx, _event_rx) = mpsc::channel::<SystemEvent>(2048);
    info!("[DEBUG] Event channel created.");

    let controller = Arc::new(NetworkController::new(
        ess.peer_id(),
        world.clone(),
        Some(event_tx),
    ));
    info!("[DEBUG] NetworkController created, local peer_id: {}", ess.peer_id());

    if let Some(crdt) = crdt_world {
        controller.set_crdt_world(crdt);
        info!("[CRDT] World state attached to NetworkController.");
    }

    let authority_path = env::var("AUTHORITY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data/authority.bin"));

    let authority_public_key = env::var("AUTHORITY_PUBLIC_KEY_B64")
        .ok()
        .and_then(|b64| B64.decode(b64.trim()).ok())
        .and_then(|raw| DalekPublicKey::from_bytes(&raw).ok());

    controller.attach_governance(
        authority.clone(),
        ghost,
        world,
        Some(authority_path),
        authority_public_key,
    );
    info!("[DEBUG] Governance attached.");

    controller.attach_security(security.clone());
    info!("[DEBUG] Security attached.");

    let supernode_list = authority.get().supernodes.clone();
    let gov_engine = GovernanceEngine::new(supernode_list.clone(), 0.66);
    *controller.governance_engine.write().unwrap() = gov_engine;
    info!("[GOVERNANCE] Engine initialized with {} supernodes.", supernode_list.len());

    let p2p_port: u16 = env::var("P2P_PORT")
        .unwrap_or_else(|_| "5001".to_string())
        .parse()
        .unwrap_or(5001);
    info!("[DEBUG] Using P2P port: {}", p2p_port);

    let mut listen_addr = Multiaddr::empty();
    listen_addr.push(Protocol::Ip4(Ipv4Addr::new(0, 0, 0, 0)));
    listen_addr.push(Protocol::Tcp(p2p_port));

    let mut swarm = swarm::create_swarm(&ess)?;
    swarm.listen_on(listen_addr.clone())?;
    info!("[P2P] Listening on {}", listen_addr);

    if let Ok(public_ip_str) = env::var("PUBLIC_IP") {
        if let Ok(ip) = public_ip_str.parse::<Ipv4Addr>() {
            let mut ext_addr = Multiaddr::empty();
            ext_addr.push(Protocol::Ip4(ip));
            ext_addr.push(Protocol::Tcp(p2p_port));
            swarm.add_external_address(ext_addr.clone());
            info!("[P2P] External address added: {}", ext_addr);
        }
    }

    let bootstrap_addrs = crate::bootstrap_cache::load_bootstrap_addrs();
    info!("[DEBUG] Loaded {} bootstrap addresses.", bootstrap_addrs.len());
    for addr in &bootstrap_addrs {
        match swarm.dial(addr.clone()) {
            Ok(()) => info!("[P2P] Dialing bootstrap addr: {}", addr),
            Err(e) => warn!("[P2P] Failed to dial bootstrap addr {}: {}", addr, e),
        }
    }

    {
        let handle = controller.swarm_handle();
        let mut guard = handle.lock();
        *guard = Some(swarm);
    }
    info!("[DEBUG] Swarm handed over to controller, mutex released.");

    let task_controller = controller.clone();
    let task_security = security.clone();
    let task_authority = authority.clone();
    let task_bootstrap = bootstrap_addrs.clone();

    tokio::spawn(async move {
        info!("[DEBUG] Background sync task spawned, sleeping 5s before starting...");
        tokio::time::sleep(Duration::from_secs(5)).await;
        info!("[BOOT] Background sync started.");

        for addr in &task_bootstrap {
            if let Some(target) = addr.iter().find_map(|p| {
                if let Protocol::P2p(pid) = p { Some(pid) } else { None }
            }) {
                info!("[DEBUG] Sending onboarding request to {}", target);
                match send_onboarding_request(&task_controller, target).await {
                    Ok(()) => info!("[BOOT] Onboarding request sent to {}", target),
                    Err(e) => warn!("[BOOT] Onboarding failed for {}: {}", target, e),
                }
            }
        }

        info!("[DEBUG] Starting policy sync from supernode(s)...");
        sync_policy_with_supernode(
            &task_controller,
            &task_security,
            &task_authority,
            &task_bootstrap,
        )
        .await;

        info!("[BOOT] Background sync finished.");
    });

    if let Err(e) = security.verify_peer(&ess.peer_id()) {
        warn!("[BOOT] Peer verification failed (ignored): {}", e);
    } else {
        info!("[BOOT] Peer identity verified against security policy.");
    }

    if let Err(e) = security.verify_access("network_runner_boot") {
        warn!("[BOOT] Access verification failed (ignored): {}", e);
    }
    if let Err(e) = security.verify_bundle_config() {
        warn!("[BOOT] Bundle config verification failed (ignored): {}", e);
    }
    if let Err(e) = security.register_response_verifier(|_resp| Ok(())) {
        warn!("[BOOT] Registering response verifier failed (ignored): {}", e);
    }

    controller.push_ghost_signal("network_runner_boot".to_string()).await;
    info!("[DEBUG] Ghost signal pushed.");
    controller.push_ghost_sync();

    let local_x25519_sk = load_or_generate_x25519_secret()
        .map_err(|e| {
            let msg = e.to_string();
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, msg)) as Box<dyn Error>
        })?;

    let peer_pubkey_store = Arc::new(DashMap::new());

    let ctx = RuntimeContext {
        onion_hops: network_config.onion_hops,
        onion_payload_size: network_config.onion_payload_size,
        local_x25519_sk,
        peer_pubkey_store,
        authority_pubkey: authority_public_key, // [FIX L-18] pass authority key untuk verifikasi onion hop
    };

    info!("[ONION] Runtime context built: hops={}, payload_size={}",
          ctx.onion_hops, ctx.onion_payload_size);

    controller.set_onion_config(ctx.onion_hops, ctx.peer_pubkey_store.clone());

    info!("[DEBUG] Entering event loop now...");
    let (tele_tx, _tele_rx) = mpsc::channel::<TelemetryEvent>(100);
    super::events::run_event_loop(controller, security, tele_tx, dashboard_tx, ctx).await
}
