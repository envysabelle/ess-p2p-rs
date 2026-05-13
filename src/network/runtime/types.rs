//! Network runtime types and behaviours.

use std::time::Duration;

use libp2p::{
    identify,
    kad::{self, Event as KadEvent},
    ping,
    request_response,
    swarm::NetworkBehaviour,
    PeerId,
};
use serde::{Deserialize, Serialize};

use crate::{
    codec::BincodeCodec,
    config::{ConfigRequest, ConfigResponse},
    gateway::{GatewayRequest, GatewayResponse},
    message::{DirectRequest, DirectResponse},
    web::{WebRequest, WebResponse},
    storage_layer::protocol::{StorageRequest, StorageResponse},
};

// ---------- Onboarding protocol types ----------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardRequest {
    pub peer_id: String,
    pub serial_number: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub nonce: [u8; 16],
    pub timestamp: u64,
    pub x25519_pubkey: Option<String>,
}

impl OnboardRequest {
    /// Build the exact message that must be signed by the peer’s Ed25519 identity.
    /// Format: `peer_id:serial_number:nonce:timestamp:x25519_pubkey`
    /// The x25519_pubkey is included as an empty string if not present.
    pub fn build_signed_message(&self) -> String {
        let pk = self.x25519_pubkey.as_deref().unwrap_or("");
        format!(
            "{}:{}:{:?}:{}:{}",
            self.peer_id, self.serial_number, self.nonce, self.timestamp, pk
        )
    }
}

// ✅ PATCH: Struct untuk mengirim info peer dalam peer exchange
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerEntry {
    pub peer_id: String,
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardResponse {
    pub accepted: bool,
    pub reason: Option<String>,
    #[serde(default)]
    pub known_peers: Vec<PeerEntry>,
}

/// The unified network behaviour for the ESS P2P node.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
pub struct Behaviour {
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub direct: request_response::Behaviour<BincodeCodec<DirectRequest, DirectResponse>>,
    pub config: request_response::Behaviour<BincodeCodec<ConfigRequest, ConfigResponse>>,
    pub gateway: request_response::Behaviour<BincodeCodec<GatewayRequest, GatewayResponse>>,
    pub web: request_response::Behaviour<BincodeCodec<WebRequest, WebResponse>>,
    pub onboard: request_response::Behaviour<BincodeCodec<OnboardRequest, OnboardResponse>>,
    pub storage: request_response::Behaviour<BincodeCodec<StorageRequest, StorageResponse>>,
}

/// The unified event type emitted by the `Behaviour`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Event {
    Ping(()),
    Identify(identify::Event),
    Kademlia(KadEvent),
    Direct(request_response::Event<DirectRequest, DirectResponse>),
    Config(request_response::Event<ConfigRequest, ConfigResponse>),
    Gateway(request_response::Event<GatewayRequest, GatewayResponse>),
    Web(request_response::Event<WebRequest, WebResponse>),
    Onboard(request_response::Event<OnboardRequest, OnboardResponse>),
    Storage(request_response::Event<StorageRequest, StorageResponse>),
}

// ----- FROM implementations -----
impl From<ping::Event> for Event {
    fn from(_value: ping::Event) -> Self {
        Self::Ping(())
    }
}

impl From<identify::Event> for Event {
    fn from(value: identify::Event) -> Self {
        Self::Identify(value)
    }
}

impl From<KadEvent> for Event {
    fn from(value: KadEvent) -> Self {
        Self::Kademlia(value)
    }
}

impl From<request_response::Event<DirectRequest, DirectResponse>> for Event {
    fn from(value: request_response::Event<DirectRequest, DirectResponse>) -> Self {
        Self::Direct(value)
    }
}

impl From<request_response::Event<ConfigRequest, ConfigResponse>> for Event {
    fn from(value: request_response::Event<ConfigRequest, ConfigResponse>) -> Self {
        Self::Config(value)
    }
}

impl From<request_response::Event<GatewayRequest, GatewayResponse>> for Event {
    fn from(value: request_response::Event<GatewayRequest, GatewayResponse>) -> Self {
        Self::Gateway(value)
    }
}

impl From<request_response::Event<WebRequest, WebResponse>> for Event {
    fn from(value: request_response::Event<WebRequest, WebResponse>) -> Self {
        Self::Web(value)
    }
}

impl From<request_response::Event<OnboardRequest, OnboardResponse>> for Event {
    fn from(value: request_response::Event<OnboardRequest, OnboardResponse>) -> Self {
        Self::Onboard(value)
    }
}

impl From<request_response::Event<StorageRequest, StorageResponse>> for Event {
    fn from(value: request_response::Event<StorageRequest, StorageResponse>) -> Self {
        Self::Storage(value)
    }
}

// ==========================================
// 🔥 GHOST TELEMETRY PIPELINE
// ==========================================

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TelemetryEvent {
    PeerConnected(()),
    PeerDisconnected(()),
    HighLatency { peer: PeerId, latency: Duration },
    RoutingFailed(PeerId),
}
