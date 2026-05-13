use std::env;
use std::error::Error;
use std::time::Duration;

use libp2p::{
    identify,
    kad::{Behaviour as Kademlia, store::MemoryStore},
    noise,
    ping,
    request_response::{self, ProtocolSupport},
    tcp,
    yamux,
    PeerId,
    StreamProtocol,
};
use libp2p::kad::store::RecordStore;

use crate::codec::BincodeCodec;
use crate::identity::EssIdentity;
use crate::kad_store::KadPersistence;

use crate::storage_layer::protocol::{StorageRequest, StorageResponse};
use super::types::{Behaviour, OnboardRequest, OnboardResponse};
use super::{CONFIG_PROTOCOL, DIRECT_PROTOCOL, GATEWAY_PROTOCOL, PROTOCOL_VERSION, WEB_PROTOCOL};

const ONBOARD_PROTOCOL: &str = "/syndicate-onboard/1.0.0";

pub type RuntimeSwarm = libp2p::Swarm<Behaviour>;

pub fn create_swarm(ess: &EssIdentity) -> Result<RuntimeSwarm, Box<dyn Error>> {
    let swarm = libp2p::SwarmBuilder::with_existing_identity(ess.keypair().clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let peer_id = PeerId::from(key.public());

            let store_path = env::var("KAD_STORE_PATH")
                .unwrap_or_else(|_| "data/kad_store".to_string());

            let mut store = MemoryStore::new(peer_id);
            if let Ok(persist) = KadPersistence::open(&store_path) {
                for rec in persist.load_records() {
                    let _ = store.put(rec);
                }
            }

            // -- codec instances --
            let direct_codec = BincodeCodec::<crate::message::DirectRequest, crate::message::DirectResponse>::new(
                StreamProtocol::new(DIRECT_PROTOCOL),
            );
            let config_codec = BincodeCodec::<crate::config::ConfigRequest, crate::config::ConfigResponse>::new(
                StreamProtocol::new(CONFIG_PROTOCOL),
            );
            let gateway_codec = BincodeCodec::<crate::gateway::GatewayRequest, crate::gateway::GatewayResponse>::new(
                StreamProtocol::new(GATEWAY_PROTOCOL),
            );
            let web_codec = BincodeCodec::<crate::web::WebRequest, crate::web::WebResponse>::new(
                StreamProtocol::new(WEB_PROTOCOL),
            );
            let onboard_codec = BincodeCodec::<OnboardRequest, OnboardResponse>::new(
                StreamProtocol::new(ONBOARD_PROTOCOL),
            );
            let storage_codec = BincodeCodec::<StorageRequest, StorageResponse>::new(
                StreamProtocol::new("/ess/storage/1"),
            );

            // -- protocol behaviours --
            let direct = request_response::Behaviour::with_codec(
                direct_codec,
                [(StreamProtocol::new(DIRECT_PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            let config = request_response::Behaviour::with_codec(
                config_codec,
                [(StreamProtocol::new(CONFIG_PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            let gateway = request_response::Behaviour::with_codec(
                gateway_codec,
                [(StreamProtocol::new(GATEWAY_PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            let web = request_response::Behaviour::with_codec(
                web_codec,
                [(StreamProtocol::new(WEB_PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            let onboard = request_response::Behaviour::with_codec(
                onboard_codec,
                [(StreamProtocol::new(ONBOARD_PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            let storage = request_response::Behaviour::with_codec(
                storage_codec,
                [(StreamProtocol::new("/ess/storage/1"), ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            Ok(Behaviour {
                ping: ping::Behaviour::default(),
                identify: identify::Behaviour::new(
                    identify::Config::new_with_signed_peer_record(
                        PROTOCOL_VERSION.to_string(),
                        &key,
                    )
                    .with_agent_version("ess-p2p-rs/0.1.0".to_string())
                    .with_push_listen_addr_updates(true),
                ),
                kademlia: Kademlia::new(peer_id, store),
                direct,
                config,
                gateway,
                web,
                onboard,
                storage,
            })
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60 * 60)))
        .build();

    Ok(swarm)
}
