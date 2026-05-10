use std::fs;
use libp2p::identity::Keypair;
fn main() {
    let data = fs::read("data/identity/ess_identity.bin").unwrap();
    let keypair = Keypair::from_protobuf_encoding(&data).unwrap();
    let pubkey = keypair.public();
    println!("{}", hex::encode(pubkey.encode_protobuf()));
}
