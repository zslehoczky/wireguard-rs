mod anti_replay;
mod decryption_state;
mod encryption_state;
mod key_wheel;
#[allow(clippy::module_inception)]
mod peer;
mod peer_state;

use std::sync::Arc;

use wg_traits::{Endpoint, tun, udp};

use crate::router::KeyPair;

pub use decryption_state::DecryptionState;
use encryption_state::EncryptionState;
pub use peer::{Peer, PeerHandle};
pub use peer_state::PeerState;

fn crypto_state<P>(peer: P, keypair: Arc<KeyPair>) -> (EncryptionState, DecryptionState<P>) {
    (
        EncryptionState::new(keypair.clone()),
        DecryptionState::new(peer, keypair),
    )
}

pub trait PeerDependencies: 'static {
    type UdpEndpoint: Endpoint;

    type TunWriter: tun::Writer;
    type UdpWriter: udp::Writer<Self::UdpEndpoint>;
}
