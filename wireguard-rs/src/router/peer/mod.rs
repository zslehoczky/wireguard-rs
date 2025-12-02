mod anti_replay;
mod decryption_state;
mod encryption_state;
mod key_wheel;
mod outbound_job;
#[allow(clippy::module_inception)]
mod peer;
mod peer_state;
mod send_queue;

use wg_traits::{Endpoint, tun, udp};

use crate::router::KeyPair;

pub use peer::{Peer, PeerHandle};
pub use peer_state::PeerState;

pub trait PeerDependencies: 'static {
    type UdpEndpoint: Endpoint;

    type TunWriter: tun::Writer;
    type UdpWriter: udp::Writer<Self::UdpEndpoint>;
}
