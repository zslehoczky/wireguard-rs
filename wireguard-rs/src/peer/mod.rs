mod anti_replay;
pub mod constants;
mod decryption_state;
mod device_interface;
mod encryption_state;
mod inbound_job;
mod key_wheel;
mod outbound_job;
#[allow(clippy::module_inception)]
mod peer;
mod peer_interface;
mod peer_state;
mod peer_state_interface;
mod send_queue;
mod timer_state;

use std::time::Duration;

use wg_traits::{Endpoint, tun, udp};

use crate::router::KeyPair;

pub use device_interface::DeviceInterface;
pub use peer::{Peer, PeerHandle};
pub use peer_interface::PeerInterface;
pub use peer_state::PeerState;
pub use peer_state_interface::PeerStateInterface;

pub trait PeerDependencies: Send + Sync + 'static {
    type UdpEndpoint: Endpoint + Send + Sync + 'static;

    type TunWriter: tun::Writer;
    type UdpWriter: udp::Writer<Self::UdpEndpoint>;
}

pub trait TimerStopControl {
    fn stop(&self);
}

pub trait TimerControls: TimerStopControl {
    fn start(&self, duration: Duration) -> bool;
    fn reset(&self, duration: Duration);
}

pub trait PeerTimers: Send + Sync {
    fn all(&self) -> &dyn TimerStopControl;

    fn retransmit_handshake(&self) -> &dyn TimerControls;
    fn send_keepalive(&self) -> &dyn TimerControls;
    fn new_handshake(&self) -> &dyn TimerControls;
    fn zero_key_material(&self) -> &dyn TimerControls;
    fn send_persistent_keepalive(&self) -> &dyn TimerControls;
}

trait TimerCallbacks: Send + Sync {
    fn new_handshake(&self);
    fn retransmit_handshake(&self);
    fn send_keepalive(&self);
    fn send_persistent_keepalive(&self);
    fn zero_key_material(&self);
}
