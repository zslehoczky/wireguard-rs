mod config;
mod constants;
mod timers;
mod udp_writer;
#[allow(clippy::module_inception)]
mod wireguard;

#[cfg(test)]
pub mod tests;

use std::marker::PhantomData;

use wg_traits::{tun::Tun, udp::UDP};

use crate::peer::PeerDependencies;

pub use config::WireGuardConfig;
pub use constants::TIME_HORIZON;
pub use timers::TimerCallbacks;
pub use wireguard::WireGuard;

pub struct PeerDeps<T: Tun, U: UDP> {
    tun: PhantomData<T>,
    udp: PhantomData<U>,
}

impl<T: Tun, U: UDP> PeerDependencies for PeerDeps<T, U> {
    type UdpEndpoint = U::Endpoint;

    type TunWriter = T::Writer;
    type UdpWriter = U::Writer;
}
