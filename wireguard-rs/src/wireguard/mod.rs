use std::marker::PhantomData;

#[cfg(test)]
pub mod tests;

#[allow(clippy::module_inception)]
mod wireguard;

use wg_traits::{tun::Tun, udp::UDP};

use crate::router::PeerDependencies;

// represents a WireGuard interface
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
