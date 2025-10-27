/// The wireguard sub-module represents a full, pure, WireGuard implementation:
///
/// The WireGuard device described here does not depend on particular IO implementations
/// or UAPI, and can be instantiated in unit-tests with the dummy IO implementation.
///
/// The code at this level serves to "glue" the handshake state-machine
/// and the crypto-key router code together,
/// e.g. every WireGuard peer consists of one handshake peer and one router peer.
mod constants;
pub mod peer;
mod queue;
pub mod router;
mod timers;
mod workers;

#[cfg(test)]
mod tests;

#[allow(clippy::module_inception)]
mod wireguard;

// represents a WireGuard interface
pub use wireguard::WireGuard;
pub use workers::tun_worker;
