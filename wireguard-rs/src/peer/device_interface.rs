use std::net::IpAddr;

use crate::router::RouterError;

use super::{Peer, PeerDependencies};

pub trait DeviceInterface<P: PeerDependencies>: Send + Sync + 'static {
    fn add_receiver(&self, prev_id: Option<u32>, new_id: u32, peer: Peer<P>) -> Option<u32>;

    fn check_route(&self, peer: &Peer<P>, packet: &mut [u8]) -> bool;

    fn insert_route(&self, ip: IpAddr, cidr: u32, peer: Peer<P>);

    fn list_routes(&self, peer: &Peer<P>) -> Vec<(IpAddr, u32)>;

    fn read_outbound(&self, msg: &[u8], endpoint: &mut P::UdpEndpoint) -> Result<(), RouterError>;

    fn remove_receivers(&self, release: &[u32]);

    fn remove_route(&self, peer: &Peer<P>);

    fn write_inbound(&self, data: &[u8]);
}
