use std::ops::Deref;

use wg_traits::tun::Writer as _;
use wg_traits::udp::Writer as _;

use crate::peer::{DeviceInterface, PeerDependencies};
use crate::router::{Router, RouterError};

pub struct FakeRouter<P: PeerDependencies> {
    router: Router<P>,
    tun_writer: P::TunWriter,
    udp_writer: P::UdpWriter,
}

impl<P: PeerDependencies> FakeRouter<P> {
    pub fn new(router: Router<P>, tun_writer: P::TunWriter, udp_writer: P::UdpWriter) -> Self {
        Self {
            router,
            tun_writer,
            udp_writer,
        }
    }
}

impl<P: PeerDependencies> Deref for FakeRouter<P> {
    type Target = Router<P>;

    fn deref(&self) -> &Self::Target {
        &self.router
    }
}

impl<P: PeerDependencies> DeviceInterface<P> for FakeRouter<P> {
    fn add_receiver(
        &self,
        prev_id: Option<u32>,
        new_id: u32,
        peer: crate::peer::Peer<P>,
    ) -> Option<u32> {
        self.router.add_receiver(prev_id, new_id, peer)
    }

    fn check_route(&self, peer: &crate::peer::Peer<P>, packet: &mut [u8]) -> bool {
        self.router.check_route(peer, packet)
    }

    fn insert_route(&self, ip: std::net::IpAddr, cidr: u32, peer: crate::peer::Peer<P>) {
        self.router.insert_route(ip, cidr, peer);
    }

    fn list_routes(&self, peer: &crate::peer::Peer<P>) -> Vec<(std::net::IpAddr, u32)> {
        self.router.list_routes(peer)
    }

    fn remove_receivers(&self, release: &[u32]) {
        self.router.remove_receivers(release);
    }

    fn remove_route(&self, peer: &crate::peer::Peer<P>) {
        self.router.remove_route(peer);
    }

    fn write_inbound(&self, data: &[u8]) {
        self.tun_writer.write(data).unwrap_or_else(|e| {
            log::debug!("failed to write inbound packet to TUN: {:?}", e);
        })
    }

    fn write_outbound(
        &self,
        msg: &[u8],
        endpoint: &mut <P as PeerDependencies>::UdpEndpoint,
    ) -> Result<(), RouterError> {
        self.udp_writer
            .write(msg, endpoint)
            .map_err(|_| RouterError::SendError)
    }
}
