use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use wg_traits::Endpoint;

pub struct StdUdpEndpoint {
    addr: SocketAddr,
}

impl Endpoint for StdUdpEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        Self { addr }
    }

    fn to_address(&self) -> SocketAddr {
        self.addr
    }

    fn clear_src(&mut self) {
        self.addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        self.addr.set_port(0);
    }
}
