use std::net::SocketAddr;

use wg_traits::Endpoint;

#[derive(Clone, Copy, Default)]
pub struct UnitEndpoint;

impl Endpoint for UnitEndpoint {
    fn from_address(_: SocketAddr) -> UnitEndpoint {
        UnitEndpoint
    }

    fn to_address(&self) -> SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }
}
