use std::io;
use std::net::UdpSocket;
use std::sync::Weak;

use wg_traits::Endpoint;
use wg_traits::udp::Reader;

use super::{get_connection_aborted_err, udp_endpoint::StdUdpEndpoint};

pub struct StdUdpReader {
    socket: Weak<UdpSocket>,
}

impl StdUdpReader {
    pub fn new(socket: Weak<UdpSocket>) -> Self {
        Self { socket }
    }
}

impl Reader<StdUdpEndpoint> for StdUdpReader {
    type Error = io::Error;

    fn read(&self, buf: &mut [u8]) -> io::Result<(usize, StdUdpEndpoint)> {
        let (n_bytes, addr) = self
            .socket
            .upgrade()
            .ok_or(get_connection_aborted_err())?
            .recv_from(buf)?;

        if self.socket.strong_count() == 0 {
            return Err(get_connection_aborted_err());
        }

        Ok((n_bytes, StdUdpEndpoint::from_address(addr)))
    }
}
