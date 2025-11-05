use std::io;
use std::net::UdpSocket;
use std::sync::Arc;

use wg_traits::udp::Owner;

use super::StdUdpSocket;

pub struct StdUdpOwner {
    _socket: StdUdpSocket<Arc<UdpSocket>>,
    port: u16,
}

impl StdUdpOwner {
    pub fn new(socket: StdUdpSocket<Arc<UdpSocket>>, port: u16) -> Self {
        Self {
            _socket: socket,
            port,
        }
    }
}

impl Owner for StdUdpOwner {
    type Error = io::Error;

    fn get_port(&self) -> u16 {
        self.port
    }

    fn set_fwmark(&mut self, _value: Option<u32>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "std udp doesn't support fwmark",
        ))
    }
}
