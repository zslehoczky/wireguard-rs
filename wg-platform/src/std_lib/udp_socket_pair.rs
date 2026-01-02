use std::io;
use std::net::UdpSocket;
use std::sync::{Arc, Weak};

use wg_traits::udp::Owner;

pub struct StdUdpSocketPair {
    port: u16,
    socket_v4: Arc<UdpSocket>,
    socket_v6: Arc<UdpSocket>,
}

impl StdUdpSocketPair {
    pub fn new(port: u16, socket_v4: UdpSocket, socket_v6: UdpSocket) -> Self {
        debug_assert_eq!(port, socket_v4.local_addr().unwrap().port());
        debug_assert_eq!(port, socket_v6.local_addr().unwrap().port());

        let socket_v4 = Arc::new(socket_v4);
        let socket_v6 = Arc::new(socket_v6);

        Self {
            port,
            socket_v4,
            socket_v6,
        }
    }

    pub fn get_v4(&self) -> Weak<UdpSocket> {
        Arc::downgrade(&self.socket_v4)
    }

    pub fn get_v6(&self) -> Weak<UdpSocket> {
        Arc::downgrade(&self.socket_v6)
    }
}

impl Owner for StdUdpSocketPair {
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
