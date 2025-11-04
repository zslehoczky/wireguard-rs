use std::io;
use std::net::UdpSocket;
use std::sync::Arc;

use wg_traits::udp::Owner;

pub struct StdUdpOwner {
    _sockets: Vec<Arc<UdpSocket>>,
    port: u16,
}

impl StdUdpOwner {
    pub fn new(socket_v4: Arc<UdpSocket>, socket_v6: Arc<UdpSocket>, port: u16) -> Self {
        debug_assert_eq!(
            if port == 0 {
                0
            } else {
                socket_v4.local_addr().unwrap().port()
            },
            port
        );
        debug_assert_eq!(
            if port == 0 {
                0
            } else {
                socket_v6.local_addr().unwrap().port()
            },
            port
        );

        Self {
            _sockets: vec![socket_v4, socket_v6],
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
