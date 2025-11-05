use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Weak;

use wg_traits::Endpoint;
use wg_traits::udp::Writer;

use super::{StdUdpSocket, get_connection_aborted_err, udp_endpoint::StdUdpEndpoint};

pub struct StdUdpWriter {
    socket: StdUdpSocket<Weak<UdpSocket>>,
}

impl StdUdpWriter {
    pub fn from_dual(socket: Weak<UdpSocket>) -> Self {
        Self {
            socket: StdUdpSocket::Dual { socket },
        }
    }

    pub fn from_separate(socket_v4: Weak<UdpSocket>, socket_v6: Weak<UdpSocket>) -> Self {
        Self {
            socket: StdUdpSocket::Separate {
                socket_v4,
                socket_v6,
            },
        }
    }
}

impl Writer<StdUdpEndpoint> for StdUdpWriter {
    type Error = io::Error;

    fn write(&self, buf: &[u8], dst: &mut StdUdpEndpoint) -> io::Result<()> {
        let socket = match &self.socket {
            StdUdpSocket::Dual { socket } => socket,
            StdUdpSocket::Separate {
                socket_v4,
                socket_v6,
            } => match dst.to_address() {
                SocketAddr::V4(_) => socket_v4,
                SocketAddr::V6(_) => socket_v6,
            },
        };

        socket
            .upgrade()
            .ok_or(get_connection_aborted_err())?
            .send_to(buf, dst.to_address())?;

        Ok(())
    }
}
