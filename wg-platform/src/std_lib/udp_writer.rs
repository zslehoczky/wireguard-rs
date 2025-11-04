use std::io;
use std::net::UdpSocket;
use std::sync::Weak;

use wg_traits::Endpoint;
use wg_traits::udp::Writer;

use super::{get_connection_aborted_err, udp_endpoint::StdUdpEndpoint};

pub struct StdUdpWriter {
    sockets: Vec<Weak<UdpSocket>>,
}

impl StdUdpWriter {
    pub fn new(socket_v4: Weak<UdpSocket>, socket_v6: Weak<UdpSocket>) -> Self {
        Self {
            sockets: vec![socket_v4, socket_v6],
        }
    }
}

impl Writer<StdUdpEndpoint> for StdUdpWriter {
    type Error = io::Error;

    fn write(&self, buf: &[u8], dst: &mut StdUdpEndpoint) -> io::Result<()> {
        for socket in &self.sockets[..] {
            socket
                .upgrade()
                .ok_or(get_connection_aborted_err())?
                .send_to(buf, dst.to_address())?;
        }

        Ok(())
    }
}
