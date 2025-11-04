use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::{Arc, Weak};

use wg_traits::Endpoint;
use wg_traits::udp::{Owner, PlatformUDP, Reader, UDP, Writer};

fn get_connection_aborted_err() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "UDP socket closed")
}

pub struct StdUdpReader {
    socket: Weak<UdpSocket>,
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

pub struct StdUdpWriter {
    sockets: Vec<Weak<UdpSocket>>,
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

pub struct StdUdpOwner {
    _sockets: Vec<Arc<UdpSocket>>,
    port: u16,
}

impl Owner for StdUdpOwner {
    type Error = io::Error;

    fn get_port(&self) -> u16 {
        self.port
    }

    fn set_fwmark(&mut self, _value: Option<u32>) -> io::Result<()> {
        unimplemented!("std udp doesn't support fwmark")
    }
}

impl PlatformUDP for StdUdp {
    type Owner = StdUdpOwner;

    fn bind(port: u16) -> io::Result<(Vec<Self::Reader>, Self::Writer, Self::Owner)> {
        let socket_v4 = Arc::new(UdpSocket::bind(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            port,
        ))?);
        let socket_v6 = Arc::new(UdpSocket::bind(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            port,
            0,
            0,
        ))?);

        Ok((
            vec![
                StdUdpReader {
                    socket: Arc::downgrade(&socket_v4),
                },
                StdUdpReader {
                    socket: Arc::downgrade(&socket_v6),
                },
            ],
            StdUdpWriter {
                sockets: vec![Arc::downgrade(&socket_v4), Arc::downgrade(&socket_v6)],
            },
            StdUdpOwner {
                _sockets: vec![socket_v4, socket_v6],
                port,
            },
        ))
    }
}

pub struct StdUdp {}

impl UDP for StdUdp {
    type Error = io::Error;
    type Endpoint = StdUdpEndpoint;
    type Writer = StdUdpWriter;
    type Reader = StdUdpReader;
}

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
        todo!("don't know what this is yet")
    }
}
