use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::Arc;

use wg_traits::udp::{PlatformUDP, UDP};

use super::{
    udp_endpoint::StdUdpEndpoint, udp_owner::StdUdpOwner, udp_reader::StdUdpReader,
    udp_writer::StdUdpWriter,
};

pub struct StdUdp {}

impl UDP for StdUdp {
    type Error = io::Error;
    type Endpoint = StdUdpEndpoint;
    type Writer = StdUdpWriter;
    type Reader = StdUdpReader;
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
                StdUdpReader::new(Arc::downgrade(&socket_v4)),
                StdUdpReader::new(Arc::downgrade(&socket_v6)),
            ],
            StdUdpWriter::new(Arc::downgrade(&socket_v4), Arc::downgrade(&socket_v6)),
            StdUdpOwner::new(socket_v4, socket_v6, port),
        ))
    }
}
