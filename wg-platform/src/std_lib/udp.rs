use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket};

use net2::UdpBuilder;

use wg_traits::udp::{PlatformUDP, UDP};

use super::{
    udp_endpoint::StdUdpEndpoint, udp_reader::StdUdpReader, udp_socket_pair::StdUdpSocketPair,
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
    type Owner = StdUdpSocketPair;

    fn bind(port: u16) -> io::Result<(Vec<Self::Reader>, Self::Writer, Self::Owner)> {
        log::trace!("Creating new StdUdp with port: {port}");

        let (port, socket_v4, socket_v6) = loop {
            let socket_v4 = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;

            // try to create v6 socket with the same port as v4
            // this is important in case of port 0, where a random port is assigned upon bind()
            let socket_v4_port = socket_v4.local_addr()?.port();
            let socket_v6_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, socket_v4_port, 0, 0);

            match UdpBuilder::new_v6()?.only_v6(true)?.bind(socket_v6_addr) {
                Ok(socket_v6) => {
                    break (socket_v4_port, socket_v4, socket_v6);
                }
                Err(err) => {
                    // if requested port was 0, try again, else return with error
                    if port != 0 {
                        return Err(err);
                    }
                }
            };
        };

        let socket_pair = StdUdpSocketPair::new(port, socket_v4, socket_v6);

        Ok((
            vec![
                StdUdpReader::new(socket_pair.get_v4()),
                StdUdpReader::new(socket_pair.get_v6()),
            ],
            StdUdpWriter::new(socket_pair.get_v4(), socket_pair.get_v6()),
            socket_pair,
        ))
    }
}
