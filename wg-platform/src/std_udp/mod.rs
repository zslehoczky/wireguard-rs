use std::io::{self, IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;

use nix::cmsg_space;
use nix::errno::Errno;
use nix::sys::socket::sockopt::{Ipv4PacketInfo, Ipv6RecvPacketInfo};
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, RecvMsg, SockaddrStorage, recvmsg, sendmsg,
    setsockopt,
};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket};

use wg_traits::Endpoint;
use wg_traits::udp::{Owner, PlatformUDP, Reader, UDP, Writer};

fn clone_socket(socket: &UdpSocket) -> UdpSocket {
    socket.try_clone().expect("cloning UDP sockets should work")
}

fn create_address_v4(port: u16) -> SockAddr {
    SocketAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).into()
}

fn create_address_v6(port: u16) -> SockAddr {
    SocketAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)).into()
}

fn create_socket(domain: Domain) -> io::Result<Socket> {
    Socket::new(domain, socket2::Type::DGRAM, Some(Protocol::UDP))
}

fn set_recv_packet_info_v4(socket: &Socket, value: bool) -> Result<(), Errno> {
    setsockopt(socket, Ipv4PacketInfo, &value)
}

fn set_recv_packet_info_v6(socket: &Socket, value: bool) -> Result<(), Errno> {
    setsockopt(socket, Ipv6RecvPacketInfo, &value)
}

fn shutdown_socket(socket: &UdpSocket) -> io::Result<()> {
    SockRef::from(socket).shutdown(Shutdown::Both)
}

pub struct StdUDPReader {
    wrapped: UdpSocket,
}

impl StdUDPReader {
    fn create_for_sockets(
        socket_v4: &Option<UdpSocket>,
        socket_v6: &Option<UdpSocket>,
    ) -> Vec<Self> {
        let mut result = Vec::with_capacity(2);

        if let Some(socket) = socket_v4 {
            result.push(StdUDPReader {
                wrapped: clone_socket(socket),
            });
        }

        if let Some(socket) = socket_v6 {
            result.push(StdUDPReader {
                wrapped: clone_socket(socket),
            });
        }

        result
    }
}

impl Reader<StdEndpoint> for StdUDPReader {
    type Error = io::Error;

    fn read(&self, buf: &mut [u8]) -> io::Result<(usize, StdEndpoint)> {
        let mut slices_to_write = [IoSliceMut::new(buf)];

        // reserve space for both an IPv4 and an IPv6 PKTINFO header
        // this guarantees that either one will fit into the buffer
        let mut control_buf = cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo);

        // receive packet with ancillary data
        let recvmsg_result: RecvMsg<'_, '_, SockaddrStorage> = recvmsg(
            self.wrapped.as_raw_fd(),
            &mut slices_to_write,
            Some(&mut control_buf),
            MsgFlags::empty(),
        )?;

        let recv_address = {
            let recv_address = recvmsg_result.address.expect("address should exist");

            if let Some(&address) = recv_address.as_sockaddr_in() {
                address.into()
            } else if let Some(&address) = recv_address.as_sockaddr_in6() {
                address.into()
            } else {
                unreachable!("socket address should be either IPv4 or IPv6");
            }
        };

        let mut remote_endpoint = StdEndpoint::from_address(recv_address);

        let packet_info = match recvmsg_result
            .cmsgs()?
            .next()
            .ok_or(io::Error::other("No control messages could be found"))?
        {
            ControlMessageOwned::Ipv4PacketInfo(info) => PktInfo::V4(info),
            ControlMessageOwned::Ipv6PacketInfo(info) => PktInfo::V6(info),
            _ => unreachable!("message type should be either IPv4 or IPv6 packet info"),
        };

        remote_endpoint.packet_info = Some(packet_info);

        Ok((recvmsg_result.bytes, remote_endpoint))
    }
}

pub struct StdUDPWriter {
    socket_v4: Option<UdpSocket>,
    socket_v6: Option<UdpSocket>,
}

impl Writer<StdEndpoint> for StdUDPWriter {
    type Error = io::Error;

    fn write(&self, buf: &[u8], dst: &StdEndpoint) -> io::Result<()> {
        // choose source socket based on destination's IP version
        let src = match dst.wrapped {
            SocketAddr::V4(_) => &self.socket_v4,
            SocketAddr::V6(_) => &self.socket_v6,
        };

        let src = src.as_ref().ok_or(io::Error::new(
            io::ErrorKind::NotConnected,
            "Socket not connected for protocol",
        ))?;

        let address: SockaddrStorage = dst.to_address().into();
        let slices_to_read = [IoSlice::new(buf)];

        let control_message = dst.packet_info.as_ref().map(|p| match p {
            PktInfo::V4(info) => ControlMessage::Ipv4PacketInfo(info),
            PktInfo::V6(info) => ControlMessage::Ipv6PacketInfo(info),
        });

        // send packet with ancillary data
        sendmsg(
            src.as_raw_fd(),
            &slices_to_read,
            control_message.as_slice(),
            MsgFlags::empty(),
            Some(&address),
        )?;

        Ok(())
    }
}

enum PktInfo {
    V4(libc::in_pktinfo),
    V6(libc::in6_pktinfo),
}

pub struct StdEndpoint {
    wrapped: SocketAddr,
    packet_info: Option<PktInfo>, // remote endpoint should be reached via the interface described here
}

impl Endpoint for StdEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        Self {
            wrapped: addr,
            packet_info: None,
        }
    }

    fn to_address(&self) -> SocketAddr {
        self.wrapped
    }

    fn clear_src(&mut self) {
        self.packet_info = None;
    }
}

pub struct StdUDP {
    socket_v4: Option<UdpSocket>,
    socket_v6: Option<UdpSocket>,
}

impl StdUDP {
    fn bind_v4(port: u16) -> io::Result<Socket> {
        let socket = create_socket(Domain::IPV4)?;
        socket.set_reuse_address(true)?;
        set_recv_packet_info_v4(&socket, true)?;
        socket.bind(&create_address_v4(port))?;
        Ok(socket)
    }

    fn bind_v6(port: u16) -> io::Result<Socket> {
        let socket = create_socket(Domain::IPV6)?;
        socket.set_reuse_address(true)?;
        socket.set_only_v6(true)?;
        set_recv_packet_info_v6(&socket, true)?;
        socket.bind(&create_address_v6(port))?;
        Ok(socket)
    }

    pub fn bind(mut port: u16) -> io::Result<(Vec<StdUDPReader>, StdUDPWriter, StdUDP)> {
        let socket_v6 = Self::bind_v6(port);

        if let Ok(socket) = &socket_v6 {
            // When port number 0 is given, socket will be bound to a random port.
            // We update the port number to the actual bound port,
            // so that v4 could be bound to the same port and not be randomized.
            port = socket
                .local_addr()
                .expect("socket should be bound")
                .as_socket()
                .expect("socket address should be convertible to IPv6")
                .port();
        }

        let socket_v4 = Self::bind_v4(port);

        let (socket_v4, socket_v6) = match (socket_v4, socket_v6) {
            (Err(err4), Err(err6)) => {
                return Err(io::Error::other(format!(
                    "Failed to bind UDP sockets for both IPv4 and IPv6. \
                     IPv4 error: {err4}; IPv6 error: {err6}"
                )));
            }
            (socket_v4, socket_v6) => (
                socket_v4.ok().map(Into::into),
                socket_v6.ok().map(Into::into),
            ),
        };

        debug_assert!(socket_v4.is_some() || socket_v4.is_some());

        // create readers
        let readers = StdUDPReader::create_for_sockets(&socket_v4, &socket_v6);

        // create writer
        let writer = StdUDPWriter {
            socket_v4: socket_v4.as_ref().map(clone_socket),
            socket_v6: socket_v6.as_ref().map(clone_socket),
        };

        // create owner
        let owner = StdUDP {
            socket_v4,
            socket_v6,
        };

        Ok((readers, writer, owner))
    }
}

impl Drop for StdUDP {
    fn drop(&mut self) {
        self.socket_v4.as_ref().map(shutdown_socket);
        self.socket_v6.as_ref().map(shutdown_socket);
    }
}

impl UDP for StdUDP {
    type Error = io::Error;
    type Endpoint = StdEndpoint;
    type Writer = StdUDPWriter;
    type Reader = StdUDPReader;
}

impl Owner for StdUDP {
    type Error = io::Error;

    fn get_port(&self) -> u16 {
        [&self.socket_v4, &self.socket_v6]
            .into_iter()
            .flatten()
            .next()
            .expect("there should be at least one bound socket")
            .local_addr()
            .expect("bound sockets should have an address")
            .port()
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, value: u32) -> io::Result<()> {
        if let Some(socket) = &self.socket_v4 {
            SockRef::from(socket).set_mark(value)?;
        }
        if let Some(socket) = &self.socket_v6 {
            SockRef::from(socket).set_mark(value)?;
        }

        Ok(())
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    fn set_fwmark(&mut self, _value: u32) -> io::Result<()> {
        Err(io::Error::other(
            "Setting FWMARK is not available for this OS",
        ))
    }
}

impl PlatformUDP for StdUDP {
    type Owner = Self;

    fn bind(port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        StdUDP::bind(port)
    }
}
