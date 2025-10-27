use std::fmt;
use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{IntoRawFd, RawFd};

use nix::cmsg_space;
use nix::sys::socket::{
    self, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockProtocol,
    SockType, SockaddrIn, SockaddrIn6, bind, getsockname, recvmsg, sendmsg, setsockopt, socket,
    sockopt::{Ipv4RecvDstAddr, Ipv4RecvIf, Ipv6RecvPacketInfo, ReuseAddr, ReusePort},
};
use std::sync::Arc;

use wg_traits::Endpoint;
use wg_traits::udp::{Owner, PlatformUDP, Reader, UDP, Writer};

#[derive(Debug)]
pub struct UdpSocket {
    socket: RawFd,
    is_ipv4: bool,
}

#[derive(Debug)]
pub enum UdpError {
    OpenSocket(nix::Error),
    SetSocketOpt(nix::Error),
    GetSockName(nix::Error),
    BindSocket(nix::Error),
    SendMsg(nix::Error),
    RecvMsg(nix::Error),
    UnexpectedControlMessage(ControlMessageOwned),
    NoControlMessage,
    InvalidAddress(String),
    UnsupportedProtocol(&'static str),
    InsufficientSourceInfo(Option<libc::in_addr>, Option<u32>),
}

impl std::fmt::Display for UdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use UdpError::*;
        match self {
            OpenSocket(err) => {
                write!(f, "failed to open socket: {}", err)
            }
            SetSocketOpt(err) => {
                write!(f, "failed to set socket option: {}", err)
            }
            GetSockName(err) => {
                write!(f, "failed to get socket name: {}", err)
            }
            BindSocket(err) => {
                write!(f, "failed to bind socket: {}", err)
            }
            SendMsg(err) => {
                write!(f, "failed to send message: {}", err)
            }
            RecvMsg(err) => {
                write!(f, "failed to receive message: {}", err)
            }
            InvalidAddress(invalid_addr) => {
                write!(f, "invalid socket address: {}", invalid_addr)
            }
            UnexpectedControlMessage(unexpected_message) => {
                write!(
                    f,
                    "received unexpected control message: {:?}",
                    unexpected_message
                )
            }
            NoControlMessage => {
                write!(f, "received no control message")
            }
            UnsupportedProtocol(protocol) => {
                write!(f, "unsupported protocol {}", protocol)
            }
            InsufficientSourceInfo(in_addr, if_index) => {
                let mut faults = Vec::with_capacity(2);
                if in_addr.is_none() {
                    faults.push("no address")
                }
                if if_index.is_none() {
                    faults.push("no reciving interface index")
                }
                write!(f, "received packet with {}", faults.join(" and "))
            }
        }
    }
}

impl std::error::Error for UdpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use UdpError::*;
        match self {
            OpenSocket(err) | SetSocketOpt(err) | GetSockName(err) | BindSocket(err)
            | SendMsg(err) | RecvMsg(err) => Some(err),
            UnexpectedControlMessage(_)
            | NoControlMessage
            | InvalidAddress(_)
            | UnsupportedProtocol(_)
            | InsufficientSourceInfo(_, _) => None,
        }
    }
}

type Result<T> = std::result::Result<T, UdpError>;

impl UdpSocket {
    fn bind(addr: impl Into<std::net::IpAddr>, port: u16) -> Result<(u16, Self)> {
        let ip_addr = addr.into();
        let addr_family = if ip_addr.is_ipv4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };

        let socket_addr: socket::SockaddrStorage = SocketAddr::new(ip_addr, port).into();

        let socket_fd = socket(
            addr_family,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )
        .map_err(UdpError::OpenSocket)?;

        if ip_addr.is_ipv4() {
            setsockopt(&socket_fd, Ipv4RecvDstAddr, &true).map_err(UdpError::SetSocketOpt)?;
            setsockopt(&socket_fd, Ipv4RecvIf, &true).map_err(UdpError::SetSocketOpt)?;
        } else {
            setsockopt(&socket_fd, Ipv6RecvPacketInfo, &true).map_err(UdpError::SetSocketOpt)?;
        }

        setsockopt(&socket_fd, ReuseAddr, &true).map_err(UdpError::SetSocketOpt)?;
        setsockopt(&socket_fd, ReusePort, &true).map_err(UdpError::SetSocketOpt)?;

        let socket: RawFd = socket_fd.into_raw_fd();

        bind(socket, &socket_addr).map_err(UdpError::BindSocket)?;
        let bound_port = if port == 0 {
            let sockaddr = getsockname(socket).map_err(UdpError::GetSockName)?;
            Self::validate_sockaddr(sockaddr)?.port()
        } else {
            port
        };

        Ok((
            bound_port,
            Self {
                socket,
                is_ipv4: ip_addr.is_ipv4(),
            },
        ))
    }

    fn validate_sockaddr(addr: socket::SockaddrStorage) -> Result<SocketAddr> {
        addr.as_sockaddr_in()
            .map(|sin| SocketAddr::V4((*sin).into()))
            .or_else(|| {
                addr.as_sockaddr_in6()
                    .map(|sin6| SocketAddr::V6((*sin6).into()))
            })
            .ok_or_else(|| UdpError::InvalidAddress(format!("{:?}", addr)))
    }

    fn send_to(&self, buf: &[u8], endpoint: &MacosEndpoint) -> Result<usize> {
        let iov = [IoSlice::new(buf)];
        let packet_info = PacketInfo::new(endpoint);
        let control_messages = [packet_info.control_message()];
        let dest_addr: socket::SockaddrStorage = endpoint.destination_sockaddr();
        sendmsg(
            self.socket,
            &iov,
            &control_messages,
            MsgFlags::empty(),
            Some(&dest_addr),
        )
        .map_err(UdpError::SendMsg)
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, MacosEndpoint)> {
        let mut iov = [IoSliceMut::new(buf)];
        let mut control_messages_buffer = self.control_message_buffer();
        let msg = recvmsg::<socket::SockaddrStorage>(
            self.socket,
            &mut iov,
            Some(&mut control_messages_buffer),
            MsgFlags::empty(),
        )
        .map_err(UdpError::RecvMsg)?;

        let endpoint = if self.is_ipv4 {
            let mut destination_addr = None;
            let mut if_index = None;

            let src_addr_info = msg
                .address
                .and_then(|addr| addr.as_sockaddr_in().copied())
                .ok_or_else(|| UdpError::InvalidAddress(format!("{:?}", msg.address)))?;

            let control_messages = msg.cmsgs().map_err(UdpError::RecvMsg)?;
            for message in control_messages {
                match message {
                    ControlMessageOwned::Ipv4RecvIf(if_sockaddr) => {
                        if_index = Some(if_sockaddr.sdl_index as u32);
                    }
                    ControlMessageOwned::Ipv4RecvDstAddr(in_addr) => {
                        destination_addr = Some(in_addr);
                    }
                    other => {
                        log::error!("received unexpected control message: {:?}", other);
                        continue;
                    }
                }
            }
            match (destination_addr, if_index) {
                (Some(incoming_destination), Some(src_if_index)) => MacosEndpoint::V4 {
                    destination: (*src_addr_info.as_ref()),
                    src_if_index,
                    src_addr: incoming_destination,
                },
                (dest, if_index) => {
                    return Err(UdpError::InsufficientSourceInfo(dest, if_index));
                }
            }
        } else {
            let src_addr_info = msg
                .address
                .and_then(|addr| addr.as_sockaddr_in6().copied())
                .ok_or_else(|| UdpError::InvalidAddress(format!("{:?}", msg.address)))?;

            let mut cmsgs = msg.cmsgs().map_err(UdpError::RecvMsg)?;
            let src_if_index = match cmsgs.next() {
                Some(ControlMessageOwned::Ipv6PacketInfo(packet_info)) => packet_info.ipi6_ifindex,
                Some(any_other_cmsg) => {
                    return Err(UdpError::UnexpectedControlMessage(any_other_cmsg));
                }
                None => {
                    return Err(UdpError::NoControlMessage);
                }
            };
            MacosEndpoint::V6 {
                destination: (*src_addr_info.as_ref()),
                src_if_index,
            }
        };
        Ok((msg.bytes, endpoint))
    }

    fn control_message_buffer(&self) -> Vec<u8> {
        if self.is_ipv4 {
            cmsg_space!(libc::in_addr, libc::sockaddr_dl)
        } else {
            cmsg_space!(libc::in6_pktinfo)
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        log::debug!("macos udp, release fd (fd = {})", self.socket);
        if let Err(err) = nix::unistd::close(self.socket) {
            log::error!("failed to close UdpSocket {}", err);
        }
    }
}
enum PacketInfo {
    V4(libc::in_pktinfo),
    V6(libc::in6_pktinfo),
}

impl PacketInfo {
    fn new(endpoint: &MacosEndpoint) -> Self {
        match endpoint {
            MacosEndpoint::V4 {
                destination,
                src_if_index,
                src_addr,
            } => Self::V4(libc::in_pktinfo {
                ipi_addr: destination.sin_addr,
                ipi_ifindex: *src_if_index,
                ipi_spec_dst: *src_addr,
            }),
            MacosEndpoint::V6 {
                destination,
                src_if_index,
            } => Self::V6(libc::in6_pktinfo {
                ipi6_addr: destination.sin6_addr,
                ipi6_ifindex: *src_if_index,
            }),
        }
    }

    fn control_message<'a>(&'a self) -> ControlMessage<'a> {
        match self {
            Self::V4(v4) => ControlMessage::Ipv4PacketInfo(v4),
            Self::V6(v6) => ControlMessage::Ipv6PacketInfo(v6),
        }
    }
}

pub struct MacosUDP();

pub struct MacosOwner {
    port: u16,
    _sock4: Option<Arc<UdpSocket>>,
    _sock6: Option<Arc<UdpSocket>>,
}

impl MacosOwner {
    pub fn get_port(&self) -> u16 {
        self.port
    }

    pub fn set_fwmark(&mut self, _value: Option<u32>) -> Result<()> {
        Ok(())
    }
}

pub enum MacosUDPReader {
    V4(Arc<UdpSocket>),
    V6(Arc<UdpSocket>),
}

impl AsRef<UdpSocket> for MacosUDPReader {
    fn as_ref(&self) -> &UdpSocket {
        match self {
            Self::V4(socket) | Self::V6(socket) => socket,
        }
    }
}

#[derive(Clone)]
pub struct MacosUDPWriter {
    sock4: Option<Arc<UdpSocket>>,
    sock6: Option<Arc<UdpSocket>>,
}

#[derive(Debug)]
pub enum MacosEndpoint {
    V4 {
        destination: libc::sockaddr_in,
        src_if_index: u32,
        src_addr: libc::in_addr,
    },
    V6 {
        destination: libc::sockaddr_in6,
        src_if_index: u32,
    },
}

impl MacosEndpoint {
    fn destination_sockaddr(&self) -> socket::SockaddrStorage {
        match self {
            Self::V4 { destination, .. } => {
                let sin = SockaddrIn::from(*destination);
                SocketAddr::V4(sin.into()).into()
            }
            Self::V6 { destination, .. } => {
                let sin6 = SockaddrIn6::from(*destination);
                SocketAddr::V6(sin6.into()).into()
            }
        }
    }

    fn destination(&self) -> SocketAddr {
        match self {
            Self::V4 { destination, .. } => SocketAddr::V4(SockaddrIn::from(*destination).into()),
            Self::V6 { destination, .. } => SocketAddr::V6(SockaddrIn6::from(*destination).into()),
        }
    }

    fn is_ipv4(&self) -> bool {
        match self {
            Self::V4 { .. } => true,
            Self::V6 { .. } => false,
        }
    }
}

impl MacosEndpoint {
    pub fn from_address(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr_v4) => Self::V4 {
                destination: *SockaddrIn::from(addr_v4).as_ref(),
                src_if_index: 0,
                src_addr: libc::in_addr { s_addr: 0u32 },
            },
            SocketAddr::V6(addr_v6) => Self::V6 {
                destination: *SockaddrIn6::from(addr_v6).as_ref(),
                src_if_index: 0,
            },
        }
    }

    pub fn clear_src(&mut self) {
        match self {
            Self::V4 {
                src_if_index,
                src_addr,
                ..
            } => {
                *src_if_index = 0;
                *src_addr = libc::in_addr { s_addr: 0u32 };
            }
            Self::V6 { src_if_index, .. } => {
                *src_if_index = 0;
            }
        }
    }

    pub fn to_address(&self) -> SocketAddr {
        self.destination()
    }
}

impl MacosUDPReader {
    pub fn read(&self, buf: &mut [u8]) -> Result<(usize, MacosEndpoint)> {
        self.as_ref().recv_from(buf)
    }
}

impl MacosUDPWriter {
    pub fn write(&self, buf: &[u8], dst: &mut MacosEndpoint) -> Result<()> {
        let maybe_socket = if dst.is_ipv4() {
            &self.sock4
        } else {
            &self.sock6
        };

        let socket =
            maybe_socket
                .as_ref()
                .ok_or(UdpError::UnsupportedProtocol(if dst.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                }))?;

        let _ = socket.send_to(buf, dst)?;
        Ok(())
    }
}

impl MacosUDP {
    #[allow(clippy::type_complexity)]
    #[allow(clippy::unnecessary_unwrap)]
    pub fn bind(mut port: u16) -> Result<(Vec<MacosUDPReader>, MacosUDPWriter, MacosOwner)> {
        log::trace!("binding to port {}", port);

        let bind6 = UdpSocket::bind(Ipv6Addr::UNSPECIFIED, port);
        if let Ok((new_port, _)) = bind6 {
            port = new_port;
        }

        let bind4 = UdpSocket::bind(Ipv4Addr::UNSPECIFIED, port);
        if let Ok((new_port, _)) = bind4 {
            port = new_port;
        }

        if bind4.is_err() && bind6.is_err() {
            log::trace!("failed to bind for either IP version");
            return Err(bind6.unwrap_err());
        }

        let sock6 = bind6.ok().map(|(_, socket)| Arc::new(socket));
        let sock4 = bind4.ok().map(|(_, socket)| Arc::new(socket));

        let owner = MacosOwner {
            port,
            _sock6: sock6.clone(),
            _sock4: sock4.clone(),
        };

        let mut readers: Vec<MacosUDPReader> = Vec::with_capacity(2);
        if let Some(sock) = sock6.clone() {
            readers.push(MacosUDPReader::V6(sock))
        }
        if let Some(sock) = sock4.clone() {
            readers.push(MacosUDPReader::V4(sock))
        }
        debug_assert!(!readers.is_empty());

        let writer = MacosUDPWriter { sock4, sock6 };

        Ok((readers, writer, owner))
    }
}

// Trait implementations

impl Endpoint for MacosEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        MacosEndpoint::from_address(addr)
    }

    fn to_address(&self) -> SocketAddr {
        self.to_address()
    }

    fn clear_src(&mut self) {
        self.clear_src()
    }
}

impl Reader<MacosEndpoint> for MacosUDPReader {
    type Error = UdpError;

    fn read(&self, buf: &mut [u8]) -> Result<(usize, MacosEndpoint)> {
        self.read(buf)
    }
}

impl Writer<MacosEndpoint> for MacosUDPWriter {
    type Error = UdpError;

    fn write(&self, buf: &[u8], dst: &mut MacosEndpoint) -> Result<()> {
        self.write(buf, dst)
    }
}

impl UDP for MacosUDP {
    type Error = UdpError;
    type Endpoint = MacosEndpoint;
    type Writer = MacosUDPWriter;
    type Reader = MacosUDPReader;
}

impl Owner for MacosOwner {
    type Error = UdpError;

    fn get_port(&self) -> u16 {
        self.get_port()
    }

    fn set_fwmark(&mut self, value: Option<u32>) -> Result<()> {
        self.set_fwmark(value)
    }
}

impl PlatformUDP for MacosUDP {
    type Owner = MacosOwner;

    fn bind(
        port: u16,
    ) -> std::result::Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        MacosUDP::bind(port)
    }
}
