use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};

use socket2::{SockAddr, SockRef, Socket};

use wg_traits::Endpoint;
use wg_traits::udp::{Owner, PlatformUDP, Reader, UDP, Writer};

fn bind_socket(socket: Socket, address: SocketAddr) -> io::Result<Socket> {
    socket.bind(&SockAddr::from(address)).map(|_| socket)
}

fn clone_socket(socket: &Socket) -> Socket {
    socket.try_clone().expect("cloning UDP sockets should work")
}

fn create_socket(address: SocketAddr) -> io::Result<Socket> {
    Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
}

fn get_socket_port(socket: &Socket) -> io::Result<Option<u16>> {
    Ok(socket
        .local_addr()?
        .as_socket_ipv6()
        .as_ref()
        .map(SocketAddrV6::port))
}

fn shutdown_socket(socket: &UdpSocket) -> io::Result<()> {
    SockRef::from(socket).shutdown(Shutdown::Both)
}

pub struct StdUDP {
    port: u16,
    socket4: Option<UdpSocket>,
    socket6: Option<UdpSocket>,
}

impl Drop for StdUDP {
    fn drop(&mut self) {
        self.socket4.as_ref().map(shutdown_socket);
        self.socket6.as_ref().map(shutdown_socket);
    }
}

pub enum StdUDPReader {
    V4(UdpSocket),
    V6(UdpSocket),
}

impl StdUDPReader {
    fn new(socket: &Socket) -> Self {
        StdUDPReader::V4(clone_socket(socket).into())
    }
}

pub struct StdUDPWriter {
    socket4: Option<UdpSocket>,
    socket6: Option<UdpSocket>,
}

pub enum StdEndpoint {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}

impl StdUDP {
    fn bind4(port: u16) -> io::Result<Socket> {
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        let socket = create_socket(address)?;
        socket.set_reuse_address(true)?;

        bind_socket(socket, address)
    }

    fn bind6(port: u16) -> io::Result<Socket> {
        let address = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
        let socket = create_socket(address)?;
        socket.set_reuse_address(true)?;
        socket.set_only_v6(true)?;

        bind_socket(socket, address)
    }

    pub fn bind(mut port: u16) -> io::Result<(Vec<StdUDPReader>, StdUDPWriter, StdUDP)> {
        log::debug!("bind to port {}", port);

        // attempt to bind on ipv6
        let socket6 = Self::bind6(port);

        if let Ok(socket6) = &socket6 {
            port = get_socket_port(socket6)?.unwrap_or(port);
        }

        // attempt to bind on ipv4 on the same port
        let socket4 = Self::bind4(port);

        // check if failed to bind on both
        if socket4.is_err()
            && let Err(error) = socket6
        {
            log::trace!("failed to bind for either IP version");
            return Err(error);
        }

        let socket4 = socket4.ok();
        let socket6 = socket6.ok();

        // create readers
        let readers: Vec<_> = [&socket4, &socket6]
            .into_iter()
            .flatten()
            .map(StdUDPReader::new)
            .collect();

        debug_assert!(!readers.is_empty());

        // create writer
        let writer = StdUDPWriter {
            socket4: socket4.as_ref().map(clone_socket).map(Into::into),
            socket6: socket6.as_ref().map(clone_socket).map(Into::into),
        };

        // create owner
        let owner = StdUDP {
            port,
            socket4: socket4.map(Into::into),
            socket6: socket6.map(Into::into),
        };

        Ok((readers, writer, owner))
    }
}

// Trait implementations

impl Endpoint for StdEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => StdEndpoint::V4(addr),
            SocketAddr::V6(addr) => StdEndpoint::V6(addr),
        }
    }

    fn to_address(&self) -> SocketAddr {
        match self {
            StdEndpoint::V4(addr) => SocketAddr::from(*addr),
            StdEndpoint::V6(addr) => SocketAddr::from(*addr),
        }
    }
}

impl Reader<StdEndpoint> for StdUDPReader {
    type Error = io::Error;

    fn read(&self, buf: &mut [u8]) -> io::Result<(usize, StdEndpoint)> {
        let socket = match self {
            Self::V4(socket) => socket,
            Self::V6(socket) => socket,
        };

        let (len, src) = socket.recv_from(buf)?;

        Ok((len, StdEndpoint::from_address(src)))
    }
}

impl Writer<StdEndpoint> for StdUDPWriter {
    type Error = io::Error;

    fn write(&self, buf: &[u8], dst: &StdEndpoint) -> io::Result<()> {
        let src = match dst {
            StdEndpoint::V4(_) => &self.socket4,
            StdEndpoint::V6(_) => &self.socket6,
        };

        let src = match src {
            Some(src) => src,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "socket not connected for protocol",
                ));
            }
        };

        let _len = src.send_to(buf, dst.to_address())?;

        Ok(())
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
        self.port
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, value: Option<u32>) -> io::Result<()> {
        let value = value.unwrap_or(0);

        if let Some(socket) = &self.socket4 {
            SockRef::from(socket).set_mark(value)?;
        }
        if let Some(socket) = &self.socket6 {
            SockRef::from(socket).set_mark(value)?;
        }

        Ok(())
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    fn set_fwmark(&mut self, _value: Option<u32>) -> io::Result<()> {
        log::debug!("set_fwmark not available for this OS");
        Ok(())
    }
}

impl PlatformUDP for StdUDP {
    type Owner = Self;

    fn bind(port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        StdUDP::bind(port)
    }
}
