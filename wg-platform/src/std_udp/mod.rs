use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};

use socket2::{Domain, Protocol, SockAddr, SockRef, Socket};

use wg_traits::Endpoint;
use wg_traits::udp::{Owner, PlatformUDP, Reader, UDP, Writer};

fn clone_socket(socket: &UdpSocket) -> UdpSocket {
    socket.try_clone().expect("cloning UDP sockets should work")
}

fn create_address_v4(port: u16) -> SockAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).into()
}

fn create_address_v6(port: u16) -> SockAddr {
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)).into()
}

fn create_socket(domain: Domain) -> io::Result<Socket> {
    Socket::new(domain, socket2::Type::DGRAM, Some(Protocol::UDP))
}

fn shutdown_socket(socket: &UdpSocket) -> io::Result<()> {
    SockRef::from(socket).shutdown(Shutdown::Both)
}

pub struct StdUDP {
    socket_v4: Option<UdpSocket>,
    socket_v6: Option<UdpSocket>,
}

impl StdUDP {
    fn bind_v4(port: u16) -> io::Result<Socket> {
        let socket = create_socket(Domain::IPV4)?;
        socket.set_reuse_address(true)?;
        socket.bind(&create_address_v4(port))?;
        Ok(socket)
    }

    fn bind_v6(port: u16) -> io::Result<Socket> {
        let socket = create_socket(Domain::IPV6)?;
        socket.set_reuse_address(true)?;
        socket.set_only_v6(true)?;
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

pub struct StdUDPWriter {
    socket_v4: Option<UdpSocket>,
    socket_v6: Option<UdpSocket>,
}

pub struct StdEndpoint {
    wrapped: SocketAddr,
}

// Trait implementations

impl Endpoint for StdEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        Self { wrapped: addr }
    }

    fn to_address(&self) -> SocketAddr {
        self.wrapped
    }
}

impl Reader<StdEndpoint> for StdUDPReader {
    type Error = io::Error;

    fn read(&self, buf: &mut [u8]) -> io::Result<(usize, StdEndpoint)> {
        let (len, src) = self.wrapped.recv_from(buf)?;

        Ok((len, StdEndpoint::from_address(src)))
    }
}

impl Writer<StdEndpoint> for StdUDPWriter {
    type Error = io::Error;

    fn write(&self, buf: &[u8], dst: &StdEndpoint) -> io::Result<()> {
        let src = match dst.wrapped {
            SocketAddr::V4(_) => &self.socket_v4,
            SocketAddr::V6(_) => &self.socket_v6,
        };

        let src = src.as_ref().ok_or(io::Error::new(
            io::ErrorKind::NotConnected,
            "Socket not connected for protocol",
        ))?;

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
