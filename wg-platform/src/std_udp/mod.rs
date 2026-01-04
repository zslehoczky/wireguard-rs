use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};

use socket2::{SockAddr, SockRef, Socket};

use wg_traits::Endpoint;
use wg_traits::udp::{Owner, PlatformUDP, Reader, UDP, Writer};

fn clone_socket(socket: &Socket) -> Socket {
    socket.try_clone().expect("cloning UDP sockets should work")
}

pub struct StdUDP {
    port: u16,
    socket4: Option<UdpSocket>,
    socket6: Option<UdpSocket>,
}

impl Drop for StdUDP {
    fn drop(&mut self) {
        self.socket4
            .as_ref()
            .map(|socket| SockRef::from(socket).shutdown(Shutdown::Both));
        self.socket6
            .as_ref()
            .map(|socket| SockRef::from(socket).shutdown(Shutdown::Both));
    }
}

pub enum StdUDPReader {
    V4(UdpSocket),
    V6(UdpSocket),
}

pub struct StdUDPWriter {
    socket4: Option<UdpSocket>,
    socket6: Option<UdpSocket>,
}

pub enum StdEndpoint {
    V4(Option<SocketAddrV4>),
    V6(Option<SocketAddrV6>),
}

impl StdUDPReader {
    pub fn read(&self, buf: &mut [u8]) -> Result<(usize, StdEndpoint), io::Error> {
        let socket = match self {
            Self::V4(socket) => socket,
            Self::V6(socket) => socket,
        };

        let (len, src) = socket.recv_from(buf)?;

        Ok((len, StdEndpoint::from_address(src)))
    }
}

impl StdUDPWriter {
    pub fn write(&self, buf: &[u8], dst: &StdEndpoint) -> Result<(), io::Error> {
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

        if let Some(dst) = dst.to_address() {
            let _len = src.send_to(buf, dst)?;

            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "unknown destination address",
            ))
        }
    }
}

impl StdUDP {
    pub fn get_port(&self) -> u16 {
        self.port
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), io::Error> {
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
    pub fn set_fwmark(&mut self, _value: Option<u32>) -> Result<(), io::Error> {
        log::debug!("set_fwmark not implemented");
        Ok(())
    }

    pub fn bind(mut port: u16) -> Result<(Vec<StdUDPReader>, StdUDPWriter, StdUDP), io::Error> {
        log::debug!("bind to port {}", port);

        // attempt to bind on ipv6
        let address = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
        let socket6 = Socket::new(
            socket2::Domain::for_address(address),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket6.set_reuse_address(true)?;
        socket6.set_only_v6(true)?;

        let socket6 = socket6.bind(&SockAddr::from(address)).map(|_| socket6);

        if let Ok(socket6) = &socket6 {
            port = socket6
                .local_addr()?
                .as_socket_ipv6()
                .as_ref()
                .map_or(port, SocketAddrV6::port);
        }

        // attempt to bind on ipv4 on the same port
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        let socket4 = Socket::new(
            socket2::Domain::for_address(address),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket4.set_reuse_address(true)?;

        let socket4 = socket4.bind(&SockAddr::from(address)).map(|_| socket4);

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
        let mut readers = Vec::with_capacity(2);

        if let Some(socket) = &socket4 {
            readers.push(StdUDPReader::V4(clone_socket(socket).into()));
        }
        if let Some(socket) = &socket6 {
            readers.push(StdUDPReader::V6(clone_socket(socket).into()));
        }

        debug_assert!(!readers.is_empty());

        // create writer
        let writer = StdUDPWriter {
            socket4: socket4.as_ref().map(|socket| clone_socket(socket).into()),
            socket6: socket6.as_ref().map(|socket| clone_socket(socket).into()),
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
            SocketAddr::V4(addr) => StdEndpoint::V4(Some(addr)),
            SocketAddr::V6(addr) => StdEndpoint::V6(Some(addr)),
        }
    }

    fn to_address(&self) -> Option<SocketAddr> {
        match self {
            StdEndpoint::V4(addr) => addr.map(SocketAddr::from),
            StdEndpoint::V6(addr) => addr.map(SocketAddr::from),
        }
    }

    fn clear_src(&mut self) {
        match self {
            StdEndpoint::V4(addr) => {
                *addr = None;
            }
            StdEndpoint::V6(addr) => {
                *addr = None;
            }
        };
    }
}

impl Reader<StdEndpoint> for StdUDPReader {
    type Error = io::Error;

    fn read(&self, buf: &mut [u8]) -> Result<(usize, StdEndpoint), Self::Error> {
        self.read(buf)
    }
}

impl Writer<StdEndpoint> for StdUDPWriter {
    type Error = io::Error;

    fn write(&self, buf: &[u8], dst: &mut StdEndpoint) -> Result<(), Self::Error> {
        self.write(buf, dst)
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
        self.get_port()
    }

    fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), Self::Error> {
        self.set_fwmark(value)
    }
}

impl PlatformUDP for StdUDP {
    type Owner = Self;

    fn bind(port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        StdUDP::bind(port)
    }
}
