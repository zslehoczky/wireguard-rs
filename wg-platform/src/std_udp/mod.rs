use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};

use socket2::SockRef;

use wg_traits::Endpoint;
use wg_traits::udp::{Owner, PlatformUDP, Reader, UDP, Writer};

fn clone_udp_socket(socket: &UdpSocket) -> UdpSocket {
    SockRef::from(socket)
        .try_clone()
        .expect("cloning UDP sockets should work")
        .into()
}

pub struct StdUDP;

pub struct StdUDPOwner {
    port: u16,
    socket4: Option<UdpSocket>,
    socket6: Option<UdpSocket>,
}

impl Drop for StdUDPOwner {
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

impl StdUDPOwner {
    pub fn get_port(&self) -> u16 {
        self.port
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), io::Error> {
        let value = value.unwrap_or(0);

        self.socket4
            .as_ref()
            .map(|socket| SockRef::from(socket).set_mark(value))?;
        self.socket6
            .as_ref()
            .map(|socket| SockRef::from(socket).set_mark(value))
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    pub fn set_fwmark(&mut self, _value: Option<u32>) -> Result<(), io::Error> {
        Ok(())
    }
}

impl StdUDP {
    pub fn bind(
        mut port: u16,
    ) -> Result<(Vec<StdUDPReader>, StdUDPWriter, StdUDPOwner), io::Error> {
        log::debug!("bind to port {}", port);

        // attempt to bind on ipv6
        let socket6 = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));

        if let Ok(socket6) = &socket6 {
            let sockref6 = SockRef::from(&socket6);
            sockref6.set_reuse_address(true)?;
            sockref6.set_only_v6(true)?;

            port = socket6.local_addr()?.port();
        }

        // attempt to bind on ipv4 on the same port
        let socket4 = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));

        if let Ok(socket4) = &socket4 {
            let sockref4 = SockRef::from(&socket4);
            sockref4.set_reuse_address(true)?;

            port = socket4.local_addr()?.port();
        }

        // check if failed to bind on both
        if socket4.is_err()
            && let Err(err6) = socket6
        {
            log::trace!("failed to bind for either IP version");
            return Err(err6);
        }

        let socket4 = socket4.ok();
        let socket6 = socket6.ok();

        // create readers
        let mut readers = Vec::with_capacity(2);

        if let Some(socket) = &socket4 {
            readers.push(StdUDPReader::V4(clone_udp_socket(socket)));
        }
        if let Some(socket) = &socket6 {
            readers.push(StdUDPReader::V6(clone_udp_socket(socket)));
        }

        debug_assert!(!readers.is_empty());

        // create writer
        let writer = StdUDPWriter {
            socket4: socket4.as_ref().map(clone_udp_socket),
            socket6: socket6.as_ref().map(clone_udp_socket),
        };

        // create owner
        let owner = StdUDPOwner {
            port,
            socket4,
            socket6,
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

impl Owner for StdUDPOwner {
    type Error = io::Error;

    fn get_port(&self) -> u16 {
        self.get_port()
    }

    fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), Self::Error> {
        self.set_fwmark(value)
    }
}

impl PlatformUDP for StdUDP {
    type Owner = StdUDPOwner;

    fn bind(port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        StdUDP::bind(port)
    }
}
