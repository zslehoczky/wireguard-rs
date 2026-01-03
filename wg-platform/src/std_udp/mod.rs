use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::{Arc, Weak};

use socket2::SockRef;

use wg_traits::Endpoint;
use wg_traits::udp::{Owner, PlatformUDP, Reader, UDP, Writer};

pub struct StdUDP;

pub struct StdUDPOwner {
    port: u16,
    _sock4: Option<Arc<UdpSocket>>,
    _sock6: Option<Arc<UdpSocket>>,
}

pub enum StdUDPReader {
    V4(Weak<UdpSocket>),
    V6(Weak<UdpSocket>),
}

#[derive(Clone)]
pub struct StdUDPWriter {
    sock4: Weak<UdpSocket>,
    sock6: Weak<UdpSocket>,
}

pub enum StdEndpoint {
    V4(Option<SocketAddrV4>),
    V6(Option<SocketAddrV6>),
}

impl StdEndpoint {
    pub fn from_address(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => StdEndpoint::V4(Some(addr)),
            SocketAddr::V6(addr) => StdEndpoint::V6(Some(addr)),
        }
    }

    pub fn to_address(&self) -> SocketAddr {
        match self {
            StdEndpoint::V4(addr) => {
                SocketAddr::from(addr.unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
            }
            StdEndpoint::V6(addr) => {
                SocketAddr::from(addr.unwrap_or(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))
            }
        }
    }

    pub fn clear_src(&mut self) {
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

impl StdUDPReader {
    pub fn read(&self, buf: &mut [u8]) -> Result<(usize, StdEndpoint), io::Error> {
        let socket = match self {
            Self::V4(socket) => match socket.upgrade() {
                Some(socket) => socket,
                None => {
                    return Ok((0, StdEndpoint::V4(None)));
                }
            },
            Self::V6(socket) => match socket.upgrade() {
                Some(socket) => socket,
                None => {
                    return Ok((0, StdEndpoint::V6(None)));
                }
            },
        };

        let (len, src) = socket.recv_from(buf)?;

        Ok((len, StdEndpoint::from_address(src)))
    }
}

impl StdUDPWriter {
    pub fn write(&self, buf: &[u8], dst: &StdEndpoint) -> Result<(), io::Error> {
        let src = match dst.to_address() {
            SocketAddr::V4(_) => &self.sock4,
            SocketAddr::V6(_) => &self.sock6,
        };

        let src = match src.upgrade() {
            Some(src) => src,
            None => return Ok(()),
        };

        let _len = src.send_to(buf, dst.to_address())?;

        Ok(())
    }
}

impl StdUDPOwner {
    pub fn get_port(&self) -> u16 {
        self.port
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), io::Error> {
        let value = value.unwrap_or(0);

        self.sock4
            .as_ref()
            .map(|socket| SockRef::from(socket).set_mark(value))?;
        self.sock6
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

        let sock4 = socket4.ok().map(Arc::new);
        let sock6 = socket6.ok().map(Arc::new);

        // create readers
        let readers: Vec<StdUDPReader> = vec![
            StdUDPReader::V4(sock4.as_ref().map(Arc::downgrade).unwrap_or_default()),
            StdUDPReader::V6(sock6.as_ref().map(Arc::downgrade).unwrap_or_default()),
        ];

        debug_assert_eq!(readers.len(), 2);

        // create writer
        let writer = StdUDPWriter {
            sock4: sock4.as_ref().map(Arc::downgrade).unwrap_or_default(),
            sock6: sock6.as_ref().map(Arc::downgrade).unwrap_or_default(),
        };

        // create owner
        let owner = StdUDPOwner {
            port,
            _sock4: sock4,
            _sock6: sock6,
        };

        Ok((readers, writer, owner))
    }
}

// Trait implementations

impl Endpoint for StdEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        StdEndpoint::from_address(addr)
    }

    fn to_address(&self) -> SocketAddr {
        self.to_address()
    }

    fn clear_src(&mut self) {
        self.clear_src()
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
