use std::net::SocketAddr;

pub trait Endpoint: Send + 'static {
    fn from_address(addr: SocketAddr) -> Self;
    fn to_address(&self) -> Option<SocketAddr>;
    fn clear_src(&mut self);
}
