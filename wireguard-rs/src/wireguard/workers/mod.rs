mod handshake;
mod tun;
mod udp;

pub use handshake::handshake_worker;
pub use tun::tun_worker;
pub use udp::udp_worker;

use x25519_dalek::PublicKey;

pub enum HandshakeJob<E> {
    Message(Vec<u8>, E),
    New(PublicKey),
}
