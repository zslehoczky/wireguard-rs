use alloc::sync::Arc;

use core::error::Error;
use core::fmt;

use crate::wireguard::peer::KeyPair;

pub trait Opaque: Send + Sync + 'static {}

impl<T> Opaque for T where T: Send + Sync + 'static {}

pub trait Callbacks: Send + Sync + 'static {
    type Opaque: Opaque;
    fn send(opaque: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64);
    fn recv(opaque: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>);
    fn need_key(opaque: &Self::Opaque);
    fn key_confirmed(opaque: &Self::Opaque);
}

#[derive(Debug)]
pub enum RouterError {
    NoCryptoKeyRoute,
    MalformedTransportMessage,
    UnknownReceiverId,
    NoEndpoint,
    SendError,
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouterError::NoCryptoKeyRoute => write!(f, "No cryptokey route configured for subnet"),
            RouterError::MalformedTransportMessage => write!(f, "Transport header is malformed"),
            RouterError::UnknownReceiverId => {
                write!(f, "No decryption state associated with receiver id")
            }
            RouterError::NoEndpoint => write!(f, "No endpoint for peer"),
            RouterError::SendError => write!(f, "Failed to send packet on bind"),
        }
    }
}

impl Error for RouterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "Generic Handshake Error"
    }
}
