use byteorder::LittleEndian;
use zerocopy::{AsBytes, FromBytes, U32};

use crate::messages::{self};
use crate::noise::SecretBytes;
use crate::time::Instant;

use super::keypair::KeyPair;

use core::error::Error;
use core::fmt;

#[derive(Clone, Copy, AsBytes, FromBytes, PartialEq, Eq, Hash)]
#[repr(C, packed)]
pub struct Identifier(U32<LittleEndian>);

impl core::fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id(0x{:08x})", self.0.get())
    }
}

impl From<u32> for Identifier {
    fn from(id: u32) -> Self {
        Identifier(U32::new(id))
    }
}

#[derive(Debug)]
pub enum Message {
    Initiation(messages::Initiation),
    Response(messages::Response),
    CookieReply(messages::CookieReply),
}

impl From<messages::Initiation> for Message {
    fn from(initiation: messages::Initiation) -> Self {
        Message::Initiation(initiation)
    }
}

impl From<messages::Response> for Message {
    fn from(response: messages::Response) -> Self {
        Message::Response(response)
    }
}

impl From<messages::CookieReply> for Message {
    fn from(cookie_reply: messages::CookieReply) -> Self {
        Message::CookieReply(cookie_reply)
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        match self {
            Message::Initiation(initiation) => initiation.as_bytes(),
            Message::Response(response) => response.as_bytes(),
            Message::CookieReply(cookie_reply) => cookie_reply.as_bytes(),
        }
    }
}

/* Internal types for the noise IKpsk2 implementation */

#[derive(Debug)]
pub enum ConfigError {
    TooManyPeers,
    PeerMatchesDevice,
    NoSuchPublicKey,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::TooManyPeers => write!(f, "Too many peers"),
            ConfigError::PeerMatchesDevice => write!(f, "Peer matches device"),
            ConfigError::NoSuchPublicKey => write!(f, "No such public key"),
        }
    }
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        "empty"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug)]
pub enum HandshakeError {
    EncryptionFailure,
    DecryptionFailure,
    UnknownPublicKey,
    UnknownReceiverId,
    InvalidMessageFormat,
    InvalidSharedSecret,
    OldTimestamp,
    InvalidState,
    InvalidMac1,
    RateLimited,
    InitiationFlood,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::EncryptionFailure => write!(f, "Failed to AEAD:SEAL"),
            HandshakeError::DecryptionFailure => write!(f, "Failed to AEAD:OPEN"),
            HandshakeError::InvalidSharedSecret => write!(f, "Zero shared secret"),
            HandshakeError::UnknownPublicKey => write!(f, "Unknown public key"),
            HandshakeError::UnknownReceiverId => {
                write!(f, "Receiver id not allocated to any handshake")
            }
            HandshakeError::InvalidMessageFormat => write!(f, "Invalid handshake message format"),
            HandshakeError::OldTimestamp => write!(f, "Timestamp is less/equal to the newest"),
            HandshakeError::InvalidState => write!(f, "Message does not apply to handshake state"),
            HandshakeError::InvalidMac1 => write!(f, "Message has invalid mac1 field"),
            HandshakeError::RateLimited => write!(f, "Message was dropped by rate limiter"),
            HandshakeError::InitiationFlood => {
                write!(f, "Message was dropped because of initiation flood")
            }
        }
    }
}

impl Error for HandshakeError {
    fn description(&self) -> &str {
        "Generic Handshake Error"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

pub struct Output<I: Instant> {
    pub msg: Option<Message>,
    pub key_pair: Option<KeyPair<I>>,
}

#[allow(clippy::upper_case_acronyms)]
pub type PSK = SecretBytes<32>;
