//! Implementation of the
//! Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
//! Protocol pattern
//!
//! See: http://www.noiseprotocol.org/noise.html.
//! For documentation.
#![cfg_attr(not(test), no_std)]

mod aead;
mod device;
mod keypair;
mod macs;
mod messages;
mod noise;
mod peer;
mod ratelimiter;
mod time;
mod timestamp;
mod types;

#[cfg(feature = "std")]
extern crate std;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, AsBytes, FromBytes, PartialOrd, Ord, Default)]
#[repr(transparent)]
struct PublicKey([u8; 32]);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[derive(Clone, Eq, Hash, AsBytes, FromBytes, ZeroizeOnDrop)]
#[repr(transparent)]
struct SecretKey([u8; 32]);

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[derive(Clone, AsBytes, FromBytes, ZeroizeOnDrop)]
#[repr(transparent)]
struct SharedSecret([u8; 32]);

impl AsRef<[u8; 32]> for SharedSecret {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl SecretKey {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        SecretKey(key)
    }

    pub fn dh(&self, pk: &PublicKey) -> Result<SharedSecret, HandshakeError> {
        let ss = x25519_dalek::x25519(self.0, pk.0);
        if ss.ct_eq(&[0u8; 32]).into() {
            Err(HandshakeError::InvalidSharedSecret)
        } else {
            Ok(SharedSecret(ss))
        }
    }

    pub fn pk(&self) -> PublicKey {
        PublicKey(x25519_dalek::x25519(self.0, X25519_BASEPOINT_BYTES))
    }
}

trait Instance: Sized {
    type Instant: Instant;
    type Timestamp: Timestamp;

    fn get(&self, pk: &PublicKey) -> Option<&Peer<Self>>;

    fn get_mut(&mut self, pk: &PublicKey) -> Option<&mut Peer<Self>>;
}

pub use aead::{Nonce, SymKey, Tag};
pub use device::Device;
pub use keypair::{Key, KeyPair};
pub use messages::{Initiation, Response};
pub use noise::SecretBytes;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
pub use time::Instant;
pub use timestamp::{TAI64N, Timestamp};
pub use types::{Message, Output, PSK};

#[cfg(feature = "std")]
pub use timestamp::StdTimestamp;
use x25519_dalek::X25519_BASEPOINT_BYTES;
use zerocopy::{AsBytes, FromBytes};
use zeroize::ZeroizeOnDrop;

use crate::{peer::Peer, types::HandshakeError};

const fn max3(a: usize, b: usize, c: usize) -> usize {
    const fn max(a: usize, b: usize) -> usize {
        if a > b { a } else { b }
    }
    max(max(a, b), c)
}

pub const MAX_HANDSHAKE_MSG_SIZE: usize = max3(
    core::mem::size_of::<messages::Initiation>(),
    core::mem::size_of::<messages::Response>(),
    core::mem::size_of::<messages::CookieReply>(),
);
