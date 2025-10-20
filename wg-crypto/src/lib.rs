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

pub use aead::{Nonce, SymKey, Tag};
pub use device::Device;
pub use keypair::{Key, KeyPair};
pub use messages::{Initiation, Response};
pub use noise::SecretBytes;
pub use time::Instant;
pub use timestamp::{TAI64N, Timestamp};
pub use types::{Message, Output, PSK};

#[cfg(feature = "std")]
pub use timestamp::StdTimestamp;

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
