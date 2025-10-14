// #![no_std]

/* Implementation of the:
 *
 * Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
 *
 * Protocol pattern, see: http://www.noiseprotocol.org/noise.html.
 * For documentation.
 */
mod aead;
mod device;
mod keypair;
mod macs;
mod messages;
mod noise;
mod peer;
mod ratelimiter;
mod timestamp;
mod types;

#[cfg(test)]
mod tests;

use std::usize;

pub use aead::SymKey;
pub use device::Device;
pub use keypair::{Key, KeyPair};
pub use types::{Message, PSK};

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
