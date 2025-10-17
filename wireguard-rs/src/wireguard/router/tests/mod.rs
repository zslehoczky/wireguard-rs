mod bench;
mod tests;

use wg_crypto as crypto;
use wg_crypto::SymKey;

use super::SIZE_MESSAGE_PREFIX;
use super::message_data_len;
use super::{Callbacks, Device};

use super::super::dummy;
use super::super::tests::make_packet;

use std::time::Instant;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn pad(msg: &[u8]) -> Vec<u8> {
    let mut o = vec![0; msg.len() + SIZE_MESSAGE_PREFIX];
    o[SIZE_MESSAGE_PREFIX..SIZE_MESSAGE_PREFIX + msg.len()].copy_from_slice(msg);
    o
}

pub fn dummy_keypair(initiator: bool) -> crypto::KeyPair {
    let k1 = crypto::Key {
        key: SymKey::from([0x53u8; 32]),
        id: 0x646e6573,
    };
    let k2 = crypto::Key {
        key: SymKey::from([0x52u8; 32]),
        id: 0x76636572,
    };
    if initiator {
        crypto::KeyPair {
            birth: Instant::now(),
            initiator: true,
            send: k1,
            recv: k2,
        }
    } else {
        crypto::KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: k2,
            recv: k1,
        }
    }
}
