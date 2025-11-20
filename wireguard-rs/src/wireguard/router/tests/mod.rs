mod router_tests;

use wg_crypto as crypto;
use wg_crypto::SymKey;

use crate::wireguard::peer::KeyPair;

use super::super::tests::make_packet;
use super::{
    Callbacks, Device,
    constants::{SIZE_MESSAGE_PREFIX, message_data_len},
};
use wg_platform::dummy;

use std::time::Instant;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn pad(msg: &[u8]) -> Vec<u8> {
    let mut o = vec![0; msg.len() + SIZE_MESSAGE_PREFIX];
    o[SIZE_MESSAGE_PREFIX..SIZE_MESSAGE_PREFIX + msg.len()].copy_from_slice(msg);
    o
}

fn dummy_keypair(initiator: bool) -> KeyPair {
    let k1 = crypto::Key {
        key: SymKey::from([0x53u8; 32]),
        id: 0x646e6573,
    };
    let k2 = crypto::Key {
        key: SymKey::from([0x52u8; 32]),
        id: 0x76636572,
    };
    if initiator {
        KeyPair {
            birth: Instant::now(),
            initiator: true,
            send: k1,
            recv: k2,
        }
    } else {
        KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: k2,
            recv: k1,
        }
    }
}
