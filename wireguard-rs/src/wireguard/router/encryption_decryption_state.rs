use std::sync::{Arc, atomic::AtomicBool};
use std::time::Instant;

use spin::Mutex;

use wg_crypto as crypto;
use wg_traits::{Endpoint, tun, udp};

use super::anti_replay::AntiReplay;
use super::peer::Peer;
use super::types::Callbacks;

pub struct EncryptionState {
    pub(super) keypair: Arc<crypto::KeyPair<Instant>>, // keypair
    pub(super) nonce: u64,                             // next available nonce
}

pub struct DecryptionState<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    pub(super) keypair: Arc<crypto::KeyPair<Instant>>,
    pub(super) confirmed: AtomicBool,
    pub(super) protector: Mutex<AntiReplay>,
    pub(super) peer: Peer<E, C, T, B>,
}
