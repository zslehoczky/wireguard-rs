use std::sync::{Arc, atomic::AtomicBool};
use std::time::Instant;

use spin::Mutex;

use wg_crypto as crypto;
use wg_traits::{Endpoint, tun, udp};

use super::anti_replay::AntiReplay;
use super::peer::Peer;
use super::types::Callbacks;

pub type KeyPair = crypto::KeyPair<Instant>;

pub struct EncryptionState {
    pub(super) keypair: Arc<KeyPair>, // keypair
    pub(super) nonce: u64,            // next available nonce
}

pub struct DecryptionState<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    pub(super) keypair: Arc<KeyPair>,
    pub(super) confirmed: AtomicBool,
    pub(super) protector: Mutex<AntiReplay>,
    pub(super) peer: Peer<E, C, T, B>,
}

impl EncryptionState {
    pub fn new(keypair: &Arc<KeyPair>) -> EncryptionState {
        EncryptionState {
            nonce: 0,
            keypair: keypair.clone(),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> DecryptionState<E, C, T, B> {
    pub fn new(peer: Peer<E, C, T, B>, keypair: &Arc<KeyPair>) -> DecryptionState<E, C, T, B> {
        DecryptionState {
            confirmed: AtomicBool::new(keypair.initiator),
            keypair: keypair.clone(),
            protector: spin::Mutex::new(AntiReplay::new()),
            peer,
        }
    }
}
