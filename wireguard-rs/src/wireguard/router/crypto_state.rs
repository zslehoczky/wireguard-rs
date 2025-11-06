use std::sync::{Arc, atomic::AtomicBool};
use std::time::Instant;

use spin::Mutex;

use wg_crypto as crypto;

use super::anti_replay::AntiReplay;

pub type KeyPair = crypto::KeyPair<Instant>;

pub fn crypto_state<P>(peer: P, keypair: Arc<KeyPair>) -> (EncryptionState, DecryptionState<P>) {
    (
        EncryptionState::new(keypair.clone()),
        DecryptionState::new(peer, keypair),
    )
}

pub struct EncryptionState {
    pub(super) keypair: Arc<KeyPair>, // keypair
    pub(super) nonce: u64,            // next available nonce
}

pub struct DecryptionState<P> {
    pub(super) keypair: Arc<KeyPair>,
    pub(super) confirmed: AtomicBool,
    pub(super) protector: Mutex<AntiReplay>,
    pub(super) peer: P,
}

impl EncryptionState {
    pub fn new(keypair: Arc<KeyPair>) -> Self {
        Self { nonce: 0, keypair }
    }
}

impl<P> DecryptionState<P> {
    pub fn new(peer: P, keypair: Arc<KeyPair>) -> Self {
        Self {
            confirmed: AtomicBool::new(keypair.initiator),
            keypair,
            protector: spin::Mutex::new(AntiReplay::new()),
            peer,
        }
    }
}
