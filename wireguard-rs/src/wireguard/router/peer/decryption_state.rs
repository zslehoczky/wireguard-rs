use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

use spin::Mutex;

use wg_crypto as crypto;

use super::anti_replay::AntiReplay;

pub type KeyPair = crypto::KeyPair<Instant>;

pub struct DecryptionState<P> {
    keypair: Arc<KeyPair>,
    confirmed: AtomicBool,
    protector: Mutex<AntiReplay>,
    peer: P,
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

    pub fn get_keypair(&self) -> Arc<KeyPair> {
        self.keypair.clone()
    }

    pub fn swap_confirmed(&self, other: bool, order: Ordering) -> bool {
        self.confirmed.swap(other, order)
    }

    pub fn update_protector(&self, seq: u64) -> bool {
        self.protector.lock().update(seq)
    }

    pub fn get_peer(&self) -> &P {
        &self.peer
    }
}
