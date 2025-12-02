use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

use spin::Mutex;

use wg_crypto as crypto;

use super::anti_replay::AntiReplay;

pub type KeyPair = crypto::KeyPair<Instant>;

pub struct DecryptionState {
    keypair: Arc<KeyPair>,
    confirmed: AtomicBool,
    protector: Mutex<AntiReplay>,
}

impl DecryptionState {
    pub fn new(keypair: Arc<KeyPair>) -> Self {
        Self {
            confirmed: AtomicBool::new(keypair.initiator),
            keypair,
            protector: spin::Mutex::new(AntiReplay::new()),
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
}
