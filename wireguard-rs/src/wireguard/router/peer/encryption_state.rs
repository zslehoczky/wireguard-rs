use std::sync::Arc;
use std::time::Instant;

use wg_crypto as crypto;

pub type KeyPair = crypto::KeyPair<Instant>;

pub struct EncryptionState {
    keypair: Arc<KeyPair>, // keypair
    nonce: u64,            // next available nonce
}

impl EncryptionState {
    pub fn new(keypair: Arc<KeyPair>) -> Self {
        Self { nonce: 0, keypair }
    }

    pub fn get_keypair(&self) -> Arc<KeyPair> {
        self.keypair.clone()
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn increment_nonce(&mut self) {
        self.nonce += 1
    }
}
