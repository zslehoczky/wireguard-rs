use core::fmt;
use zeroize::Zeroize;

use std::time::Instant;

use crate::aead::SymKey;

#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    pub key: SymKey,
    pub id: u32,
}

// zero key on drop
impl Drop for Key {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key {{ id = {} }}", self.id)
    }
}

#[derive(Clone)]
pub struct KeyPair {
    pub birth: Instant,  // when was the key-pair created
    pub initiator: bool, // has the key-pair been confirmed?
    pub send: Key,       // key for outbound messages
    pub recv: Key,       // key for inbound messages
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ initator = {}, age = {} secs, send = {:?}, recv = {:?}}}",
            self.initiator,
            self.birth.elapsed().as_secs(),
            self.send,
            self.recv
        )
    }
}

impl KeyPair {
    pub fn local_id(&self) -> u32 {
        self.recv.id
    }
}
