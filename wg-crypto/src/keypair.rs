use core::fmt;
use zeroize::Zeroize;

use crate::{aead::SymKey, time::Instant};

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
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("key", &self.key)
            .finish()
    }
}

#[derive(Clone)]
pub struct KeyPair<I: Instant> {
    pub birth: I,        // when was the key-pair created
    pub initiator: bool, // has the key-pair been confirmed?
    pub send: Key,       // key for outbound messages
    pub recv: Key,       // key for inbound messages
}

impl<I: Instant> fmt::Debug for KeyPair<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("initiator", &self.initiator)
            .field("birth", &self.birth)
            .field("send", &self.send)
            .field("recv", &self.recv)
            .finish()
    }
}

impl<I: Instant> KeyPair<I> {
    pub fn local_id(&self) -> u32 {
        self.recv.id
    }
}
