use alloc::sync::Arc;

use super::KeyPair;

pub trait Callbacks: Send + Sync + 'static {
    type Opaque: Send + Sync + 'static;
    fn send(opaque: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64);
    fn recv(opaque: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>);
    fn need_key(opaque: &Self::Opaque);
    fn key_confirmed(opaque: &Self::Opaque);
}
