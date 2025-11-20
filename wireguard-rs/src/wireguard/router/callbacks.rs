use alloc::sync::Arc;

use crate::wireguard::peer::KeyPair;

pub trait Opaque: Send + Sync + 'static {}

impl<T> Opaque for T where T: Send + Sync + 'static {}

pub trait Callbacks: Send + Sync + 'static {
    type Opaque: Opaque;
    fn send(opaque: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64);
    fn recv(opaque: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>);
    fn need_key(opaque: &Self::Opaque);
    fn key_confirmed(opaque: &Self::Opaque);
}
