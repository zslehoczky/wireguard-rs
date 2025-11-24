use alloc::sync::Arc;

use super::KeyPair;

pub trait TimerState: Send + Sync + 'static {
    fn send(&self, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64);
    fn recv(&self, size: usize, sent: bool, keypair: &Arc<KeyPair>);
    fn need_key(&self);
    fn key_confirmed(&self);
}
