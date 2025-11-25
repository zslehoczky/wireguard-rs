use alloc::sync::Arc;

use super::KeyPair;

pub trait PeerState: Send + Sync + 'static {
    fn send(&self, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64);
    fn recv(&self, size: usize, sent: bool, keypair: &Arc<KeyPair>);

    fn need_key(&self);
    fn key_confirmed(&self);

    fn increment_rx_bytes(&self, by: u64) -> u64;
    fn increment_tx_bytes(&self, by: u64) -> u64;

    fn reset_queued_handshake(&self);

    fn handshake_initiation_sent(&self) {}
    fn handshake_response_sent(&self) {}

    fn timers_handshake_complete(&self) {}
    fn timers_session_derived(&self) {}
}
