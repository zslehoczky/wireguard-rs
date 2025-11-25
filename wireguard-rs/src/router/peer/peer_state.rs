use alloc::sync::Arc;

use super::KeyPair;

pub trait PeerState: Send + Sync + 'static {
    // Called after the router encrypts a transport message destined for the peer.
    // This method is called, even if the encrypted payload is empty (keepalive)
    fn send(&self, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64);

    // Called after the router successfully decrypts a transport message from a peer.
    // This method is called, even if the decrypted packet is:
    //
    // - A keepalive
    // - A malformed IP packet
    // - Fails to cryptkey route
    fn recv(&self, size: usize, sent: bool, keypair: &Arc<KeyPair>);

    // Called every time the router detects that a key is required,
    // but no valid key-material is available for the particular peer.
    //
    // The message is called continuously
    // (e.g. for every packet that must be encrypted, until a key becomes available)
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
