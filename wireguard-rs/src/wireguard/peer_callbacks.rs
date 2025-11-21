use std::fmt;
use std::marker::PhantomData;
use std::sync::{Arc, atomic::Ordering};
use std::time::Instant;

use wg_traits::{tun::Tun, udp::UDP};

use super::constants::*;
use super::peer_state::PeerState;
use super::router::{Callbacks, KeyPair, message_data_len};

pub struct PeerCallbacks<T: Tun, B: UDP> {
    tun: PhantomData<T>,
    udp: PhantomData<B>,
}

impl<T: Tun, B: UDP> Callbacks for PeerCallbacks<T, B> {
    type Opaque = PeerState<T, B>;

    /* Called after the router encrypts a transport message destined for the peer.
     * This method is called, even if the encrypted payload is empty (keepalive)
     */
    #[inline(always)]
    fn send(peer: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64) {
        log::trace!("{} : EVENT(send)", peer);

        // update timers and stats

        peer.timers_any_authenticated_packet_traversal();
        peer.timers_any_authenticated_packet_sent();
        peer.tx_bytes.fetch_add(size as u64, Ordering::Relaxed);
        if size > message_data_len(0) && sent {
            peer.timers_data_sent();
        }

        // keep_key_fresh

        fn keep_key_fresh(keypair: &Arc<KeyPair>, counter: u64) -> bool {
            counter > REKEY_AFTER_MESSAGES
                || (keypair.initiator && Instant::now() - keypair.birth > REKEY_AFTER_TIME)
        }

        if keep_key_fresh(keypair, counter) {
            peer.packet_send_queued_handshake_initiation(false);
        }
    }

    /* Called after the router successfully decrypts a transport message from a peer.
     * This method is called, even if the decrypted packet is:
     *
     * - A keepalive
     * - A malformed IP packet
     * - Fails to cryptkey route
     */
    #[inline(always)]
    fn recv(peer: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>) {
        log::trace!("{} : EVENT(recv)", peer);

        // update timers and stats

        peer.timers_any_authenticated_packet_traversal();
        peer.timers_any_authenticated_packet_received();
        peer.rx_bytes.fetch_add(size as u64, Ordering::Relaxed);
        if size > 0 && sent {
            peer.timers_data_received();
        }

        // keep_key_fresh

        #[inline(always)]
        fn keep_key_fresh(keypair: &Arc<KeyPair>) -> bool {
            Instant::now() - keypair.birth > REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
        }

        if keep_key_fresh(keypair) && peer.timers().register_lastminute_handshake_sent() {
            peer.packet_send_queued_handshake_initiation(false);
        }
    }

    /* Called every time the router detects that a key is required,
     * but no valid key-material is available for the particular peer.
     *
     * The message is called continuously
     * (e.g. for every packet that must be encrypted, until a key becomes available)
     */
    #[inline(always)]
    fn need_key(peer: &Self::Opaque) {
        log::trace!("{} : EVENT(need_key)", peer);
        peer.packet_send_queued_handshake_initiation(false);
    }

    #[inline(always)]
    fn key_confirmed(peer: &Self::Opaque) {
        log::trace!("{} : EVENT(key_confirmed)", peer);
        peer.timers_handshake_complete();
    }
}

impl<T: Tun, B: UDP> fmt::Display for PeerState<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerState").field("id", &self.id).finish()
    }
}
