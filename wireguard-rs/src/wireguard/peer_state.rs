use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use spin::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use wg_traits::{tun::Tun, udp::UDP};
use x25519_dalek::PublicKey;

use super::constants::*;
use super::timers::Timers;
use super::wireguard::WireGuard;
use super::workers::HandshakeJob;

pub struct PeerState<T: Tun, B: UDP> {
    // internal id (for logging)
    pub id: u64,

    // wireguard device state
    pub wg: WireGuard<T, B>,

    // TODO: eliminate
    pub pk: PublicKey,

    // handshake state
    pub walltime_last_handshake: Mutex<Option<SystemTime>>, // walltime for last handshake (for UAPI status)
    pub last_handshake_sent: Mutex<Instant>,                // instant for last handshake
    pub handshake_queued: AtomicBool,                       // is a handshake job currently queued?

    // stats and configuration
    pub rx_bytes: AtomicU64, // received bytes
    pub tx_bytes: AtomicU64, // transmitted bytes

    // timer model
    pub timers: RwLock<Timers>,
}

impl<T: Tun, B: UDP> PeerState<T, B> {
    /* Queue a handshake request for the parallel workers
     * (if one does not already exist)
     *
     * The function is ratelimited.
     */
    pub fn packet_send_handshake_initiation(&self) {
        log::trace!("{} : packet_send_handshake_initiation", self);

        // the function is rate limited
        {
            let mut lhs = self.last_handshake_sent.lock();
            if lhs.elapsed() < REKEY_TIMEOUT {
                log::trace!("{} : packet_send_handshake_initiation, rate-limited!", self);
                return;
            }
            *lhs = Instant::now();
        }

        // create a new handshake job for the peer
        if !self.handshake_queued.swap(true, Ordering::SeqCst) {
            self.wg.pending.fetch_add(1, Ordering::SeqCst);
            self.wg.send_to_handshake_queue(HandshakeJob::New(self.pk));
            log::trace!(
                "{} : packet_send_handshake_initiation, handshake queued",
                self
            );
        } else {
            log::trace!(
                "{} : packet_send_handshake_initiation, handshake already queued",
                self
            );
        }
    }

    #[inline(always)]
    pub fn timers(&'_ self) -> RwLockReadGuard<'_, Timers> {
        self.timers.read()
    }

    #[inline(always)]
    pub fn timers_mut(&'_ self) -> RwLockWriteGuard<'_, Timers> {
        self.timers.write()
    }

    pub fn get_keepalive_interval(&self) -> u64 {
        self.timers().get_keepalive_interval()
    }

    pub fn stop_timers(&self) {
        self.timers_mut().disable();
    }

    pub fn start_timers(&self) {
        self.timers_mut().enable();
    }

    /* should be called after an authenticated data packet is sent */
    pub fn timers_data_sent(&self) {
        self.timers().start_new_handshake_timer();
    }

    /* should be called after an authenticated data packet is received */
    pub fn timers_data_received(&self) {
        self.timers().queue_another_keepalive();
    }

    /* Should be called after any type of authenticated packet is sent, whether:
     * - keepalive
     * - data
     * - handshake
     */
    pub fn timers_any_authenticated_packet_sent(&self) {
        log::trace!("timers_any_authenticated_packet_sent");
        self.timers().stop_send_keepalive_timer();
    }

    /* Should be called after any type of authenticated packet is received, whether:
     * - keepalive
     * - data
     * - handshake
     */
    pub fn timers_any_authenticated_packet_received(&self) {
        log::trace!("timers_any_authenticated_packet_received");
        self.timers().stop_new_handshake_timer();
    }

    /* Should be called after a handshake initiation message is sent. */
    pub fn timers_handshake_initiated(&self) {
        log::trace!("timers_handshake_initiated");
        self.timers().restart_retransmit_handshake_timer();
    }

    /* Should be called after a handshake response message is received and processed
     * or when getting key confirmation via the first data message.
     */
    pub fn timers_handshake_complete(&self) {
        log::trace!("timers_handshake_complete");
        let timers_update_result = self.timers().stop_retransmit_handshake_timer();
        if timers_update_result.is_some() {
            *self.walltime_last_handshake.lock() = Some(SystemTime::now());
        }
    }

    /* Should be called after an ephemeral key is created, which is before sending a
     * handshake response or after receiving a handshake response.
     */
    pub fn timers_session_derived(&self) {
        log::trace!("timers_session_derived");
        self.timers().restart_zero_key_material_timer();
    }

    /* Should be called before a packet with authentication, whether
     * keepalive, data, or handshake is sent, or after one is received.
     */
    pub fn timers_any_authenticated_packet_traversal(&self) {
        log::trace!("timers_any_authenticated_packet_traversal");
        self.timers().push_persistent_keepalive_into_future();
    }

    /* Called after a handshake worker sends a handshake initiation to the peer
     */
    pub fn sent_handshake_initiation(&self) {
        *self.last_handshake_sent.lock() = Instant::now();
        self.timers_handshake_initiated();
        self.timers_any_authenticated_packet_traversal();
        self.timers_any_authenticated_packet_sent();
    }

    pub fn sent_handshake_response(&self) {
        *self.last_handshake_sent.lock() = Instant::now();
        self.timers_any_authenticated_packet_traversal();
        self.timers_any_authenticated_packet_sent();
    }

    pub fn set_persistent_keepalive_interval(&self, secs: u64) {
        self.timers_mut().set_persistent_keepalive_interval(secs);
    }

    pub fn packet_send_queued_handshake_initiation(&self, is_retry: bool) {
        if !is_retry {
            self.timers().reset_handshake_attempts();
        }
        self.packet_send_handshake_initiation();
    }
}
