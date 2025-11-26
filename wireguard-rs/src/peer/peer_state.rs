use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime};

use log::debug;
use spin::Mutex;
use wg_traits::{tun::Tun, udp::UDP};
use x25519_dalek::PublicKey;

use crate::router::{self, KeyPair, PeerHandle, message_data_len};
use crate::wireguard::{PeerDeps, TIME_HORIZON, TimerCallbacks, WireGuard};
use crate::workers::HandshakeJob;

use super::PeerTimers;
use super::constants::{
    KEEPALIVE_TIMEOUT, MAX_TIMER_HANDSHAKES, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES,
    REKEY_AFTER_TIME, REKEY_TIMEOUT,
};
use super::timer_state::TimerState;

pub struct PeerState<T: Tun, B: UDP> {
    // internal id (for logging)
    id: u64,

    // wireguard device state
    wg: WireGuard<T, B>,

    // TODO: eliminate
    pk: PublicKey,

    // handshake state
    walltime_last_handshake: Mutex<Option<SystemTime>>, // walltime for last handshake (for UAPI status)
    last_handshake_sent: Mutex<Instant>,                // instant for last handshake
    handshake_queued: AtomicBool,                       // is a handshake job currently queued?

    // stats and configuration
    rx_bytes: AtomicU64, // received bytes
    tx_bytes: AtomicU64, // transmitted bytes

    // timer model
    timer_state: TimerState,
}

impl<T: Tun, B: UDP> PeerState<T, B> {
    pub fn new_as_arc(
        id: u64,
        wg: WireGuard<T, B>,
        pk: PublicKey,
        timers: Box<dyn PeerTimers>,
        timers_enabled: bool,
    ) -> Arc<Self> {
        let timer_state = TimerState::new(timers, timers_enabled);

        let result = Arc::new(Self {
            id,
            wg,
            pk,
            walltime_last_handshake: Mutex::new(None),
            last_handshake_sent: Mutex::new(Instant::now() - TIME_HORIZON),
            handshake_queued: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            timer_state,
        });

        result.timer_state.set_timer_callbacks(result.clone());

        result
    }

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
            self.wg.increment_pending();
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

    pub fn get_keepalive_interval(&self) -> u64 {
        self.timer_state.get_keepalive_interval()
    }

    pub fn stop_timers(&self) {
        self.timer_state.disable();
    }

    pub fn start_timers(&self) {
        self.timer_state.enable();
    }

    /* should be called after an authenticated data packet is sent */
    pub fn timers_data_sent(&self) {
        self.timer_state.start_new_handshake_timer();
    }

    /* should be called after an authenticated data packet is received */
    pub fn timers_data_received(&self) {
        self.timer_state.queue_another_keepalive();
    }

    /* Should be called after any type of authenticated packet is sent, whether:
     * - keepalive
     * - data
     * - handshake
     */
    pub fn timers_any_authenticated_packet_sent(&self) {
        log::trace!("timers_any_authenticated_packet_sent");
        self.timer_state.stop_send_keepalive_timer();
    }

    /* Should be called after any type of authenticated packet is received, whether:
     * - keepalive
     * - data
     * - handshake
     */
    pub fn timers_any_authenticated_packet_received(&self) {
        log::trace!("timers_any_authenticated_packet_received");
        self.timer_state.stop_new_handshake_timer();
    }

    /* Should be called after a handshake initiation message is sent. */
    pub fn timers_handshake_initiated(&self) {
        log::trace!("timers_handshake_initiated");
        self.timer_state.restart_retransmit_handshake_timer();
    }

    /* Should be called after a handshake response message is received and processed
     * or when getting key confirmation via the first data message.
     */
    pub fn timers_handshake_complete(&self) {
        log::trace!("timers_handshake_complete");
        let timers_update_result = self.timer_state.stop_retransmit_handshake_timer();
        if timers_update_result.is_some() {
            *self.walltime_last_handshake.lock() = Some(SystemTime::now());
        }
    }

    /* Should be called after an ephemeral key is created, which is before sending a
     * handshake response or after receiving a handshake response.
     */
    pub fn timers_session_derived(&self) {
        log::trace!("timers_session_derived");
        self.timer_state.restart_zero_key_material_timer();
    }

    /* Should be called before a packet with authentication, whether
     * keepalive, data, or handshake is sent, or after one is received.
     */
    pub fn timers_any_authenticated_packet_traversal(&self) {
        log::trace!("timers_any_authenticated_packet_traversal");
        self.timer_state.push_persistent_keepalive_into_future();
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
        self.timer_state.set_persistent_keepalive_interval(secs);
    }

    pub fn packet_send_queued_handshake_initiation(&self, is_retry: bool) {
        if !is_retry {
            self.timer_state.reset_handshake_attempts();
        }
        self.packet_send_handshake_initiation();
    }

    pub fn get_walltime_last_handshake(&self) -> Option<SystemTime> {
        *self.walltime_last_handshake.lock()
    }

    pub fn get_rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::SeqCst)
    }

    pub fn get_tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::SeqCst)
    }
}

impl<T: Tun, B: UDP> router::PeerState for PeerState<T, B> {
    fn send(&self, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64) {
        log::trace!("{} : EVENT(send)", self);

        // update timers and stats

        self.timers_any_authenticated_packet_traversal();
        self.timers_any_authenticated_packet_sent();
        self.tx_bytes.fetch_add(size as u64, Ordering::Relaxed);
        if size > message_data_len(0) && sent {
            self.timers_data_sent();
        }

        // keep_key_fresh

        fn keep_key_fresh(keypair: &Arc<KeyPair>, counter: u64) -> bool {
            counter > REKEY_AFTER_MESSAGES
                || (keypair.initiator && Instant::now() - keypair.birth > REKEY_AFTER_TIME)
        }

        if keep_key_fresh(keypair, counter) {
            self.packet_send_queued_handshake_initiation(false);
        }
    }

    fn recv(&self, size: usize, sent: bool, keypair: &Arc<KeyPair>) {
        log::trace!("{} : EVENT(recv)", self);

        // update timers and stats

        self.timers_any_authenticated_packet_traversal();
        self.timers_any_authenticated_packet_received();
        self.rx_bytes.fetch_add(size as u64, Ordering::Relaxed);
        if size > 0 && sent {
            self.timers_data_received();
        }

        // keep_key_fresh

        #[inline(always)]
        fn keep_key_fresh(keypair: &Arc<KeyPair>) -> bool {
            Instant::now() - keypair.birth > REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
        }

        if keep_key_fresh(keypair) && self.timer_state.register_lastminute_handshake_sent() {
            self.packet_send_queued_handshake_initiation(false);
        }
    }

    fn need_key(&self) {
        log::trace!("{} : EVENT(need_key)", self);
        self.packet_send_queued_handshake_initiation(false);
    }

    fn key_confirmed(&self) {
        log::trace!("{} : EVENT(key_confirmed)", self);
        self.timers_handshake_complete();
    }

    fn increment_rx_bytes(&self, req_len: u64) -> u64 {
        self.rx_bytes.fetch_add(req_len, Ordering::Relaxed)
    }

    fn increment_tx_bytes(&self, resp_len: u64) -> u64 {
        self.tx_bytes.fetch_add(resp_len, Ordering::Relaxed)
    }

    fn handshake_initiation_sent(&self) {
        self.sent_handshake_initiation()
    }

    fn handshake_response_sent(&self) {
        self.sent_handshake_response()
    }

    fn timers_handshake_complete(&self) {
        self.timers_handshake_complete()
    }

    fn timers_session_derived(&self) {
        self.timers_session_derived()
    }

    fn reset_queued_handshake(&self) {
        self.handshake_queued.store(false, Ordering::SeqCst)
    }
}

impl<T: Tun, B: UDP> fmt::Display for PeerState<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerState").field("id", &self.id).finish()
    }
}

fn call_with_peer<F, T: Tun, B: UDP>(
    wireguard_device: &WireGuard<T, B>,
    public_key_of_peer: &PublicKey,
    callback: F,
) where
    F: Fn(&PeerHandle<PeerDeps<T, B>>, &PeerState<T, B>),
{
    wireguard_device.visit_peer(public_key_of_peer, |peer_handle, peer_state| {
        callback(peer_handle, peer_state)
    });
}

fn call_with_peer_and_timers<F, T: Tun, B: UDP>(
    wireguard_device: &WireGuard<T, B>,
    public_key_of_peer: &PublicKey,
    callback: F,
) where
    F: Fn(&PeerHandle<PeerDeps<T, B>>, &PeerState<T, B>, &TimerState),
{
    call_with_peer(
        wireguard_device,
        public_key_of_peer,
        |peer_handle, peer_state| {
            let timers = &peer_state.timer_state;
            if timers.is_enabled() {
                callback(peer_handle, peer_state, timers)
            }
        },
    )
}

impl<T: Tun, B: UDP> TimerCallbacks for PeerState<T, B> {
    fn retransmit_handshake(&self) {
        call_with_peer_and_timers(
            &self.wg,
            &self.pk,
            |peer_handle, peer_state, timer_state| {
                // check if handshake attempts remaining
                let attempts = timer_state.increment_handshake_attempts();
                if attempts > MAX_TIMER_HANDSHAKES {
                    debug!(
                        "Handshake for peer {} did not complete after {} attempts, giving up",
                        peer_handle,
                        attempts + 1
                    );
                    timer_state.get_timers().send_keepalive().stop();
                    timer_state
                        .get_timers()
                        .zero_key_material()
                        .start(REJECT_AFTER_TIME * 3);
                    peer_handle.purge_staged_packets();
                } else {
                    debug!(
                        "Handshake for {} did not complete after {} seconds, retrying (try {})",
                        peer_handle,
                        REKEY_TIMEOUT.as_secs(),
                        attempts
                    );
                    timer_state
                        .get_timers()
                        .retransmit_handshake()
                        .reset(REKEY_TIMEOUT);
                    peer_handle.clear_src();
                    peer_state.packet_send_queued_handshake_initiation(true);
                }
            },
        )
    }

    fn send_keepalive(&self) {
        call_with_peer_and_timers(&self.wg, &self.pk, |peer_handle, _, timer_state| {
            // send keepalive and schedule next keepalive
            peer_handle.send_keepalive();
            if timer_state.needs_another_keepalive() {
                timer_state
                    .get_timers()
                    .send_keepalive()
                    .start(KEEPALIVE_TIMEOUT);
            }
        })
    }

    fn new_handshake(&self) {
        call_with_peer(&self.wg, &self.pk, |peer_handle, peer_state| {
            // clear source and retry
            log::debug!(
                "Retrying handshake with {} because we stopped hearing back after {} seconds",
                peer_handle,
                (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT).as_secs()
            );
            peer_handle.clear_src();
            peer_state.packet_send_queued_handshake_initiation(false);
        })
    }

    fn zero_key_material(&self) {
        call_with_peer(&self.wg, &self.pk, |peer_handle, _| {
            log::trace!("{} : timer fired (zero_key_material)", peer_handle);

            // null all key-material
            peer_handle.zero_keys();
        })
    }

    fn send_persistent_keepalive(&self) {
        call_with_peer_and_timers(&self.wg, &self.pk, |peer_handle, _, timer_state| {
            log::trace!("{} : timer fired (send_persistent_keepalive)", peer_handle);

            // send and schedule persistent keepalive
            if timer_state.get_keepalive_interval() > 0 {
                timer_state.get_timers().send_keepalive().stop();
                peer_handle.send_keepalive();
                log::trace!("{} : keepalive queued", peer_handle);
                timer_state
                    .get_timers()
                    .send_persistent_keepalive()
                    .start(Duration::from_secs(timer_state.get_keepalive_interval()));
            }
        })
    }
}
