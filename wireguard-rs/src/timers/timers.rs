use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use hjul::Timer;
use log::debug;
use x25519_dalek::PublicKey;

use wg_traits::{tun::Tun, udp::UDP};

use crate::router::PeerHandle;
use crate::wireguard::WireGuard;

use super::constants::{KEEPALIVE_TIMEOUT, MAX_TIMER_HANDSHAKES, REJECT_AFTER_TIME, REKEY_TIMEOUT};
use super::peer_callbacks::PeerCallbacks;

type Peer<T, B, E, Tw, Bw> = PeerHandle<E, PeerCallbacks<T, B>, Tw, Bw>;

fn call_with_peer<F, T: Tun, B: UDP>(
    wireguard_device: &WireGuard<T, B>,
    public_key_of_peer: &PublicKey,
    callback: F,
) where
    F: Fn(&Peer<T, B, B::Endpoint, T::Writer, B::Writer>),
{
    let peers = wireguard_device.peers.read();
    if let Some(peer) = peers.get(public_key_of_peer) {
        callback(peer)
    }
}

fn call_with_peer_and_timers<F, T: Tun, B: UDP>(
    wireguard_device: &WireGuard<T, B>,
    public_key_of_peer: &PublicKey,
    callback: F,
) where
    F: Fn(&Peer<T, B, B::Endpoint, T::Writer, B::Writer>, &Timers),
{
    call_with_peer(wireguard_device, public_key_of_peer, |peer| {
        let timers = peer.timers();
        if timers.enabled {
            callback(peer, &timers)
        }
    })
}

pub struct Timers {
    // only updated during configuration
    enabled: bool,
    keepalive_interval: u64,

    handshake_attempts: AtomicUsize,
    sent_lastminute_handshake: AtomicBool,
    need_another_keepalive: AtomicBool,

    retransmit_handshake: Timer,
    send_keepalive: Timer,
    send_persistent_keepalive: Timer,
    zero_key_material: Timer,
    new_handshake: Timer,
}

impl Timers {
    #[inline(always)]
    pub fn needs_another_keepalive(&self) -> bool {
        self.need_another_keepalive.swap(false, Ordering::SeqCst)
    }

    pub fn new<T: Tun, B: UDP>(
        wireguard_device: &WireGuard<T, B>,
        public_key_of_peer: &PublicKey,
        timers_started: bool,
    ) -> Timers {
        let runner = wireguard_device.runner.lock();

        let spawn_timer = |callback: fn(&WireGuard<T, B>, &PublicKey)| {
            let wireguard_device = wireguard_device.clone();
            let public_key_of_peer = *public_key_of_peer;

            runner.timer(move || callback(&wireguard_device, &public_key_of_peer))
        };

        // create a timer instance for the provided peer
        Timers {
            enabled: timers_started,
            keepalive_interval: 0, // disabled
            need_another_keepalive: AtomicBool::new(false),
            sent_lastminute_handshake: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: spawn_timer(Self::retransmit_handshake),
            send_keepalive: spawn_timer(Self::send_keepalive),
            new_handshake: spawn_timer(Self::new_handshake),
            zero_key_material: spawn_timer(Self::zero_key_material),
            send_persistent_keepalive: spawn_timer(Self::send_persistent_keepalive),
        }
    }

    pub fn get_keepalive_interval(&self) -> u64 {
        self.keepalive_interval
    }

    pub fn enable(&mut self) {
        // set flag to reenable timer events
        if self.enabled {
            return;
        }
        self.enabled = true;

        // start send_persistent_keepalive
        if self.keepalive_interval > 0 {
            self.send_persistent_keepalive.start(Duration::from_secs(0));
        }
    }

    pub fn disable(&mut self) {
        // set flag to prevent future timer events
        if !self.enabled {
            return;
        }
        self.enabled = false;

        // stop all pending timers
        self.retransmit_handshake.stop();
        self.send_keepalive.stop();
        self.send_persistent_keepalive.stop();
        self.zero_key_material.stop();
        self.new_handshake.stop();

        // reset all timer state
        self.handshake_attempts.store(0, Ordering::SeqCst);
        self.sent_lastminute_handshake
            .store(false, Ordering::SeqCst);
        self.need_another_keepalive.store(false, Ordering::SeqCst);
    }

    pub fn start_new_handshake_timer(&self) {
        if self.enabled {
            self.new_handshake.start(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
        }
    }

    pub fn queue_another_keepalive(&self) {
        if self.enabled && !self.send_keepalive.start(KEEPALIVE_TIMEOUT) {
            self.need_another_keepalive.store(true, Ordering::SeqCst)
        }
    }

    pub fn stop_send_keepalive_timer(&self) {
        if self.enabled {
            self.send_keepalive.stop()
        }
    }

    pub fn stop_new_handshake_timer(&self) {
        if self.enabled {
            self.new_handshake.stop();
        }
    }

    pub fn restart_retransmit_handshake_timer(&self) {
        if self.enabled {
            self.send_keepalive.stop();
            self.retransmit_handshake.reset(REKEY_TIMEOUT);
        }
    }

    /// Return Some(()) if timers are enabled, None otherwise
    pub fn stop_retransmit_handshake_timer(&self) -> Option<()> {
        if self.enabled {
            self.retransmit_handshake.stop();
            self.handshake_attempts.store(0, Ordering::SeqCst);
            self.sent_lastminute_handshake
                .store(false, Ordering::SeqCst);

            return Some(());
        }

        None
    }

    pub fn restart_zero_key_material_timer(&self) {
        if self.enabled {
            self.zero_key_material.reset(REJECT_AFTER_TIME * 3);
        }
    }

    pub fn push_persistent_keepalive_into_future(&self) {
        if self.enabled && self.keepalive_interval > 0 {
            self.send_persistent_keepalive
                .reset(Duration::from_secs(self.keepalive_interval));
        }
    }

    pub fn set_persistent_keepalive_interval(&mut self, secs: u64) {
        // update the stored keepalive_interval
        self.keepalive_interval = secs;

        // stop the keepalive timer with the old interval
        self.send_persistent_keepalive.stop();

        // cause immediate expiry of persistent_keepalive timer
        if secs > 0 && self.enabled {
            self.send_persistent_keepalive.reset(Duration::from_secs(0));
        }
    }

    pub fn reset_handshake_attempts(&self) {
        self.handshake_attempts.store(0, Ordering::SeqCst);
    }

    /// Return true if the event hasn't been registered before this call, otherwise false
    pub fn register_lastminute_handshake_sent(&self) -> bool {
        !self.sent_lastminute_handshake.swap(true, Ordering::Acquire)
    }

    pub fn retransmit_handshake<T: Tun, B: UDP>(
        wireguard_device: &WireGuard<T, B>,
        public_key_of_peer: &PublicKey,
    ) {
        call_with_peer_and_timers(wireguard_device, public_key_of_peer, |peer, timers| {
            // check if handshake attempts remaining
            let attempts = timers.handshake_attempts.fetch_add(1, Ordering::SeqCst);
            if attempts > MAX_TIMER_HANDSHAKES {
                debug!(
                    "Handshake for peer {} did not complete after {} attempts, giving up",
                    peer,
                    attempts + 1
                );
                timers.send_keepalive.stop();
                timers.zero_key_material.start(REJECT_AFTER_TIME * 3);
                peer.purge_staged_packets();
            } else {
                debug!(
                    "Handshake for {} did not complete after {} seconds, retrying (try {})",
                    peer,
                    REKEY_TIMEOUT.as_secs(),
                    attempts
                );
                timers.retransmit_handshake.reset(REKEY_TIMEOUT);
                peer.clear_src();
                peer.packet_send_queued_handshake_initiation(true);
            }
        })
    }

    pub fn send_keepalive<T: Tun, B: UDP>(
        wireguard_device: &WireGuard<T, B>,
        public_key_of_peer: &PublicKey,
    ) {
        call_with_peer_and_timers(wireguard_device, public_key_of_peer, |peer, timers| {
            // send keepalive and schedule next keepalive
            peer.send_keepalive();
            if timers.needs_another_keepalive() {
                timers.send_keepalive.start(KEEPALIVE_TIMEOUT);
            }
        })
    }

    pub fn new_handshake<T: Tun, B: UDP>(
        wireguard_device: &WireGuard<T, B>,
        public_key_of_peer: &PublicKey,
    ) {
        call_with_peer(wireguard_device, public_key_of_peer, |peer| {
            // clear source and retry
            log::debug!(
                "Retrying handshake with {} because we stopped hearing back after {} seconds",
                peer,
                (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT).as_secs()
            );
            peer.clear_src();
            peer.packet_send_queued_handshake_initiation(false);
        })
    }

    pub fn zero_key_material<T: Tun, B: UDP>(
        wireguard_device: &WireGuard<T, B>,
        public_key_of_peer: &PublicKey,
    ) {
        call_with_peer(wireguard_device, public_key_of_peer, |peer| {
            log::trace!("{} : timer fired (zero_key_material)", peer);

            // null all key-material
            peer.zero_keys();
        })
    }

    pub fn send_persistent_keepalive<T: Tun, B: UDP>(
        wireguard_device: &WireGuard<T, B>,
        public_key_of_peer: &PublicKey,
    ) {
        call_with_peer_and_timers(wireguard_device, public_key_of_peer, |peer, timers| {
            log::trace!("{} : timer fired (send_persistent_keepalive)", peer);

            // send and schedule persistent keepalive
            if timers.keepalive_interval > 0 {
                timers.send_keepalive.stop();
                peer.send_keepalive();
                log::trace!("{} : keepalive queued", peer);
                timers
                    .send_persistent_keepalive
                    .start(Duration::from_secs(timers.keepalive_interval));
            }
        })
    }
}
