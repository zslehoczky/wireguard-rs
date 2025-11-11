use std::sync::atomic::Ordering;
use std::time::Duration;

use log::debug;

use hjul::{Runner, Timer};
use x25519_dalek::PublicKey;

use wg_traits::{tun::Tun, udp::UDP};

use crate::wireguard::WireGuard;
use crate::wireguard::constants::*;

use super::Timers;

/// Find peer based on public key and assign to variable, or call return from parent scope if
/// not found
macro_rules! fetch_peer {
    ( $wireguard_device:expr, $public_key_of_peer:expr, $peer:ident) => {
        let peers = $wireguard_device.peers.read();
        let $peer = match peers.get(&$public_key_of_peer) {
            None => {
                return;
            }
            Some(peer) => peer,
        };
    };
}

/// Find peer and timers based on public key and assign them to variables, or call return from
/// parent scope if peer not found or timers not enabled
macro_rules! fetch_peer_and_timers {
    ( $wireguard_device:expr, $public_key_of_peer:expr, $peer:ident, $timers:ident) => {
        fetch_peer!($wireguard_device, $public_key_of_peer, $peer);

        let $timers = $peer.timers();
        if !$timers.enabled {
            return;
        }
    };
}

impl Timers {
    pub fn create_retransmit_handshake_timer<T: Tun, B: UDP>(
        wireguard_device: WireGuard<T, B>,
        public_key_of_peer: PublicKey,
        runner: &Runner,
    ) -> Timer {
        runner.timer(move || {
            // create variables 'peer' and 'timers'
            fetch_peer_and_timers!(wireguard_device, public_key_of_peer, peer, timers);

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

    pub fn create_send_keepalive_timer<T: Tun, B: UDP>(
        wireguard_device: WireGuard<T, B>,
        public_key_of_peer: PublicKey,
        runner: &Runner,
    ) -> Timer {
        runner.timer(move || {
            // create variables 'peer' and 'timers'
            fetch_peer_and_timers!(wireguard_device, public_key_of_peer, peer, timers);

            // send keepalive and schedule next keepalive
            peer.send_keepalive();
            if timers.needs_another_keepalive() {
                timers.send_keepalive.start(KEEPALIVE_TIMEOUT);
            }
        })
    }

    pub fn create_new_handshake_timer<T: Tun, B: UDP>(
        wireguard_device: WireGuard<T, B>,
        public_key_of_peer: PublicKey,
        runner: &Runner,
    ) -> Timer {
        runner.timer(move || {
            // create variable 'peer'
            fetch_peer!(wireguard_device, public_key_of_peer, peer);

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

    pub fn create_zero_key_material_timer<T: Tun, B: UDP>(
        wireguard_device: WireGuard<T, B>,
        public_key_of_peer: PublicKey,
        runner: &Runner,
    ) -> Timer {
        runner.timer(move || {
            // create variable 'peer'
            fetch_peer!(wireguard_device, public_key_of_peer, peer);

            log::trace!("{} : timer fired (zero_key_material)", peer);

            // null all key-material
            peer.zero_keys();
        })
    }

    pub fn create_send_persistent_keepalive_timer<T: Tun, B: UDP>(
        wireguard_device: WireGuard<T, B>,
        public_key_of_peer: PublicKey,
        runner: &Runner,
    ) -> Timer {
        runner.timer(move || {
            // create variables 'peer' and 'timers'
            fetch_peer_and_timers!(wireguard_device, public_key_of_peer, peer, timers);

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
