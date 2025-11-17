use std::sync::atomic::Ordering;
use std::time::Duration;

use log::debug;
use x25519_dalek::PublicKey;

use wg_traits::{tun::Tun, udp::UDP};

use crate::wireguard::{WireGuard, constants::*, peer::PeerInner, router::PeerHandle};

use super::Timers;

type Peer<T, B, E, Tw, Bw> = PeerHandle<E, PeerInner<T, B>, Tw, Bw>;

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

impl Timers {
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
