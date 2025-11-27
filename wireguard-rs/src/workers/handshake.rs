use std::num::NonZeroUsize;
use std::thread::{self, ScopedJoinHandle};
use std::time::Instant;

use crossbeam_channel::Receiver;
use log::debug;
use rand::rngs::OsRng;
use x25519_dalek::PublicKey;

use wg_traits::{Endpoint, tun::Tun, udp::PlatformUDP, udp::UDP};

use crate::wireguard::WireGuard;

use super::HandshakeJob;
use super::constants::{DURATION_UNDER_LOAD, MAX_QUEUED_INCOMING_HANDSHAKES, THRESHOLD_UNDER_LOAD};

pub fn spawn_handshake_workers<'scope, 'env, T: Tun, B: PlatformUDP>(
    thread_scope: &'scope thread::Scope<'scope, 'env>,
    wireguard_device: &'env WireGuard<T, B>,
    handshake_receiver: crossbeam_channel::Receiver<HandshakeJob<B::Endpoint>>,
    n_workers: NonZeroUsize,
) -> Vec<ScopedJoinHandle<'scope, ()>> {
    (0..n_workers.get())
        .map(|_| {
            let handshake_receiver = handshake_receiver.clone();
            thread_scope.spawn(|| handshake_worker(wireguard_device, handshake_receiver))
        })
        .collect()
}

pub fn handshake_worker<T: Tun, B: UDP>(
    wireguard_device: &WireGuard<T, B>,
    rx: Receiver<HandshakeJob<B::Endpoint>>,
) {
    debug!("{} : handshake worker, started", wireguard_device);

    // process elements from the handshake queue
    for job in rx {
        // check if under load
        let mut under_load = false;
        let job: HandshakeJob<B::Endpoint> = job;
        let pending = wireguard_device.decrement_pending();
        debug_assert!(pending < MAX_QUEUED_INCOMING_HANDSHAKES + (1 << 16));

        // immediate go under load if too many handshakes pending
        if pending > THRESHOLD_UNDER_LOAD {
            log::trace!(
                "{} : handshake worker, under load (above threshold)",
                wireguard_device
            );
            wireguard_device.set_last_under_load(Instant::now());
            under_load = true;
        }

        // remain under load for DURATION_UNDER_LOAD
        if !under_load
            && DURATION_UNDER_LOAD >= wireguard_device.get_elapsed_since_last_under_load()
        {
            log::trace!(
                "{} : handshake worker, under load (recent)",
                wireguard_device
            );
            under_load = true;
        }

        // de-multiplex staged handshake jobs and handshake messages
        match job {
            HandshakeJob::Message(msg, src) => {
                handle_message(wireguard_device, msg, src, under_load)
            }
            HandshakeJob::New(pk) => handle_new(wireguard_device, pk),
        }
    }
}

fn handle_message<T: Tun, B: UDP>(
    wireguard_device: &WireGuard<T, B>,
    msg: Vec<u8>,
    mut src: <B as UDP>::Endpoint,
    under_load: bool,
) {
    let device = wireguard_device.get_crypto_device();
    match device.process(
        Instant::now(),
        &mut OsRng,
        &msg[..],
        if under_load {
            Some(src.to_address())
        } else {
            None
        },
    ) {
        Ok(output) => {
            // send response (might be cookie reply or handshake response)
            let mut resp_len: u64 = 0;
            if let Some(msg) = output.msg {
                resp_len = msg.as_ref().len() as u64;
                // TODO: consider a more elegant solution for accessing the bind
                let _ = wireguard_device
                    .send_raw(msg.as_ref(), &mut src)
                    .map_err(|e| {
                        debug!(
                            "{} : handshake worker, failed to send response, error = {}",
                            wireguard_device, e
                        );
                    });
            }

            // update peer state
            if let Some(peer) = output.id {
                // authenticated handshake packet received

                // add to rx_bytes and tx_bytes
                let req_len = msg.len() as u64;
                peer.get_peer_state().increment_rx_bytes(req_len);
                peer.get_peer_state().increment_tx_bytes(resp_len);

                // update endpoint
                peer.set_endpoint(src);

                if resp_len > 0 {
                    // update timers after sending handshake response
                    debug!(
                        "{} : handshake worker, handshake response sent",
                        wireguard_device
                    );
                    peer.get_peer_state().handshake_response_sent();
                } else {
                    // update timers after receiving handshake response
                    debug!(
                        "{} : handshake worker, handshake response was received",
                        wireguard_device
                    );
                    peer.get_peer_state().timers_handshake_complete();
                }

                // add any new keypair to peer
                if let Some(kp) = output.key_pair {
                    debug!(
                        "{} : handshake worker, new keypair for {}",
                        wireguard_device, peer
                    );

                    // this means that a handshake response was processed or sent
                    peer.get_peer_state().timers_session_derived();

                    // free any unused ids
                    for id in peer.add_keypair(kp) {
                        device.release(id);
                    }
                };
            }
        }
        Err(e) => debug!("{} : handshake worker, error = {:?}", wireguard_device, e),
    }
}

fn handle_new<T: Tun, B: UDP>(wireguard_device: &WireGuard<T, B>, public_key: PublicKey) {
    let device = wireguard_device.get_crypto_device();
    if let Some(peer) = device.get(&public_key) {
        debug!(
            "{} : handshake worker, new handshake requested for {}",
            wireguard_device, peer
        );
        let _ = device
            .begin(Instant::now(), &mut OsRng, &public_key)
            .map(|msg| {
                let _ = peer.send_raw(msg.as_ref()).map_err(|e| {
                    debug!(
                        "{} : handshake worker, failed to send handshake initiation, error = {}",
                        wireguard_device, e
                    )
                });
                peer.get_peer_state().handshake_initiation_sent();
            });
        peer.get_peer_state().reset_queued_handshake();
    }
}
