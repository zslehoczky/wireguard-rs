use std::num::NonZeroUsize;
use std::sync::atomic::Ordering;
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
        let pending = wireguard_device.pending.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(pending < MAX_QUEUED_INCOMING_HANDSHAKES + (1 << 16));

        // immediate go under load if too many handshakes pending
        if pending > THRESHOLD_UNDER_LOAD {
            log::trace!(
                "{} : handshake worker, under load (above threshold)",
                wireguard_device
            );
            *wireguard_device.last_under_load.lock() = Instant::now();
            under_load = true;
        }

        // remain under load for DURATION_UNDER_LOAD
        if !under_load {
            let elapsed = wireguard_device.last_under_load.lock().elapsed();
            if DURATION_UNDER_LOAD >= elapsed {
                log::trace!(
                    "{} : handshake worker, under load (recent)",
                    wireguard_device
                );
                under_load = true;
            }
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
    let device = wireguard_device.peers.read();
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
                    .router
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
                peer.opaque().rx_bytes.fetch_add(req_len, Ordering::Relaxed);
                peer.opaque()
                    .tx_bytes
                    .fetch_add(resp_len, Ordering::Relaxed);

                // update endpoint
                peer.set_endpoint(src);

                if resp_len > 0 {
                    // update timers after sending handshake response
                    debug!(
                        "{} : handshake worker, handshake response sent",
                        wireguard_device
                    );
                    peer.opaque().sent_handshake_response();
                } else {
                    // update timers after receiving handshake response
                    debug!(
                        "{} : handshake worker, handshake response was received",
                        wireguard_device
                    );
                    peer.opaque().timers_handshake_complete();
                }

                // add any new keypair to peer
                if let Some(kp) = output.key_pair {
                    debug!(
                        "{} : handshake worker, new keypair for {}",
                        wireguard_device, peer
                    );

                    // this means that a handshake response was processed or sent
                    peer.opaque().timers_session_derived();

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
    if let Some(peer) = wireguard_device.peers.read().get(&public_key) {
        debug!(
            "{} : handshake worker, new handshake requested for {}",
            wireguard_device, peer
        );
        let device = wireguard_device.peers.read();
        let _ = device
            .begin(Instant::now(), &mut OsRng, &public_key)
            .map(|msg| {
                let _ = peer.send_raw(msg.as_ref()).map_err(|e| {
                    debug!(
                        "{} : handshake worker, failed to send handshake initiation, error = {}",
                        wireguard_device, e
                    )
                });
                peer.opaque().sent_handshake_initiation();
            });
        peer.opaque()
            .handshake_queued
            .store(false, Ordering::SeqCst);
    }
}
