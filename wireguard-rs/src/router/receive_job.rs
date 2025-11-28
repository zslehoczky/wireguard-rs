use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use spin::Mutex;
use zerocopy::{AsBytes, LayoutVerified};

use super::constants::{REJECT_AFTER_MESSAGES, SIZE_TAG};
use super::ip::inner_length;
use super::parallel_queue::ParallelJob;
use super::peer::{Peer, PeerDependencies};
use super::sequential_queue::{SequentialJob, SequentialQueue};
use super::transport::TransportHeader;

struct Inner<P: PeerDependencies> {
    ready: AtomicBool,                                // job status
    buffer: Mutex<(Option<P::UdpEndpoint>, Vec<u8>)>, // endpoint & ciphertext buffer
    peer: Peer<P>, // decryption state (keys and replay protector)
}

pub struct ReceiveJob<P: PeerDependencies>(Arc<Inner<P>>);

impl<P: PeerDependencies> Clone for ReceiveJob<P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P: PeerDependencies> ReceiveJob<P> {
    pub fn new(buffer: Vec<u8>, endpoint: P::UdpEndpoint, peer: Peer<P>) -> Self {
        Self(Arc::new(Inner {
            ready: AtomicBool::new(false),
            buffer: Mutex::new((Some(endpoint), buffer)),
            peer,
        }))
    }
}

impl<P: PeerDependencies> ParallelJob for ReceiveJob<P> {
    fn sequential_queue(&self) -> &SequentialQueue<Self> {
        self.0.peer.get_inbound()
    }

    /* The parallel section of an incoming job:
     *
     * - Decryption.
     * - Crypto-key routing lookup.
     *
     * Note: We truncate the message buffer to 0 bytes in case of authentication failure
     * or crypto-key routing failure (attempted impersonation).
     *
     * Note: We cannot do replay protection in the parallel job,
     * since this can cause dropping of packets (leaving the window) due to scheduling.
     */
    fn parallel_work(&self) {
        debug_assert!(!self.is_ready(), "doing parallel work on completed job");
        log::trace!("processing parallel receive job");

        // decrypt
        {
            // closure for locking
            let job = &self.0;
            let peer = &job.peer;
            let mut msg = job.buffer.lock();

            // process buffer
            let ok = (|| {
                // cast to header followed by payload
                let (header, packet): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
                    match LayoutVerified::new_from_prefix(&mut msg.1[..]) {
                        Some(v) => v,
                        None => return false,
                    };

                // create nonce object
                let mut nonce = [0u8; 12];
                debug_assert_eq!(nonce.len(), CHACHA20_POLY1305.nonce_len());
                nonce[4..].copy_from_slice(header.f_counter.as_bytes());
                let nonce = Nonce::assume_unique_for_key(nonce);
                // do the weird ring AEAD dance
                let key = LessSafeKey::new(
                    UnboundKey::new(
                        &CHACHA20_POLY1305,
                        peer.get_decryption_key().get_keypair().recv.key.as_ref(),
                    )
                    .unwrap(),
                );

                // attempt to open (and authenticate) the body
                match key.open_in_place(nonce, Aad::empty(), packet) {
                    Ok(_) => (),
                    Err(_) => return false,
                }

                // check that counter not after reject
                if header.f_counter.get() >= REJECT_AFTER_MESSAGES {
                    return false;
                }

                // check crypto-key router
                packet.len() == SIZE_TAG || peer.check_route(peer, packet)
            })();

            // remove message in case of failure:
            // to indicate failure and avoid later accidental use of unauthenticated data.
            if !ok {
                msg.1.truncate(0);
            }
        };

        // mark ready
        self.0.ready.store(true, Ordering::Release);
    }
}

impl<P: PeerDependencies> SequentialJob for ReceiveJob<P> {
    fn is_ready(&self) -> bool {
        self.0.ready.load(Ordering::Acquire)
    }

    fn sequential_work(self) {
        debug_assert!(
            self.is_ready(),
            "doing sequential work on an incomplete job"
        );
        log::trace!("processing sequential receive job");

        let job = &self.0;
        let peer = &job.peer;
        let decryption_key = peer.get_decryption_key();
        let mut msg = job.buffer.lock();
        let endpoint = msg.0.take();

        // cast transport header
        let (header, packet): (LayoutVerified<&[u8], TransportHeader>, &[u8]) =
            match LayoutVerified::new_from_prefix(&msg.1[..]) {
                Some(v) => v,
                None => {
                    // also covers authentication failure (will fail to parse header)
                    return;
                }
            };

        // check for replay
        if !decryption_key.update_protector(header.f_counter.get()) {
            log::debug!("inbound worker: replay detected");
            return;
        }

        // check for confirms key
        if !decryption_key.swap_confirmed(true, Ordering::SeqCst) {
            log::debug!("inbound worker: message confirms key");
            peer.confirm_key(&decryption_key.get_keypair());
        }

        // update endpoint
        peer.update_endpoint(endpoint);

        // check if should be written to TUN
        // (keep-alive and malformed packets will have no inner length)
        if let Some(inner) = inner_length(packet)
            && inner + SIZE_TAG <= packet.len()
        {
            peer.write_inbound(&packet[..inner]);
        }

        // trigger callback
        peer.get_peer_state()
            .recv(msg.1.len(), true, &decryption_key.get_keypair());
    }
}
