use std::sync::Arc;
use std::sync::atomic::Ordering;

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use zerocopy::{AsBytes, LayoutVerified};

use crate::router::{
    IPv4Header, IPv6Header, REJECT_AFTER_MESSAGES, SIZE_TAG, TransportHeader, VERSION_IP4,
    VERSION_IP6,
};

use super::peer::Peer;
use super::send_queue::{Job, SendJob};
use super::{KeyPair, PeerDependencies};

fn inner_length(packet: &[u8]) -> Option<usize> {
    match packet.first()? >> 4 {
        VERSION_IP4 => {
            let (header, _): (LayoutVerified<&[u8], IPv4Header>, _) =
                LayoutVerified::new_from_prefix(packet)?;

            Some(header.f_total_len.get() as usize)
        }
        VERSION_IP6 => {
            // check length and cast to IPv6 header
            let (header, _): (LayoutVerified<&[u8], IPv6Header>, _) =
                LayoutVerified::new_from_prefix(packet)?;

            Some(header.f_len.get() as usize + size_of::<IPv6Header>())
        }
        _ => None,
    }
}

pub struct TunSendJob<P: PeerDependencies> {
    buffer: Vec<u8>,
    endpoint: Option<P::UdpEndpoint>,
}

impl<P: PeerDependencies> TunSendJob<P> {
    pub fn new(buffer: Vec<u8>, endpoint: P::UdpEndpoint) -> Self {
        Self {
            buffer,
            endpoint: Some(endpoint),
        }
    }
}

impl<P: PeerDependencies> SendJob<P> for TunSendJob<P> {
    fn send(mut self, peer: &Peer<P>) {
        log::trace!("processing sequential receive job");

        let decryption_key = peer.get_decryption_key();

        // cast transport header
        let (header, packet): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
            match LayoutVerified::new_from_prefix(&mut self.buffer[..]) {
                Some(v) => v,
                None => {
                    // also covers authentication failure (will fail to parse header)
                    return;
                }
            };

        // check crypto-key router
        if packet.len() != SIZE_TAG && !peer.check_route(packet) {
            return;
        }

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
        peer.update_endpoint(self.endpoint.take());

        // check if should be written to TUN
        // (keep-alive and malformed packets will have no inner length)
        if let Some(inner) = inner_length(packet)
            && inner + SIZE_TAG <= packet.len()
        {
            peer.write_inbound(&packet[..inner]);
        }

        // trigger callback
        peer.get_peer_state()
            .recv(self.buffer.len(), true, &decryption_key.get_keypair());
    }
}

pub struct DecryptionJob<P: PeerDependencies> {
    buffer: Vec<u8>,
    endpoint: P::UdpEndpoint,
    keypair: Arc<KeyPair>,
}

impl<P: PeerDependencies> DecryptionJob<P> {
    pub fn new(buffer: Vec<u8>, endpoint: P::UdpEndpoint, keypair: Arc<KeyPair>) -> Self {
        Self {
            buffer,
            endpoint,
            keypair,
        }
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
    pub fn decrypt(mut self) -> TunSendJob<P> {
        log::trace!("processing parallel receive job");

        // process buffer
        let ok = (|| {
            // cast to header followed by payload
            let (header, packet): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
                match LayoutVerified::new_from_prefix(&mut self.buffer[..]) {
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
                UnboundKey::new(&CHACHA20_POLY1305, self.keypair.recv.key.as_ref()).unwrap(),
            );

            // attempt to open (and authenticate) the body
            match key.open_in_place(nonce, Aad::empty(), packet) {
                Ok(_) => (),
                Err(_) => return false,
            }

            // check that counter not after reject
            header.f_counter.get() < REJECT_AFTER_MESSAGES
        })();

        // remove message in case of failure:
        // to indicate failure and avoid later accidental use of unauthenticated data.
        if !ok {
            self.buffer.truncate(0);
        }

        TunSendJob::new(self.buffer, self.endpoint)
    }
}

pub enum InboundJob<P: PeerDependencies> {
    Decryption { job: DecryptionJob<P> },
}

impl<P: PeerDependencies> Job<P> for InboundJob<P> {
    type S = TunSendJob<P>;

    fn process(self) -> Self::S {
        match self {
            InboundJob::Decryption { job } => job.decrypt(),
        }
    }
}
