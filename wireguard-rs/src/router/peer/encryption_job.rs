use std::sync::Arc;

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use zerocopy::{AsBytes, LayoutVerified};

use crate::router::constants::{REJECT_AFTER_MESSAGES, SIZE_TAG};
use crate::router::transport::{TYPE_TRANSPORT, TransportHeader};

use super::KeyPair;
use super::outbound_queue::UdpSendJob;

pub struct EncryptionJob {
    buffer: Vec<u8>,
    counter: u64,
    keypair: Arc<KeyPair>,
}

impl EncryptionJob {
    pub fn new(buffer: Vec<u8>, counter: u64, keypair: Arc<KeyPair>) -> Self {
        Self {
            buffer,
            counter,
            keypair,
        }
    }

    pub fn encrypt(mut self) -> UdpSendJob {
        log::trace!("processing parallel send job");

        // encrypt body
        {
            // make space for the tag
            let job = &mut self;
            let msg = &mut job.buffer;
            msg.extend([0u8; SIZE_TAG].iter());

            // cast to header (should never fail)
            let (mut header, packet): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
                LayoutVerified::new_from_prefix(&mut msg[..])
                    .expect("earlier code should ensure that there is ample space");

            // set header fields
            debug_assert!(
                job.counter < REJECT_AFTER_MESSAGES,
                "should be checked when assigning counters"
            );
            header.f_type.set(TYPE_TRANSPORT);
            header.f_receiver.set(job.keypair.send.id);
            header.f_counter.set(job.counter);

            // create a nonce object
            let mut nonce = [0u8; 12];
            debug_assert_eq!(nonce.len(), CHACHA20_POLY1305.nonce_len());
            nonce[4..].copy_from_slice(header.f_counter.as_bytes());
            let nonce = Nonce::assume_unique_for_key(nonce);

            // encrypt contents of transport message in-place
            let tag_offset = packet.len() - SIZE_TAG;
            let key = LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, job.keypair.send.key.as_ref()).unwrap(),
            );
            let tag = key
                .seal_in_place_separate_tag(nonce, Aad::empty(), &mut packet[..tag_offset])
                .unwrap();

            // append tag
            packet[tag_offset..].copy_from_slice(tag.as_ref());
        }

        UdpSendJob::new(self.buffer, self.counter, self.keypair)
    }
}
