use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use spin::Mutex;
use zerocopy::{AsBytes, LayoutVerified};

use super::KeyPair;
use super::constants::{REJECT_AFTER_MESSAGES, SIZE_TAG};
use super::parallel_queue::ParallelJob;
use super::peer::{Peer, PeerDependencies};
use super::sequential_queue::{SequentialJob, SequentialQueue};
use super::transport::{TYPE_TRANSPORT, TransportHeader};

struct Inner<P: PeerDependencies> {
    ready: AtomicBool,
    buffer: Mutex<Vec<u8>>,
    counter: u64,
    keypair: Arc<KeyPair>,
    peer: Peer<P>,
}

pub struct SendJob<P: PeerDependencies>(Arc<Inner<P>>);

impl<P: PeerDependencies> Clone for SendJob<P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P: PeerDependencies> SendJob<P> {
    pub fn new(buffer: Vec<u8>, counter: u64, keypair: Arc<KeyPair>, peer: Peer<P>) -> Self {
        Self(Arc::new(Inner {
            buffer: Mutex::new(buffer),
            counter,
            keypair,
            peer,
            ready: AtomicBool::new(false),
        }))
    }
}

impl<P: PeerDependencies> ParallelJob for SendJob<P> {
    fn sequential_queue(&self) -> &SequentialQueue<Self> {
        self.0.peer.get_outbound()
    }

    fn parallel_work(&self) {
        debug_assert!(!self.is_ready(), "doing parallel work on completed job");
        log::trace!("processing parallel send job");

        // encrypt body
        {
            // make space for the tag
            let job = &*self.0;
            let mut msg = job.buffer.lock();
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

        // mark ready
        self.0.ready.store(true, Ordering::Release);
    }
}

impl<P: PeerDependencies> SequentialJob for SendJob<P> {
    fn is_ready(&self) -> bool {
        self.0.ready.load(Ordering::Acquire)
    }

    fn sequential_work(self) {
        debug_assert!(
            self.is_ready(),
            "doing sequential work
            on an incomplete job"
        );
        log::trace!("processing sequential send job");

        // send to peer
        let job = &self.0;
        let msg = job.buffer.lock();
        let xmit = job.peer.send_raw(&msg[..]).is_ok();

        // trigger callback (for timers)
        job.peer
            .get_peer_state()
            .send(msg.len(), xmit, &job.keypair, job.counter);
    }
}
