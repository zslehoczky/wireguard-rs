use std::num::NonZeroUsize;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{Receiver, Sender};

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use zerocopy::{AsBytes, LayoutVerified};

use super::KeyPair;
use super::constants::{REJECT_AFTER_MESSAGES, SIZE_TAG};
use super::peer::{OutboundJob, Peer, PeerDependencies};
use super::transport::{TYPE_TRANSPORT, TransportHeader};

pub struct EncryptionJob<P: PeerDependencies> {
    buffer: Vec<u8>,
    counter: u64,
    keypair: Arc<KeyPair>,
    peer: Peer<P>,
}

impl<P: PeerDependencies> EncryptionJob<P> {
    pub fn new(buffer: Vec<u8>, counter: u64, keypair: Arc<KeyPair>, peer: Peer<P>) -> Self {
        Self {
            buffer,
            counter,
            keypair,
            peer,
        }
    }

    fn encrypt(mut self) -> OutboundJob {
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

        OutboundJob::new(self.buffer, self.counter, self.keypair)
    }
}

fn encryption_worker<P: PeerDependencies>(receiver: Receiver<EncryptionJob<P>>) {
    loop {
        log::trace!("pool worker awaiting job");
        match receiver.recv() {
            Ok(job) => {
                let peer = job.peer.clone();
                let outbound_job = job.encrypt();
                peer.enqueue_outbound_job(outbound_job);
            }
            Err(e) => {
                log::debug!("worker stopped with {}", e);
                break;
            }
        }
    }
}

pub struct EncryptionQueue<P: PeerDependencies> {
    sender: Option<Sender<EncryptionJob<P>>>,
    handles: Vec<JoinHandle<()>>,
}

impl<P: PeerDependencies> EncryptionQueue<P> {
    pub fn new(n_workers: NonZeroUsize) -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();

        let handles: Vec<_> = (0..n_workers.get())
            .map(|_| {
                let receiver = receiver.clone();
                thread::spawn(|| encryption_worker(receiver))
            })
            .collect();

        Self {
            sender: Some(sender),
            handles,
        }
    }

    pub fn enqueue_job(&self, job: EncryptionJob<P>) {
        self.sender
            .as_ref()
            .expect("sender should exist until drop is called")
            .send(job)
            .expect("receiver should exist while sender exists");
    }
}

impl<P: PeerDependencies> Drop for EncryptionQueue<P> {
    fn drop(&mut self) {
        log::trace!("EncryptionQueue: begin drop");

        // close worker queue
        self.sender = None;

        // join all worker threads
        while let Some(handle) = self.handles.pop() {
            handle.join().unwrap();
        }

        log::debug!("EncryptionQueue: joined all handles");
    }
}
