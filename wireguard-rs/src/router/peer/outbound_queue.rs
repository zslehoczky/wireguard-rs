use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{Receiver, Sender};

use crate::router::PeerDependencies;

use super::KeyPair;
use super::peer::Peer;

const QUEUE_SIZE: usize = 1024;

pub struct OutboundJob {
    buffer: Vec<u8>,
    counter: u64,
    keypair: Arc<KeyPair>,
}

impl OutboundJob {
    pub fn new(buffer: Vec<u8>, counter: u64, keypair: Arc<KeyPair>) -> Self {
        Self {
            buffer,
            counter,
            keypair,
        }
    }

    fn send<P: PeerDependencies>(&self, peer: &Peer<P>) {
        log::trace!("processing sequential send job");

        // send to peer
        let msg = &self.buffer;
        let xmit = peer.send_raw(&msg[..]).is_ok();

        // trigger callback (for timers)
        peer.get_peer_state()
            .send(msg.len(), xmit, &self.keypair, self.counter);
    }
}

fn outbound_worker<P: PeerDependencies>(
    peer: Peer<P>,
    registration_receiver: Receiver<u64>,
    job_receiver: Receiver<OutboundJob>,
) {
    let mut waiting_queue: BTreeMap<u64, Option<OutboundJob>> = BTreeMap::new();

    for job in job_receiver {
        while let Ok(registered_id) = registration_receiver.try_recv() {
            waiting_queue.insert(registered_id, None);
        }

        if let Some(entry) = waiting_queue.get_mut(&job.counter) {
            *entry = Some(job);
        }

        let mut last_processed_key: u64 = 0;

        'take_while_some: for (key, value) in waiting_queue.iter() {
            // send values until they are Some, break at the first None
            // i.e. only send values if all previously registered values have arrived

            match value {
                Some(job) => {
                    job.send(&peer);
                }
                None => {
                    break 'take_while_some;
                }
            }

            last_processed_key = *key;
        }

        waiting_queue.retain(|key, _| *key > last_processed_key);
    }
}

pub struct OutboundQueue {
    registration_sender: Sender<u64>,
    outbound_sender: Sender<OutboundJob>,

    outbound_handle: Option<JoinHandle<()>>,
}

impl OutboundQueue {
    pub fn new<P: PeerDependencies>(peer: Peer<P>) -> Self {
        let (registration_sender, registration_receiver) = crossbeam_channel::bounded(QUEUE_SIZE);

        let (collection_sender, collection_receiver) = crossbeam_channel::bounded(QUEUE_SIZE);

        let collection_handle =
            { thread::spawn(|| outbound_worker(peer, registration_receiver, collection_receiver)) };

        Self {
            registration_sender,
            outbound_sender: collection_sender,

            outbound_handle: Some(collection_handle),
        }
    }

    pub fn enqueue_job(&self, job: OutboundJob) {
        self.outbound_sender
            .send(job)
            .expect("channel should always be open");
    }

    pub fn register_counter(&self, counter: u64) {
        self.registration_sender
            .send(counter)
            .expect("channel should always be open");
    }
}

impl Drop for OutboundQueue {
    fn drop(&mut self) {
        log::trace!("SendQueue: begin drop");

        // join all worker threads
        self.outbound_handle
            .take()
            .expect("collection thread should exist until drop")
            .join()
            .unwrap();

        log::debug!("SendQueue: joined all handles");
    }
}
