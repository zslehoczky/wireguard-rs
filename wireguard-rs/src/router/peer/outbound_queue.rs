use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{Receiver, Sender};

use crate::router::PeerDependencies;
use crate::router::constants::INORDER_QUEUE_SIZE;

use super::EncryptionJob;
use super::KeyPair;
use super::peer::Peer;

pub enum OutboundJob {
    Encryption { job: EncryptionJob },
}

fn create_send_job(outbound_job: OutboundJob) -> UdpSendJob {
    match outbound_job {
        OutboundJob::Encryption { job } => job.encrypt(),
    }
}

pub struct UdpSendJob {
    buffer: Vec<u8>,
    counter: u64,
    keypair: Arc<KeyPair>,
}

impl UdpSendJob {
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

fn outbound_worker<P: PeerDependencies>(peer: Peer<P>, outbound_receiver: Receiver<OutboundJob>) {
    outbound_receiver
        .iter()
        .map(create_send_job)
        .for_each(|send_job| send_job.send(&peer));
}

pub struct OutboundQueue {
    outbound_sender: Sender<OutboundJob>,

    outbound_handle: Option<JoinHandle<()>>,
}

impl OutboundQueue {
    pub fn new<P: PeerDependencies>(peer: Peer<P>) -> Self {
        let (outbound_sender, outbound_receiver) = crossbeam_channel::bounded(INORDER_QUEUE_SIZE);

        let collection_handle = { thread::spawn(|| outbound_worker(peer, outbound_receiver)) };

        Self {
            outbound_sender,

            outbound_handle: Some(collection_handle),
        }
    }

    pub fn enqueue_job(&self, job: OutboundJob) {
        self.outbound_sender
            .send(job)
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
