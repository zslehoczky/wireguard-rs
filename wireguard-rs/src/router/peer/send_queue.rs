use rayon::prelude::*;

use std::marker::PhantomData;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{self, Receiver, Sender};

use crate::router::PeerDependencies;
use crate::router::constants::INORDER_QUEUE_SIZE;

use super::peer::Peer;

pub trait SendJob<P: PeerDependencies>: Send + Sync + 'static {
    fn send(self, peer: &Peer<P>);
}

pub trait Job<P: PeerDependencies>: Send + Sync + 'static {
    type S: SendJob<P>;

    fn process(self) -> Self::S;
}

fn create_channel<T>(size: usize) -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = crossbeam_channel::bounded(size);

    (sender, receiver)
}

fn send_worker<P: PeerDependencies, J: Job<P>>(peer: Peer<P>, outbound_receiver: Receiver<J>) {
    let mut queue = Vec::new();

    for job in &outbound_receiver {
        queue.push(job);

        while let Ok(job) = outbound_receiver.try_recv() {
            queue.push(job);
        }

        for send_job_vec in queue.par_drain(..).map(Job::process).collect_vec_list() {
            for send_job in send_job_vec {
                send_job.send(&peer);
            }
        }
    }
}

pub struct SendQueue<P: PeerDependencies, J: Job<P>> {
    peer_deps: PhantomData<P>,
    job_sender: Option<Sender<J>>,
    worker_handle: Option<JoinHandle<()>>,
}

impl<P: PeerDependencies, J: Job<P>> SendQueue<P, J> {
    pub fn new(peer: Peer<P>) -> Self {
        let (job_sender, job_receiver) = create_channel(INORDER_QUEUE_SIZE);

        let worker_handle = { thread::spawn(|| send_worker(peer, job_receiver)) };

        Self {
            peer_deps: PhantomData,
            job_sender: Some(job_sender),
            worker_handle: Some(worker_handle),
        }
    }

    pub fn enqueue_job(&self, job: J) {
        self.job_sender
            .as_ref()
            .expect("sender should always exist")
            .send(job)
            .expect("channel should always be open");
    }
}

impl<P: PeerDependencies, J: Job<P>> Drop for SendQueue<P, J> {
    fn drop(&mut self) {
        log::trace!("SendQueue: begin drop");

        self.job_sender = None;

        // join all worker threads
        self.worker_handle
            .take()
            .expect("collection thread should exist until drop")
            .join()
            .unwrap();

        log::debug!("SendQueue: joined all handles");
    }
}
