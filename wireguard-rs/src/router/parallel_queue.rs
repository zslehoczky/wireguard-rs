pub use std::num::NonZeroUsize;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{Receiver, Sender, bounded};

use super::peer::PeerDependencies;
use super::receive_job::ReceiveJob;
use super::send_job::SendJob;
use super::sequential_queue::{SequentialJob, SequentialQueue};

pub trait ParallelJob: Sized + SequentialJob {
    fn sequential_queue(&self) -> &SequentialQueue<Self>;

    fn parallel_work(&self);
}

pub enum ParallelJobUnion<P: PeerDependencies> {
    Outbound(SendJob<P>),
    Inbound(ReceiveJob<P>),
}

fn parallel_worker<P: PeerDependencies>(receiver: Receiver<ParallelJobUnion<P>>) {
    loop {
        log::trace!("pool worker awaiting job");
        match receiver.recv() {
            Err(e) => {
                log::debug!("worker stopped with {}", e);
                break;
            }
            Ok(ParallelJobUnion::Inbound(job)) => {
                job.parallel_work();
                job.sequential_queue().consume();
            }
            Ok(ParallelJobUnion::Outbound(job)) => {
                job.parallel_work();
                job.sequential_queue().consume();
            }
        }
    }
}

pub struct ParallelQueue<P: PeerDependencies> {
    sender: Option<Sender<ParallelJobUnion<P>>>,
    handles: Vec<JoinHandle<()>>,
}

impl<P: PeerDependencies> ParallelQueue<P> {
    /// Create a new ParallelQueue instance
    ///
    /// # Arguments
    ///
    /// - `queues`: number of readers
    /// - `capacity`: capacity of each internal queue
    pub fn new(n_workers: NonZeroUsize, capacity: usize) -> Self {
        let (sender, receiver) = bounded(capacity);

        let handles: Vec<_> = (0..n_workers.get())
            .map(|_| {
                let receiver = receiver.clone();
                thread::spawn(|| parallel_worker(receiver))
            })
            .collect();

        Self {
            sender: Some(sender),
            handles,
        }
    }

    pub fn queue_job(&self, job: ParallelJobUnion<P>) {
        self.sender
            .as_ref()
            .expect("sender should exist until drop is called")
            .send(job)
            .expect("receiver should exist while sender exists");
    }
}

impl<P: PeerDependencies> Drop for ParallelQueue<P> {
    fn drop(&mut self) {
        log::trace!("parallel queue: begin drop");

        // close worker queue
        self.sender = None;

        // join all worker threads
        while let Some(handle) = self.handles.pop() {
            handle.join().unwrap();
        }

        log::debug!("parallel queue: joined all handles");
    }
}
