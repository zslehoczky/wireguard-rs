pub use std::num::NonZeroUsize;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{Receiver, Sender, bounded};

use wg_traits::{Endpoint, tun, udp};

use super::callbacks::Callbacks;
use super::receive::ReceiveJob;
use super::send::SendJob;
use super::sequential_queue::{SequentialJob, SequentialQueue};

pub trait ParallelJob: Sized + SequentialJob {
    fn sequential_queue(&self) -> &SequentialQueue<Self>;

    fn parallel_work(&self);
}

pub enum ParallelJobUnion<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    Outbound(SendJob<E, C, T, B>),
    Inbound(ReceiveJob<E, C, T, B>),
}

fn parallel_worker<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    receiver: Receiver<ParallelJobUnion<E, C, T, B>>,
) {
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

pub struct ParallelQueue<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    sender: Option<Sender<ParallelJobUnion<E, C, T, B>>>,
    handles: Vec<JoinHandle<()>>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> ParallelQueue<E, C, T, B> {
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

    pub fn queue_job(&self, job: ParallelJobUnion<E, C, T, B>) {
        self.sender
            .as_ref()
            .expect("sender should exist until drop is called")
            .send(job)
            .expect("receiver should exist while sender exists");
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Drop
    for ParallelQueue<E, C, T, B>
{
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
