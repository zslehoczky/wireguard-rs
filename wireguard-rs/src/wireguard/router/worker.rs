use super::receive::ReceiveJob;
use super::send::SendJob;
use super::sequential_queue::{SequentialJob, SequentialQueue};

use super::types::Callbacks;

use crossbeam_channel::Receiver;
use wg_traits::{Endpoint, tun, udp};

pub trait ParallelJob: Sized + SequentialJob {
    fn sequential_queue(&self) -> &SequentialQueue<Self>;

    fn parallel_work(&self);
}

pub enum JobUnion<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    Outbound(SendJob<E, C, T, B>),
    Inbound(ReceiveJob<E, C, T, B>),
}

pub fn worker<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    receiver: Receiver<JobUnion<E, C, T, B>>,
) {
    loop {
        log::trace!("pool worker awaiting job");
        match receiver.recv() {
            Err(e) => {
                log::debug!("worker stopped with {}", e);
                break;
            }
            Ok(JobUnion::Inbound(job)) => {
                job.parallel_work();
                job.sequential_queue().consume();
            }
            Ok(JobUnion::Outbound(job)) => {
                job.parallel_work();
                job.sequential_queue().consume();
            }
        }
    }
}
