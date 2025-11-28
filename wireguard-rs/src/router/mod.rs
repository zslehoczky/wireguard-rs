mod constants;
mod device;
mod ip;
mod parallel_queue;
mod peer;
mod peer_lookup;
mod receive_job;
mod router_error;
mod routing_table;
mod send_job;
mod sequential_queue;
mod transport;

#[cfg(test)]
mod tests;

pub use constants::{
    CAPACITY_MESSAGE_POSTFIX, MAX_QUEUED_PACKETS, REJECT_AFTER_MESSAGES, SIZE_MESSAGE_PREFIX,
    message_data_len,
};
pub use device::Device;
pub use peer::{PeerDependencies, PeerState};
pub use router_error::RouterError;
pub use transport::TYPE_TRANSPORT;

pub type KeyPair = wg_crypto::KeyPair<std::time::Instant>;
