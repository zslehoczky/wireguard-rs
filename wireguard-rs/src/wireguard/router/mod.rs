mod anti_replay;
mod constants;
mod crypto_state;
mod device;
mod ip;
mod parallel_queue;
mod peer;
mod receive;
mod route;
mod send;
mod sequential_queue;
mod transport;
mod types;

#[cfg(test)]
mod tests;

use transport::TransportHeader;

use super::constants::REJECT_AFTER_MESSAGES;

use core::mem;

pub const SIZE_TAG: usize = 16;
pub const SIZE_MESSAGE_PREFIX: usize = mem::size_of::<TransportHeader>();
pub const CAPACITY_MESSAGE_POSTFIX: usize = SIZE_TAG;

pub const fn message_data_len(payload: usize) -> usize {
    payload + mem::size_of::<TransportHeader>() + SIZE_TAG
}

pub use device::Device;
pub use peer::PeerHandle;
pub use transport::TYPE_TRANSPORT;
pub use types::Callbacks;
