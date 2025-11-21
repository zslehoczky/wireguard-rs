pub mod callbacks;
pub mod constants;
pub mod device;
mod ip;
pub mod parallel_queue;
pub mod receive;
mod receiver_lookup;
pub mod router_error;
mod routing_table;
pub mod send;
pub mod sequential_queue;
mod transport;

#[cfg(test)]
mod tests;

pub use callbacks::Callbacks;
pub use constants::{CAPACITY_MESSAGE_POSTFIX, SIZE_MESSAGE_PREFIX, message_data_len};
pub use device::Device;
pub use transport::TYPE_TRANSPORT;

pub type KeyPair = wg_crypto::KeyPair<std::time::Instant>;
