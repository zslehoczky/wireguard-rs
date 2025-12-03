mod constants;
mod fake_router;
mod ip;
mod peer_lookup;
#[allow(clippy::module_inception)]
mod router;
mod router_error;
mod routing_table;
mod transport;

pub use constants::{
    CAPACITY_MESSAGE_POSTFIX, MAX_QUEUED_PACKETS, REJECT_AFTER_MESSAGES, SIZE_MESSAGE_PREFIX,
    SIZE_TAG, message_data_len,
};
pub use fake_router::FakeRouter;
pub use ip::{IPv4Header, IPv6Header, VERSION_IP4, VERSION_IP6};
pub use router::Router;
pub use router_error::RouterError;
pub use transport::{TYPE_TRANSPORT, TransportHeader};

pub type KeyPair = wg_crypto::KeyPair<std::time::Instant>;
