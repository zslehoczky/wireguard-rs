use std::mem::size_of;

use super::transport::TransportHeader;

// WireGuard semantics

pub const MAX_QUEUED_PACKETS: usize = 1024;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 4);

// performance

pub const INORDER_QUEUE_SIZE: usize = MAX_QUEUED_PACKETS;

// message size

pub const SIZE_TAG: usize = 16;
pub const SIZE_MESSAGE_PREFIX: usize = size_of::<TransportHeader>();
pub const CAPACITY_MESSAGE_POSTFIX: usize = SIZE_TAG;

pub const fn message_data_len(payload: usize) -> usize {
    payload + size_of::<TransportHeader>() + SIZE_TAG
}
