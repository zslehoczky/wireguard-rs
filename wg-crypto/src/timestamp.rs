use core::cmp::Ordering;
use subtle::ConstantTimeEq;
use zerocopy::{AsBytes, FromBytes};

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, Default, Ord, Eq, Clone, Copy)]
pub struct TAI64N(pub [u8; 12]);

impl AsRef<[u8]> for TAI64N {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for TAI64N {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl PartialEq for TAI64N {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl PartialOrd for TAI64N {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let mut gt = 0u8;
        let mut lt = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            gt |= ((b < a) as u8) & !lt;
            lt |= ((a < b) as u8) & !gt;
        }
        if gt != 0 {
            Some(Ordering::Greater)
        } else if lt != 0 {
            Some(Ordering::Less)
        } else {
            Some(Ordering::Equal)
        }
    }
}

pub trait Timestamp {
    /// Must return a monotonically increasing timestamp.
    ///
    /// The usual implementation is to use the TAI64N timestamp.
    /// However, on some embedded platforms, without a real-time clock,
    /// a monotonic counter can be used instead.
    ///
    /// Additionally, this trait allows derandomizing the implementation:
    /// allowing easy testing against test vectors.
    ///
    /// Implementors would aim to support at least one 20ms resolution:
    /// the implementation will expect that calling this function every 20ms
    /// produces a new (larger) timestamp. Note that a counter satisifies this.
    fn generate() -> TAI64N;
}

#[cfg(feature = "std")]
pub struct StdTimestamp;

#[cfg(feature = "std")]
impl Timestamp for StdTimestamp {
    fn generate() -> TAI64N {
        use std::time::{SystemTime, UNIX_EPOCH};

        const TAI64_EPOCH: u64 = 0x400000000000000a;

        // get system time as duration
        let sysnow = SystemTime::now();
        let delta = sysnow.duration_since(UNIX_EPOCH).unwrap();

        // convert to tai64n
        let tai64_secs = delta.as_secs() + TAI64_EPOCH;
        let tai64_nano = delta.subsec_nanos();

        // serialize
        let mut res = [0u8; 12];
        res[..8].copy_from_slice(&tai64_secs.to_be_bytes()[..]);
        res[8..].copy_from_slice(&tai64_nano.to_be_bytes()[..]);
        TAI64N(res)
    }
}
