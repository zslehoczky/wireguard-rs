use core::cmp::Ordering;
use subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
};
use zerocopy::{AsBytes, FromBytes};

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, Default, Eq, Clone, Copy, Debug)]
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

// Implement constant-time comparison traits for TAI64N
impl ConstantTimeEq for TAI64N {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Ord for TAI64N {
    fn cmp(&self, other: &Self) -> Ordering {
        // pack the bytes into words
        // TAI64N is big-endian, so lexicographic comparison is correct
        let a0 = u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]);
        let a1 = u32::from_be_bytes([self.0[4], self.0[5], self.0[6], self.0[7]]);
        let a2 = u32::from_be_bytes([self.0[8], self.0[9], self.0[10], self.0[11]]);
        let b0 = u32::from_be_bytes([other.0[0], other.0[1], other.0[2], other.0[3]]);
        let b1 = u32::from_be_bytes([other.0[4], other.0[5], other.0[6], other.0[7]]);
        let b2 = u32::from_be_bytes([other.0[8], other.0[9], other.0[10], other.0[11]]);

        // constant-time comparison of the words
        let mut is_less = Choice::from(0u8);
        let mut is_greater = Choice::from(0u8);

        // compare word 0
        is_less |= a0.ct_lt(&b0) & !(is_less | is_greater);
        is_greater |= a0.ct_gt(&b0) & !(is_less | is_greater);

        // compare word 1
        is_less |= a1.ct_lt(&b1) & !(is_less | is_greater);
        is_greater |= a1.ct_gt(&b1) & !(is_less | is_greater);

        // compare word 2
        is_less |= a2.ct_lt(&b2) & !(is_less | is_greater);
        is_greater |= a2.ct_gt(&b2) & !(is_less | is_greater);

        // sanity check
        debug_assert!({
            let check: bool = (!is_less | !is_greater).into();
            check
        });

        // constant-time selection of the result
        let mut result = Ordering::Equal as i8;
        result = i8::conditional_select(&result, &(Ordering::Less as i8), is_less);
        result = i8::conditional_select(&result, &(Ordering::Greater as i8), is_greater);

        // convert back to Ordering:
        // safe because result can only be { -1, 0, 1 }
        // (the discriminants of Ordering)
        match result {
            -1 => Ordering::Less,
            0 => Ordering::Equal,
            1 => Ordering::Greater,
            _ => unsafe { core::hint::unreachable_unchecked() },
        }
    }
}

impl PartialOrd for TAI64N {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    #[test]
    fn test_constant_time_ordering() {
        // Test basic ordering properties
        let ts1 = TAI64N([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]); // 1 second
        let ts2 = TAI64N([0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0]); // 2 seconds
        let ts3 = TAI64N([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1]); // 1 second + 1 nanosecond

        assert_eq!(ts1.cmp(&ts1), Ordering::Equal);
        assert_eq!(ts1.cmp(&ts2), Ordering::Less);
        assert_eq!(ts2.cmp(&ts1), Ordering::Greater);
        assert_eq!(ts1.cmp(&ts3), Ordering::Less);
        assert_eq!(ts3.cmp(&ts1), Ordering::Greater);
        assert_eq!(ts3.cmp(&ts2), Ordering::Less);

        // Test that PartialOrd agrees with Ord
        assert!(ts1 < ts2);
        assert!(ts2 > ts1);
        assert!(ts1 == ts1);
        assert!(ts1 < ts3);
        assert!(ts3 < ts2);
    }

    #[test]
    fn test_constant_time_equality() {
        let ts1 = TAI64N([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let ts2 = TAI64N([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let ts3 = TAI64N([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13]);

        assert!(ts1.eq(&ts2));
        assert!(!ts1.eq(&ts3));
        assert_eq!(ts1.cmp(&ts2), Ordering::Equal);
        assert_eq!(ts1.cmp(&ts3), Ordering::Less);
    }

    #[test]
    fn test_word_boundary_comparisons() {
        // Test comparisons that differ in first word (bytes 0-3)
        let ts1 = TAI64N([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        let ts2 = TAI64N([0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(ts1.cmp(&ts2), Ordering::Less);
        assert_eq!(ts2.cmp(&ts1), Ordering::Greater);

        // Test comparisons that differ in second word (bytes 4-7)
        let ts3 = TAI64N([0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]);
        let ts4 = TAI64N([0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0]);
        assert_eq!(ts3.cmp(&ts4), Ordering::Less);
        assert_eq!(ts4.cmp(&ts3), Ordering::Greater);

        // Test comparisons that differ in third word (bytes 8-11)
        let ts5 = TAI64N([0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]);
        let ts6 = TAI64N([0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(ts5.cmp(&ts6), Ordering::Less);
        assert_eq!(ts6.cmp(&ts5), Ordering::Greater);
    }

    #[test]
    fn test_first_byte_differs() {
        // Ensure first byte difference is detected
        let ts1 = TAI64N([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let ts2 = TAI64N([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(ts1.cmp(&ts2), Ordering::Less);
        assert_eq!(ts2.cmp(&ts1), Ordering::Greater);
    }

    #[test]
    fn test_last_byte_differs() {
        // Ensure last byte difference is detected
        let ts1 = TAI64N([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let ts2 = TAI64N([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(ts1.cmp(&ts2), Ordering::Less);
        assert_eq!(ts2.cmp(&ts1), Ordering::Greater);
    }

    #[test]
    fn test_extreme_values() {
        // Test minimum value
        let min = TAI64N([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // Test maximum value
        let max = TAI64N([255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]);

        assert_eq!(min.cmp(&min), Ordering::Equal);
        assert_eq!(max.cmp(&max), Ordering::Equal);
        assert_eq!(min.cmp(&max), Ordering::Less);
        assert_eq!(max.cmp(&min), Ordering::Greater);

        // Test value just above minimum
        let min_plus_one = TAI64N([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(min.cmp(&min_plus_one), Ordering::Less);
        assert_eq!(min_plus_one.cmp(&min), Ordering::Greater);

        // Test value just below maximum
        let max_minus_one = TAI64N([255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254]);
        assert_eq!(max_minus_one.cmp(&max), Ordering::Less);
        assert_eq!(max.cmp(&max_minus_one), Ordering::Greater);
    }

    #[test]
    fn test_adjacent_values() {
        // Test many adjacent timestamp values
        for i in 0u8..255 {
            let ts1 = TAI64N([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i]);
            let ts2 = TAI64N([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i + 1]);
            assert_eq!(ts1.cmp(&ts2), Ordering::Less);
            assert_eq!(ts2.cmp(&ts1), Ordering::Greater);
            assert_eq!(ts1.cmp(&ts1), Ordering::Equal);
        }
    }

    #[test]
    fn test_lexicographic_ordering() {
        // Test that big-endian lexicographic ordering is correct
        // Earlier bytes should take precedence
        let ts1 = TAI64N([0, 0, 0, 1, 255, 255, 255, 255, 255, 255, 255, 255]);
        let ts2 = TAI64N([0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]);

        // ts1 < ts2 because first word (0x00000001) < (0x00000002)
        // even though later bytes in ts1 are larger
        assert_eq!(ts1.cmp(&ts2), Ordering::Less);
    }

    #[test]
    fn test_fuzz() {
        // Test that random values are ordered correctly:
        // testing against the (insecure) lexicographic ordering of the arrays
        let mut rng = ChaCha8Rng::seed_from_u64(0xcafecafe);
        for _ in 0..100_000 {
            let ts1 = TAI64N(rng.r#gen());
            let ts2 = TAI64N(rng.r#gen());
            let cmp = ts1.cmp(&ts2);
            assert_eq!(cmp, ts1.0.cmp(&ts2.0));
        }
    }
}
