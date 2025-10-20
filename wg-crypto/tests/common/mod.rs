// Common test utilities and mock implementations
#![allow(dead_code)]

use core::ops::Add;
use core::time::Duration;
use rand_core::{CryptoRng, RngCore, Error as RngError};
use wg_crypto::{Instant, Timestamp, TAI64N};

// ============================================================================
// Mock implementations for deterministic testing
// ============================================================================

/// MockRng that outputs a predetermined sequence of bytes
pub struct MockRng {
    counter: u8,
}

impl MockRng {
    pub fn new(seed: u8) -> Self {
        MockRng { counter: seed }
    }
}

impl RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.counter;
            self.counter = self.counter.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for MockRng {}

/// Default fixed timestamp: Unix epoch 1234567890, nanoseconds 123456789
pub const DEFAULT_TIMESTAMP: [u8; 12] = {
    const TAI64_EPOCH: u64 = 0x400000000000000a;
    let tai64_secs: u64 = 1234567890 + TAI64_EPOCH;
    let tai64_nano: u32 = 123456789;

    let mut res = [0u8; 12];
    let secs_bytes = tai64_secs.to_be_bytes();
    let nano_bytes = tai64_nano.to_be_bytes();

    let mut i = 0;
    while i < 8 {
        res[i] = secs_bytes[i];
        i += 1;
    }
    let mut j = 0;
    while j < 4 {
        res[8 + j] = nano_bytes[j];
        j += 1;
    }
    res
};

/// Default fixed timestamp implementation
pub struct DefaultTimestamp;

impl Timestamp for DefaultTimestamp {
    fn generate() -> TAI64N {
        TAI64N(DEFAULT_TIMESTAMP)
    }
}

/// MockInstant for testing - allows time to be advanced without actually sleeping
#[derive(Debug, Copy, Clone, Default)]
pub struct MockInstant {
    millis: u64,
}

impl Add<Duration> for MockInstant {
    type Output = Self;

    fn add(self, duration: Duration) -> Self {
        MockInstant {
            millis: self.millis + duration.as_millis() as u64,
        }
    }
}

impl Instant for MockInstant {
    fn since(&self, other: &Self) -> Duration {
        Duration::from_millis(self.millis.saturating_sub(other.millis))
    }
}

// ============================================================================
// Test Fixture Helpers
// ============================================================================

use wg_crypto::{Device, SecretBytes};
use x25519_dalek::{PublicKey, StaticSecret};

/// Fixed test parameters
pub const SK1_BYTES: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

pub const SK2_BYTES: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];

pub const PSK: [u8; 32] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
];

/// Create device 1 (initiator) with fixed parameters
pub fn setup_test_device_1() -> (Device<usize, MockInstant, DefaultTimestamp>, PublicKey) {
    let sk1 = StaticSecret::from(SK1_BYTES);
    let sk2 = StaticSecret::from(SK2_BYTES);
    let pk2 = PublicKey::from(&sk2);

    let mut dev1 = Device::new();
    dev1.set_sk(Some(sk1));
    dev1.add(pk2, 0).unwrap();
    dev1.set_psk(pk2, SecretBytes(PSK)).unwrap();

    (dev1, pk2)
}

/// Create device 2 (responder) with fixed parameters
pub fn setup_test_device_2() -> (Device<usize, MockInstant, DefaultTimestamp>, PublicKey) {
    let sk1 = StaticSecret::from(SK1_BYTES);
    let pk1 = PublicKey::from(&sk1);
    let sk2 = StaticSecret::from(SK2_BYTES);

    let mut dev2 = Device::new();
    dev2.set_sk(Some(sk2));
    dev2.add(pk1, 0).unwrap();
    dev2.set_psk(pk1, SecretBytes(PSK)).unwrap();

    (dev2, pk1)
}
