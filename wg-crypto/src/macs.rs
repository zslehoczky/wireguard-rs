use aead::consts::U16;
use blake2::digest::Mac;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use spin::RwLock;
use zerocopy::{AsBytes, FromBytes, U32};
use zeroize::{Zeroize, ZeroizeOnDrop};

// types to coalesce into bytes
use core::net::SocketAddr;
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey;

use std::time::{Duration, Instant};

use crate::{
    aead::{SymKey, XNonce},
    messages::{CookieReply, MACFooter, SIZE_COOKIE, TYPE_COOKIE_REPLY},
    noise::Hash,
    types::HandshakeError,
};

const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";
const COOKIE_UPDATE_INTERVAL: Duration = Duration::from_secs(120);

struct CookieState {
    key: MacKey<SIZE_COOKIE>,
    time: Instant,
}

pub struct Generator {
    cookie: Option<CookieState>,
    mac1_key: MacKey<32>,
    last_mac1: Option<MAC>,
    cookie_key: SymKey, // xchacha20poly key for opening cookie response
}

impl Generator {
    /// Initalize a new mac field generator
    ///
    /// # Arguments
    ///
    /// - pk: The public key of the peer to which the generator is associated
    ///
    /// # Returns
    ///
    /// A freshly initated generator
    pub fn new(pk: PublicKey) -> Generator {
        Generator {
            mac1_key: Hash::new([LABEL_MAC1, pk.as_bytes()]).into(),
            cookie_key: Hash::new([LABEL_COOKIE, pk.as_bytes()]).into(),
            last_mac1: None,
            cookie: None,
        }
    }

    /// Process a CookieReply message
    ///
    /// # Arguments
    ///
    /// - reply: CookieReply to process
    ///
    /// # Returns
    ///
    /// Can fail if the cookie reply fails to validate
    /// (either indicating that it is outdated or malformed)
    pub fn process(&mut self, time: Instant, reply: &CookieReply) -> Result<(), HandshakeError> {
        let mut cookie = MacKey([0u8; _]);
        self.cookie_key.xopen(
            &mut cookie,
            self.last_mac1.ok_or(HandshakeError::InvalidState)?,
            &reply.f_nonce,
            &reply.f_cookie,
            &reply.f_cookie_tag,
        )?;
        self.cookie = Some(CookieState { time, key: cookie });
        Ok(())
    }

    /// Generate both mac fields for an inner message
    ///
    /// # Arguments
    ///
    /// - inner: A byteslice representing the inner message to be covered
    /// - macs: The destination mac footer for the resulting macs
    pub fn generate(&mut self, time: Instant, inner: &[u8]) -> MACFooter {
        let f_mac1 = self.mac1_key.mac(|m| m.append(inner));
        let f_mac2 = match &self.cookie {
            Some(cookie) if time.duration_since(cookie.time) < COOKIE_UPDATE_INTERVAL => {
                cookie.key.mac(|m| {
                    m.append(inner);
                    m.append(f_mac1);
                })
            }
            _ => Default::default(),
        };
        self.last_mac1 = Some(f_mac1);
        MACFooter { f_mac1, f_mac2 }
    }
}

#[derive(Debug, Clone, ZeroizeOnDrop, Zeroize)]
struct MacKey<const N: usize>([u8; N]);

impl From<Hash> for MacKey<32> {
    fn from(hash: Hash) -> Self {
        MacKey(hash.0)
    }
}

impl<const N: usize> From<[u8; N]> for MacKey<N> {
    fn from(key: [u8; N]) -> Self {
        MacKey(key)
    }
}

impl<const N: usize> MacKey<N> {
    fn new<R: RngCore>(rng: &mut R) -> Self {
        let mut key = [0u8; _];
        rng.fill_bytes(&mut key);
        MacKey(key)
    }

    fn cookie_from_src(&self, src: &SocketAddr) -> MacKey<SIZE_COOKIE> {
        let mac = self.mac(|m| match src {
            SocketAddr::V4(addr) => {
                m.append([4u8]);
                m.append(addr.ip().octets());
                m.append(addr.port().to_le_bytes());
            }
            SocketAddr::V6(addr) => {
                m.append([6u8]);
                m.append(addr.ip().octets());
                m.append(addr.port().to_le_bytes());
            }
        });
        MacKey(mac.0)
    }
}

impl<const N: usize> AsRef<[u8]> for MacKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for MacKey<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[repr(C, packed)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, FromBytes, AsBytes, Eq, Default)]
pub struct MAC(pub [u8; 16]);

impl PartialEq for MAC {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl AsRef<[u8]> for MAC {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

struct MacStream<'a>(&'a mut blake2::Blake2sMac<U16>);

impl<'a> MacStream<'a> {
    fn append<A: AsRef<[u8]>>(&mut self, data: A) {
        self.0.update(data.as_ref());
    }
}

impl<const N: usize> MacKey<N> {
    fn mac<F>(&self, f: F) -> MAC
    where
        F: FnOnce(&mut MacStream),
    {
        assert!(N <= 32);
        let mut mac = blake2::Blake2sMac::new_with_salt_and_personal(&self.0, &[], &[]).unwrap();
        f(&mut MacStream(&mut mac));
        let mac = mac.finalize().into_bytes();
        MAC(mac.into())
    }
}

enum Secret {
    Set { value: MacKey<32>, birth: Instant },
    Unset,
}

impl Secret {
    fn tau(&self, time: Instant, src: &SocketAddr) -> Option<MacKey<16>> {
        match self {
            Secret::Set { value, birth }
                if time.duration_since(*birth) < COOKIE_UPDATE_INTERVAL =>
            {
                Some(value.cookie_from_src(src))
            }
            _ => None,
        }
    }
}

pub struct Validator {
    mac1_key: MacKey<32>, // mac1 key, derived from device public key
    cookie_key: SymKey,   // xchacha20poly key for sealing cookie response
    secret: RwLock<Secret>,
}

impl Validator {
    pub fn new(pk: PublicKey) -> Validator {
        Validator {
            mac1_key: Hash::new([LABEL_MAC1, pk.as_bytes()]).into(),
            cookie_key: Hash::new([LABEL_COOKIE, pk.as_bytes()]).into(),
            secret: RwLock::new(Secret::Unset),
        }
    }

    fn get_tau(&self, time: Instant, src: &SocketAddr) -> Option<MacKey<16>> {
        self.secret.read().tau(time, src)
    }

    fn get_set_tau<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        src: &SocketAddr,
        time: Instant,
    ) -> MacKey<16> {
        // check if current value is still valid
        // (using a read lock)
        {
            let secret = self.secret.read();
            if let Some(secret) = secret.tau(time, src) {
                return secret;
            }
        }

        // take write lock, check again
        let mut secret = self.secret.write();
        if let Some(secret) = secret.tau(time, src) {
            return secret;
        }

        // set new random cookie secret
        let key = MacKey::new(rng);
        let tau = key.cookie_from_src(src);
        *secret = Secret::Set {
            value: key,
            birth: time,
        };
        tau
    }

    pub fn create_cookie_reply<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        time: Instant,
        receiver: u32,    // receiver id of incoming message
        src: &SocketAddr, // source address of incoming message
        macs: &MACFooter, // footer of incoming message
    ) -> CookieReply {
        let mut msg = CookieReply {
            f_type: U32::new(TYPE_COOKIE_REPLY),
            f_receiver: U32::new(receiver),
            f_nonce: XNonce(rng.r#gen()),
            f_cookie: Default::default(),
            f_cookie_tag: Default::default(),
        };

        // Encrypt the cookie,
        // the Blake2s key for generating mac2,
        // using the cookie key derived from our public key
        self.cookie_key.xseal(
            self.get_set_tau(rng, src, time), // pt
            macs.f_mac1,                      // ad
            &msg.f_nonce,                     // nonce
            &mut msg.f_cookie,                // ct
            &mut msg.f_cookie_tag,            // tag
        );
        msg
    }

    /// Check the mac1 field against the inner message
    ///
    /// # Arguments
    ///
    /// - inner: The inner message covered by the mac1 field
    /// - macs: The mac footer
    pub fn check_mac1(&self, inner: &[u8], macs: &MACFooter) -> Result<(), HandshakeError> {
        if self.mac1_key.mac(|m| m.append(inner)) == macs.f_mac1 {
            Ok(())
        } else {
            Err(HandshakeError::InvalidMac1)
        }
    }

    pub fn check_mac2(
        &self,
        time: Instant,
        inner: &[u8],
        src: &SocketAddr,
        macs: &MACFooter,
    ) -> bool {
        if let Some(tau) = self.get_tau(time, src) {
            tau.mac(|m| {
                m.append(inner);
                m.append(macs.f_mac1);
            }) == macs.f_mac2
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::rngs::OsRng;
    use x25519_dalek::StaticSecret;

    fn new_validator_generator() -> (Validator, Generator) {
        let sk = StaticSecret::random_from_rng(&mut OsRng);
        let pk = PublicKey::from(&sk);
        (Validator::new(pk), Generator::new(pk))
    }

    proptest! {
        #[test]
        fn test_cookie_reply(inner1 : Vec<u8>, inner2 : Vec<u8>, receiver : u32) {
            let src: SocketAddr = "192.0.2.16:8080".parse().unwrap();
            let time = Instant::now();
            let (validator, mut generator) = new_validator_generator();

            // generate mac1 for first message
            let macs = generator.generate(time, &inner1[..]);
            assert_ne!(macs.f_mac1, Default::default(), "mac1 should be set");
            assert_eq!(macs.f_mac2, Default::default(), "mac2 should not be set");

            // check validity of mac1
            validator.check_mac1(&inner1[..], &macs).expect("mac1 of inner1 did not validate");
            assert_eq!(validator.check_mac2(time, &inner1[..], &src, &macs), false, "mac2 of inner2 did not validate");
            let msg = validator.create_cookie_reply(&mut OsRng, time, receiver, &src, &macs);

            // consume cookie reply
            generator.process(time, &msg).expect("failed to process CookieReply");

            // generate mac2 & mac2 for second message
            let macs = generator.generate(time, &inner2[..]);
            assert_ne!(macs.f_mac1, Default::default(), "mac1 should be set");
            assert_ne!(macs.f_mac2, Default::default(), "mac2 should be set");

            // check validity of mac1 and mac2
            validator.check_mac1(&inner2[..], &macs).expect("mac1 of inner2 did not validate");
            assert!(validator.check_mac2(time, &inner2[..], &src, &macs), "mac2 of inner2 did not validate");
        }
    }
}
