use chacha20poly1305::KeyInit;

// HASH & MAC
use blake2::{Blake2s256, Digest};
use hmac::{Mac, SimpleHmac};

// DH
use x25519_dalek;

use rand_core::{CryptoRng, RngCore};

use zerocopy::{AsBytes, U32};
use zeroize::{Zeroize, ZeroizeOnDrop};

use subtle::ConstantTimeEq;

use crate::aead::SymKey;
use crate::peer::StInit;
use crate::timestamp::Timestamp;
use crate::{Instance, PublicKey, SecretKey};

use super::device::{Device, KeyState};
use super::messages::{NoiseInitiation, NoiseResponse};
use super::messages::{TYPE_INITIATION, TYPE_RESPONSE};
use super::peer::{Peer, State};
use super::timestamp;
use super::types::*;

use super::keypair::{Key, KeyPair};

// Type aliases to reduce complexity
type InitiationResult<'a, I> = Result<(&'a Peer<I>, PublicKey, TemporaryState), HandshakeError>;

pub type ChainKey = SecretBytes<32>;

type HmacBlake2s256 = SimpleHmac<Blake2s256>;

// convenient alias to pass state temporarily into device.rs and back

type TemporaryState = (Identifier, PublicKey, Hash, ChainKey);

// C := Hash(Construction)
const INITIAL_CK: Hash = Hash([
    0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, //
    0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0, //
    0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, //
    0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
]);

// H := Hash(C || Identifier)
const INITIAL_HS: Hash = Hash([
    0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, //
    0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32, //
    0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7, //
    0x0e, 0xe1, 0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3,
]);

/// Just some bytes which are sensitive and thus needs
/// to be zeroed out after use and (ideally) not paged out to disk.
#[derive(ZeroizeOnDrop, Zeroize, Eq, Clone)]
pub struct SecretBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> From<[u8; N]> for SecretBytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        SecretBytes(bytes)
    }
}

impl<const N: usize> Default for SecretBytes<N> {
    fn default() -> Self {
        SecretBytes([0u8; N])
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// Hashes are public and hence can be compared in non-constant time
/// They also do not need to be zeroized on drop.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    #[inline]
    pub fn new<const N: usize>(inputs: [&[u8]; N]) -> Self {
        let mut hasher = Blake2s256::default();
        for input in inputs {
            hasher.update(input);
        }
        Hash(hasher.finalize().into())
    }
}

impl AsRef<[u8]> for Hash {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[inline(always)]
fn hmac<const N: usize, A: AsRef<[u8]>>(key: A, inputs: [&[u8]; N]) -> SecretBytes<32> {
    let mut hmac: HmacBlake2s256 = KeyInit::new_from_slice(key.as_ref()).unwrap();
    for input in inputs {
        hmac.update(input);
    }
    SecretBytes(hmac.finalize().into_bytes().into())
}

fn kdf1<A: AsRef<[u8]>, B: AsRef<[u8]>, O: From<SecretBytes<32>>>(ck: A, input: B) -> O {
    let t0 = hmac(ck, [input.as_ref()]);
    let t1 = hmac(&t0, [&[0x01]]);
    t1.into()
}

fn kdf2<A: AsRef<[u8]>, B: AsRef<[u8]>, O1: From<SecretBytes<32>>, O2: From<SecretBytes<32>>>(
    ck: A,
    input: B,
) -> (O1, O2) {
    let t0 = hmac(ck, [input.as_ref()]);
    let t1 = hmac(&t0, [&[0x01]]);
    let t2 = hmac(&t0, [t1.as_ref(), &[0x02]]);
    (t1.into(), t2.into())
}

fn kdf3<
    A: AsRef<[u8]>,
    B: AsRef<[u8]>,
    O1: From<SecretBytes<32>>,
    O2: From<SecretBytes<32>>,
    O3: From<SecretBytes<32>>,
>(
    ck: A,
    input: B,
) -> (O1, O2, O3) {
    let t0 = hmac(ck, [input.as_ref()]);
    let t1 = hmac(&t0, [&[0x01]]);
    let t2 = hmac(&t0, [t1.as_ref(), &[0x02]]);
    let t3 = hmac(&t0, [t2.as_ref(), &[0x03]]);
    (t1.into(), t2.into(), t3.into())
}

// Computes an X25519 shared secret.
//
// This function wraps dalek to add a zero-check.
// This is not recommended by the Noise specification,
// but implemented in the kernel with which we strive for equivalent behavior.
#[inline(always)]
fn shared_secret(
    sk: &x25519_dalek::StaticSecret,
    pk: &x25519_dalek::PublicKey,
) -> Result<x25519_dalek::SharedSecret, HandshakeError> {
    let ss = sk.diffie_hellman(pk);
    if ss.as_bytes().ct_eq(&[0u8; 32]).into() {
        Err(HandshakeError::InvalidSharedSecret)
    } else {
        Ok(ss)
    }
}

pub(super) fn create_initiation<I: Instance, R: RngCore + CryptoRng>(
    rng: &mut R,
    keyst: &KeyState<I::Instant>,
    peer: &mut Peer<I>,
    pk: &PublicKey,
    local: Identifier,
) -> Result<NoiseInitiation, HandshakeError> {
    log::debug!("create initiation");

    let mut msg = NoiseInitiation {
        f_type: U32::new(TYPE_INITIATION),
        f_sender: local,
        f_ephemeral: Default::default(),
        f_static: Default::default(),
        f_static_tag: Default::default(),
        f_timestamp: Default::default(),
        f_timestamp_tag: Default::default(),
    };

    // check for zero shared-secret (see "shared_secret" note).
    let static_static = match peer.ss {
        Some(ref ss) => ss,
        None => return Err(HandshakeError::InvalidSharedSecret),
    };

    // initialize state
    let ck = INITIAL_CK;
    let hs = INITIAL_HS;
    let hs = Hash::new([
        hs.as_ref(), //
        pk.as_bytes(),
    ]);

    // (E_priv, E_pub) := DH-Generate()

    let ep = SecretKey::random(rng);

    // msg.ephemeral := E_pub

    msg.f_ephemeral = ep.pk();

    // C := Kdf(C, E_pub)

    let ck: ChainKey = kdf1(ck, msg.f_ephemeral.as_bytes());

    // H := HASH(H, msg.ephemeral)

    let hs = Hash::new([
        hs.as_ref(), //
        msg.f_ephemeral.as_ref(),
    ]);

    // (C, k) := Kdf2(C, DH(E_priv, S_pub))

    let (ck, key): (ChainKey, SymKey) = kdf2(
        &ck, //
        ep.dh(pk)?.as_bytes(),
    );

    // msg.static := Aead(k, 0, S_pub, H)

    key.seal(
        keyst.pk.as_bytes(),   // pt
        hs,                    // ad
        &Default::default(),   // nonce
        &mut msg.f_static,     // ct
        &mut msg.f_static_tag, // tag
    );

    // H := Hash(H || msg.static)

    let hs = Hash::new([
        hs.as_ref(),
        msg.f_static.as_ref(),
        msg.f_static_tag.as_ref(),
    ]);

    // (C, k) := Kdf2(C, DH(S_priv, S_pub))

    let (ck, key): (ChainKey, SymKey) = kdf2(&ck, static_static);

    // msg.timestamp := Aead(k, 0, Timestamp(), H)

    key.seal(
        I::Timestamp::generate(), // pt (timestamp)
        hs,                       // ad
        &Default::default(),      // nonce
        &mut msg.f_timestamp,     // ct
        &mut msg.f_timestamp_tag, // tag
    );

    // H := Hash(H || msg.timestamp)

    let hs = Hash::new([
        hs.as_ref(),
        msg.f_timestamp.as_ref(),
        msg.f_timestamp_tag.as_ref(),
    ]);

    // update state of peer

    peer.state = State::InitiationSent(StInit { hs, ck, ep, local });

    Ok(msg)
}

pub(super) fn consume_initiation<'a, I: Instance>(
    now: I::Instant,
    state: &'a mut I,
    keyst: &KeyState<I::Instant>,
    msg: &NoiseInitiation,
) -> InitiationResult<'a, I> {
    log::debug!("consume initiation");

    // initialize new state
    let ck = INITIAL_CK;
    let hs = INITIAL_HS;
    let hs = Hash::new([
        hs.as_ref(), //
        keyst.pk.as_bytes(),
    ]);

    // C := Kdf(C, E_pub)

    let ck: ChainKey = kdf1(ck, msg.f_ephemeral.as_bytes());

    // H := HASH(H, msg.ephemeral)

    let hs = Hash::new([
        hs.as_ref(), //
        &msg.f_ephemeral.as_bytes(),
    ]);

    // (C, k) := Kdf2(C, DH(E_priv, S_pub))

    let eph_r_pk = PublicKey::from(msg.f_ephemeral);
    let (ck, key): (ChainKey, SymKey) = kdf2(
        &ck, //
        keyst.sk.dh(&msg.f_ephemeral)?.as_bytes(),
    );

    // msg.static := Aead(k, 0, S_pub, H)

    let mut pk = PublicKey::default();
    key.open(
        &mut pk,             // pt
        hs,                  // ad
        &Default::default(), // nonce
        &msg.f_static,       // ct
        &msg.f_static_tag,   // tag
    )?;

    let peer = state.get_mut(&pk).ok_or(HandshakeError::UnknownPublicKey)?;

    // reset initiation state

    let static_static = peer
        .ss
        .as_ref()
        .ok_or(HandshakeError::InvalidSharedSecret)?;

    peer.state = State::Reset;

    // H := Hash(H || msg.static)

    let hs = Hash::new([
        hs.as_ref(),
        msg.f_static.as_ref(),
        msg.f_static_tag.as_ref(),
    ]);

    // (C, k) := Kdf2(C, DH(S_priv, S_pub))

    let (ck, key): (ChainKey, SymKey) = kdf2(&ck, static_static);

    // msg.timestamp := Aead(k, 0, Timestamp(), H)

    let mut ts: timestamp::TAI64N = Default::default();

    key.open(
        &mut ts,              // pt
        hs,                   // ad
        &Default::default(),  // nonce
        &msg.f_timestamp,     // ct
        &msg.f_timestamp_tag, // tag
    )?;

    // check and update timestamp

    peer.check_replay_flood(now, ts)?;

    // H := Hash(H || msg.timestamp)

    let hs = Hash::new([
        hs.as_ref(),
        msg.f_timestamp.as_ref(),
        msg.f_timestamp_tag.as_ref(),
    ]);

    // return state (to create response)

    Ok((peer, PublicKey::from(pk), (msg.f_sender, eph_r_pk, hs, ck)))
}

pub(super) fn create_response<R: RngCore + CryptoRng, I: Instance>(
    rng: &mut R,
    now: I::Instant,
    peer: &Peer<I>,
    pk: &PublicKey,
    local: Identifier,     // sending identifier
    state: TemporaryState, // state from "consume_initiation"
) -> Result<(NoiseResponse, KeyPair<I::Instant>), HandshakeError> {
    log::debug!("create response");

    // unpack state
    let (receiver, eph_r_pk, hs, ck) = state;

    let mut msg = NoiseResponse {
        f_type: U32::new(TYPE_RESPONSE),
        f_sender: local,
        f_receiver: receiver,
        f_ephemeral: Default::default(),
        f_empty_tag: Default::default(),
    };

    // (E_priv, E_pub) := DH-Generate()

    let eph_sk = SecretKey::random(rng);

    // msg.ephemeral := E_pub

    msg.f_ephemeral = eph_sk.pk();

    // C := Kdf1(C, E_pub)

    let ck: ChainKey = kdf1(
        &ck, //
        msg.f_ephemeral.as_bytes(),
    );

    // H := Hash(H || msg.ephemeral)

    let hs = Hash::new([
        hs.as_ref(), //
        &msg.f_ephemeral.as_bytes(),
    ]);

    // C := Kdf1(C, DH(E_priv, E_pub))

    let ck: ChainKey = kdf1(
        &ck, //
        eph_sk.dh(&eph_r_pk)?.as_bytes(),
    );

    // C := Kdf1(C, DH(E_priv, S_pub))

    let ck: ChainKey = kdf1(
        &ck, //
        eph_sk.dh(pk)?.as_bytes(),
    );

    // (C, tau, k) := Kdf3(C, Q)

    let (ck, tau, key): (ChainKey, SecretBytes<32>, SymKey) = kdf3(
        &ck, //
        &peer.psk,
    );

    // H := Hash(H || tau)

    let hs = Hash::new([
        hs.as_ref(),  //
        tau.as_ref(), // bind key to transcript
    ]);

    // msg.empty := Aead(k, 0, [], H)

    key.seal(
        [],                   // pt
        hs,                   // ad
        &Default::default(),  // nonce
        &mut [],              // \epsilon
        &mut msg.f_empty_tag, // tag
    );

    // Not strictly needed
    // let hs = HASH!(&hs, &msg.f_empty_tag);

    // derive key-pair

    let (key_recv, key_send): (SymKey, SymKey) = kdf2(&ck, []);

    // return unconfirmed key-pair

    Ok((
        msg,
        KeyPair {
            birth: now,
            initiator: false,
            send: Key {
                id: receiver,
                key: key_send,
            },
            recv: Key {
                id: local,
                key: key_recv,
            },
        },
    ))
}

/// The state lock is released while processing the message to
/// allow concurrent processing of potential responses to the initiation,
/// in order to better mitigate DoS from malformed response messages.
pub(super) fn consume_response<'a, I: Instance>(
    now: I::Instant,
    device: &'a Device<I>,
    keyst: &KeyState<I::Instant>,
    msg: &NoiseResponse,
) -> Result<Output<I::Instant>, HandshakeError> {
    log::debug!("consume response");

    // retrieve peer and copy initiation state
    let (peer, _) = device.lookup_id(msg.f_receiver.get())?;
    let st: StInit = match &*peer.state.lock() {
        State::InitiationSent(st) => Ok(st.clone()),
        _ => Err(HandshakeError::InvalidState),
    }?;

    // C := Kdf1(C, E_pub)

    let ck: ChainKey = kdf1(
        &st.ck, //
        msg.f_ephemeral,
    );

    // H := Hash(H || msg.ephemeral)

    let hs = Hash::new([
        st.hs.as_ref(), //
        msg.f_ephemeral.as_bytes(),
    ]);

    // C := Kdf1(C, DH(E_priv, E_pub))

    let eph_r_pk = PublicKey::from(msg.f_ephemeral);
    let ck: ChainKey = kdf1(
        &ck, //
        st.ep.dh(&eph_r_pk)?.as_bytes(),
    );

    // C := Kdf1(C, DH(E_priv, S_pub))

    let ck: ChainKey = kdf1(
        &ck, //
        keyst.sk.dh(&eph_r_pk)?.as_bytes(),
    );

    // (C, tau, k) := Kdf3(C, Q)

    let (ck, tau, key): (ChainKey, SecretBytes<32>, SymKey) = kdf3(
        &ck, //
        &peer.psk,
    );

    // H := Hash(H || tau)

    let hs = Hash::new([
        hs.as_ref(), //
        tau.as_ref(),
    ]);

    // msg.empty := Aead(k, 0, [], H)

    key.open(
        &mut [],             // pt
        hs,                  // ad
        &Default::default(), // nonce
        &[],                 // \epsilon
        &msg.f_empty_tag,    // tag
    )?;

    // derive key-pair

    let (key_send, key_recv): (SymKey, SymKey) = kdf2(&ck, []);

    // check for new initiation sent while lock released

    let mut st_new = peer.state.lock();
    if let State::InitiationSent(st_init) = &*st_new
        && st_init == st
    {
        // null the initiation state
        // (to avoid replay of this response message)
        *st_new = State::Reset;

        // return confirmed key-pair
        Ok(Output {
            msg: None,
            key_pair: Some(KeyPair {
                birth: now,
                initiator: true,
                send: Key {
                    id: msg.f_sender,
                    key: key_send,
                },
                recv: Key {
                    id: st.local,
                    key: key_recv,
                },
            }),
        })
    } else {
        Err(HandshakeError::InvalidState)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
    const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

    /* Sanity check precomputed initial chain key
     */
    #[test]
    fn precomputed_chain_key() {
        assert_eq!(INITIAL_CK, Hash::new([CONSTRUCTION]));
    }

    /* Sanity check precomputed initial hash transcript
     */
    #[test]
    fn precomputed_hash() {
        assert_eq!(INITIAL_HS, Hash::new([INITIAL_CK.as_ref(), IDENTIFIER]));
    }

    /* Sanity check the HKDF macro
     *
     * Test vectors generated using WireGuard-Go
     */
    #[test]
    fn hkdf() {
        type TestVector = (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32], [u8; 32]);
        let tests: Vec<TestVector> = vec![
            (
                vec![],
                vec![],
                [
                    0x83, 0x87, 0xb4, 0x6b, 0xf4, 0x3e, 0xcc, 0xfc, //
                    0xf3, 0x49, 0x55, 0x2a, 0x09, 0x5d, 0x83, 0x15, //
                    0xc4, 0x05, 0x5b, 0xeb, 0x90, 0x20, 0x8f, 0xb1, //
                    0xbe, 0x23, 0xb8, 0x94, 0xbc, 0x2e, 0xd5, 0xd0,
                ],
                [
                    0x58, 0xa0, 0xe5, 0xf6, 0xfa, 0xef, 0xcc, 0xf4, //
                    0x80, 0x7b, 0xff, 0x1f, 0x05, 0xfa, 0x8a, 0x92, //
                    0x17, 0x94, 0x57, 0x62, 0x04, 0x0b, 0xce, 0xc2, //
                    0xf4, 0xb4, 0xa6, 0x2b, 0xdf, 0xe0, 0xe8, 0x6e,
                ],
                [
                    0x0c, 0xe6, 0xea, 0x98, 0xec, 0x54, 0x8f, 0x8e, //
                    0x28, 0x1e, 0x93, 0xe3, 0x2d, 0xb6, 0x56, 0x21, //
                    0xc4, 0x5e, 0xb1, 0x8d, 0xc6, 0xf0, 0xa7, 0xad, //
                    0x94, 0x17, 0x86, 0x10, 0xa2, 0xf7, 0x33, 0x8e,
                ],
            ),
            (
                vec![0xde, 0xad, 0xbe, 0xef],
                vec![],
                [
                    0x55, 0x32, 0x9d, 0xc8, 0x0e, 0x69, 0x0f, 0xd8, //
                    0x6b, 0xd9, 0x66, 0x1f, 0x08, 0x51, 0xc9, 0xb3, //
                    0x68, 0x6d, 0xf2, 0xb1, 0xfd, 0xa0, 0x34, 0x7b, //
                    0xc3, 0xd2, 0x79, 0x58, 0x25, 0x4b, 0x32, 0xc6,
                ],
                [
                    0x8d, 0xfc, 0x6d, 0x33, 0xa8, 0x11, 0x8f, 0xfe, //
                    0x40, 0x8b, 0x31, 0xdd, 0xac, 0x25, 0xf7, 0x2a, //
                    0xee, 0x91, 0x15, 0xa4, 0x5b, 0x69, 0xba, 0x17, //
                    0x6a, 0xd0, 0x12, 0xb2, 0x43, 0x83, 0x4f, 0xee,
                ],
                [
                    0xd6, 0x9e, 0x85, 0x2a, 0x28, 0x96, 0x56, 0x9e, //
                    0xa5, 0x4a, 0x67, 0x96, 0x9a, 0xa1, 0x80, 0x02, //
                    0x87, 0x92, 0x1d, 0xac, 0x53, 0xce, 0x6d, 0xb4, //
                    0xb4, 0xe1, 0x21, 0x92, 0xf2, 0x63, 0xc4, 0xc4,
                ],
            ),
        ];

        for (key, input, t0, t1, t2) in &tests {
            let tt0: SecretBytes<_> = kdf1(key, input);
            assert_eq!(tt0.as_ref(), &t0[..], "kdf1 failed");

            let (tt0, tt1): (SecretBytes<_>, SecretBytes<_>) = kdf2(key, input);
            assert_eq!(tt0.as_ref(), &t0[..], "kdf2 failed");
            assert_eq!(tt1.as_ref(), &t1[..], "kdf2 failed");

            let (tt0, tt1, tt2): (SecretBytes<_>, SecretBytes<_>, SecretBytes<_>) =
                kdf3(key, input);
            assert_eq!(tt0.as_ref(), &t0[..], "kdf3 failed");
            assert_eq!(tt1.as_ref(), &t1[..], "kdf3 failed");
            assert_eq!(tt2.as_ref(), &t2[..], "kdf3 failed");
        }
    }
}
