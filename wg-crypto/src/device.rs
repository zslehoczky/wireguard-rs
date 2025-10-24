use core::marker::PhantomData;
use std::collections::HashMap;

use core::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use zerocopy::AsBytes;

use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use zeroize::Zeroize;

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use crate::time::Instant;
use crate::timestamp::Timestamp;

use super::macs;
use super::messages::{CookieReply, Initiation, Response};
use super::messages::{TYPE_COOKIE_REPLY, TYPE_INITIATION, TYPE_RESPONSE};
use super::noise;
use super::peer::Peer;
use super::ratelimiter::RateLimiter;
use super::types::*;

const MAX_PEER_PER_DEVICE: usize = 1 << 20;

pub struct KeyState<I: Instant> {
    pub(super) sk: StaticSecret, // static secret key
    pub(super) pk: PublicKey,    // static public key
    macs: macs::Validator<I>,    // validator for the mac fields
}

/// The device is generic over an "opaque" type
/// which can be used to associate the public key with this value.
/// (the instance is a Peer object in the parent module)
pub struct Device<O, I: Instant, T: Timestamp> {
    key_st: Option<KeyState<I>>,
    id_map: DashMap<u32, [u8; 32]>, // concurrent map
    pk_map: HashMap<[u8; 32], Peer<O, I, T>>,
    limiter: RateLimiter,
    _ph: PhantomData<(I, T)>,
}

/* These methods enable the Device to act as a map
 * from public keys to the set of contained opaque values.
 *
 * It also abstracts away the problem of PublicKey not being hashable.
 */
impl<O, I: Instant, T: Timestamp> Device<O, I, T> {
    pub fn _clear(&mut self) {
        self.id_map.clear();
        self.pk_map.clear();
    }

    /// Enables enumeration of (public key, opaque) pairs
    /// without exposing internal peer type.
    pub fn iter(&'_ self) -> impl Iterator<Item = (PublicKey, &O)> {
        self.pk_map
            .iter()
            .map(|(pk, peer)| (PublicKey::from(*pk), &peer.opaque))
    }

    /// Enables lookup by public key without exposing internal peer type.
    pub fn get(&self, pk: &PublicKey) -> Option<&O> {
        self.pk_map.get(pk.as_bytes()).map(|peer| &peer.opaque)
    }

    pub fn contains_key(&self, pk: &PublicKey) -> bool {
        self.pk_map.contains_key(pk.as_bytes())
    }
}

/* A mutable reference to the device needs to be held during configuration.
 * Wrapping the device in a RwLock enables peer config after "configuration time"
 */
impl<O, I: Instant, T: Timestamp> Default for Device<O, I, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<O, I: Instant, T: Timestamp> Device<O, I, T> {
    pub fn new() -> Self {
        Self {
            key_st: None,
            id_map: DashMap::new(),
            pk_map: HashMap::new(),
            limiter: RateLimiter::new(),
            _ph: PhantomData,
        }
    }

    fn update_ss(&mut self) -> Option<PublicKey> {
        let mut same = None;
        for (pk, peer) in self.pk_map.iter_mut() {
            if let Some(key) = self.key_st.as_ref() {
                if key.pk.as_bytes() == pk {
                    same = Some(PublicKey::from(*pk));
                    peer.ss = None
                } else {
                    let pk = PublicKey::from(*pk);
                    peer.ss = Some(key.sk.diffie_hellman(&pk));
                }
            } else {
                peer.ss.zeroize();
            }
            if let Some(id) = peer.reset_state() {
                // release ids from aborted handshakes
                self.id_map.remove(&id);
            }
        }
        same
    }

    /// Update the secret key of the device
    ///
    /// # Arguments
    ///
    /// * `sk` - x25519 scalar representing the local private key
    ///
    /// TODO: Get rid of this method
    pub fn set_sk(&mut self, sk: Option<StaticSecret>) -> Option<PublicKey> {
        // update secret and public key
        self.key_st = sk.map(|sk| {
            let pk = PublicKey::from(&sk);
            let macs = macs::Validator::new(pk);
            KeyState { pk, sk, macs }
        });

        // recalculate / erase the shared secrets for every peer
        let same = self.update_ss();

        // if we found a peer matching the device public key
        // remove it and return its value to the caller
        same.inspect(|pk| {
            self.pk_map.remove(pk.as_bytes());
        })
    }

    /// Return the secret key of the device
    ///
    /// # Returns
    ///
    /// A secret key (x25519 scalar)
    pub fn get_sk(&self) -> Option<&StaticSecret> {
        self.key_st.as_ref().map(|key| &key.sk)
    }

    /// Add a new public key to the state machine
    /// To remove public keys, you must create a new machine instance
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to add
    /// * `identifier` - Associated identifier which can be used to distinguish the peers
    pub fn add(&mut self, pk: PublicKey, opaque: O) -> Result<(), ConfigError> {
        // ensure less than 2^20 peers
        if self.pk_map.len() > MAX_PEER_PER_DEVICE {
            return Err(ConfigError::TooManyPeers);
        }

        // error if public key matches device
        if let Some(key) = self.key_st.as_ref()
            && pk == key.pk
        {
            return Err(ConfigError::PeerMatchesDevice);
        }

        // pre-compute shared secret and add to pk_map
        self.pk_map.insert(
            *pk.as_bytes(),
            Peer::new(
                pk,
                self.key_st.as_ref().map(|key| key.sk.diffie_hellman(&pk)),
                opaque,
            ),
        );

        Ok(())
    }

    /// Remove a peer by public key
    /// To remove public keys, you must create a new machine instance
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key of the peer to remove
    ///
    /// # Returns
    ///
    /// The call might fail if the public key is not found
    pub fn remove(&mut self, pk: &PublicKey) -> Result<(), ConfigError> {
        // remove the peer
        self.pk_map
            .remove(pk.as_bytes())
            .ok_or(ConfigError::NoSuchPublicKey)?;

        // remove every id entry for the peer in the public key map
        // O(n) operations, however it is rare: only when removing peers.
        self.id_map.retain(|_, v| v != pk.as_bytes());
        Ok(())
    }

    /// Add a psk to the peer
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key of the peer
    /// * `psk` - The psk to set / unset
    ///
    /// # Returns
    ///
    /// The call might fail if the public key is not found
    pub fn set_psk(&mut self, pk: PublicKey, psk: PSK) -> Result<(), ConfigError> {
        match self.pk_map.get_mut(pk.as_bytes()) {
            Some(peer) => {
                peer.psk = psk;
                Ok(())
            }
            _ => Err(ConfigError::NoSuchPublicKey),
        }
    }

    /// Return the psk for the peer
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key of the peer
    ///
    /// # Returns
    ///
    /// A 32 byte array holding the PSK
    ///
    /// The call might fail if the public key is not found
    pub fn get_psk(&self, pk: &PublicKey) -> Result<&PSK, ConfigError> {
        match self.pk_map.get(pk.as_bytes()) {
            Some(peer) => Ok(&peer.psk),
            _ => Err(ConfigError::NoSuchPublicKey),
        }
    }

    /// Release an id back to the pool
    ///
    /// # Arguments
    ///
    /// * `id` - The (sender) id to release
    pub fn release(&self, id: u32) {
        let old = self.id_map.remove(&id);
        assert!(old.is_some(), "released id not allocated");
    }

    /// Begin a new handshake
    ///
    /// # Arguments
    ///
    /// * `now` - Current time
    /// * `rng` - RNG instance to sample randomness from
    /// * `pk` - Public key of peer to initiate handshake for
    pub fn begin<R: RngCore + CryptoRng>(
        &self,
        now: I, // current time
        rng: &mut R,
        pk: &PublicKey,
    ) -> Result<Message, HandshakeError> {
        match (self.key_st.as_ref(), self.pk_map.get(pk.as_bytes())) {
            (_, None) => Err(HandshakeError::UnknownPublicKey),
            (None, _) => Err(HandshakeError::UnknownPublicKey),
            (Some(keyst), Some(peer)) => {
                let local = self.allocate(rng, pk);

                // create noise part of initation
                let noise = noise::create_initiation::<I, T, _, _>(rng, keyst, peer, pk, local)?;

                // add macs to initation
                let macs = peer.macs.lock().generate(now, noise.as_bytes());

                Ok(Message::Initiation(Initiation { noise, macs }))
            }
        }
    }

    /// Process a handshake message.
    ///
    /// # Arguments
    ///
    /// * `now` - Current time
    /// * `rng` - RNG instance to sample randomness from
    /// * `msg` - Byte slice containing the message (untrusted input)
    /// * `src` - Optional source endpoint, set when "under load"
    ///
    /// # Returns
    ///
    pub fn process<'a, R: RngCore + CryptoRng>(
        &'a self,
        now: I,                  // current time
        rng: &mut R,             // rng instance to sample randomness from
        msg: &[u8],              // message buffer
        src: Option<SocketAddr>, // optional source endpoint, set when "under load"
    ) -> Result<Output<'a, O, I>, HandshakeError> {
        // ensure type read in-range
        if msg.len() < 4 {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        // obtain reference to key state
        // if no key is configured return a noop.
        let keyst = match self.key_st.as_ref() {
            Some(key) => key,
            None => {
                return Ok(Output {
                    id: None,
                    msg: None,
                    key_pair: None,
                });
            }
        };

        // de-multiplex the message type field
        match LittleEndian::read_u32(msg) {
            TYPE_INITIATION => {
                // parse message
                let msg = Initiation::parse(msg)?;

                // check mac1 field
                keyst.macs.check_mac1(msg.noise.as_bytes(), &msg.macs)?;

                // address validation & DoS mitigation
                if let Some(src) = src {
                    // check mac2 field
                    if !keyst
                        .macs
                        .check_mac2(now, msg.noise.as_bytes(), &src, &msg.macs)
                    {
                        let reply = keyst.macs.create_cookie_reply(
                            rng,
                            now,
                            msg.noise.f_sender.get(),
                            &src,
                            &msg.macs,
                        );
                        return Ok(Output {
                            id: None,
                            msg: Some(reply.into()),
                            key_pair: None,
                        });
                    }

                    // check ratelimiter
                    if !self.limiter.check(&src.ip()) {
                        return Err(HandshakeError::RateLimited);
                    }
                }

                // consume the initiation
                let (peer, pk, st) = noise::consume_initiation(now, self, keyst, &msg.noise)?;

                // allocate new index for response
                let local = self.allocate(rng, &pk);

                // create response (release id on error)
                let (noise, keys) = noise::create_response(rng, now, peer, &pk, local, st)
                    .inspect_err(|_e| {
                        self.release(local);
                    })?;

                // add macs to response
                let macs = peer.macs.lock().generate(now, noise.as_bytes());

                // return unconfirmed keypair and the response as vector
                Ok(Output {
                    id: Some(&peer.opaque),
                    msg: Some(Response { noise, macs }.into()),
                    key_pair: Some(keys),
                })
            }
            TYPE_RESPONSE => {
                let msg = Response::parse(msg)?;

                // check mac1 field
                keyst.macs.check_mac1(msg.noise.as_bytes(), &msg.macs)?;

                // address validation & DoS mitigation
                if let Some(src) = src {
                    // check mac2 field
                    if !keyst
                        .macs
                        .check_mac2(now, msg.noise.as_bytes(), &src, &msg.macs)
                    {
                        let reply = keyst.macs.create_cookie_reply(
                            rng,
                            now,
                            msg.noise.f_sender.get(),
                            &src,
                            &msg.macs,
                        );
                        return Ok(Output {
                            id: None,
                            msg: Some(reply.into()),
                            key_pair: None,
                        });
                    }

                    // check ratelimiter
                    if !self.limiter.check(&src.ip()) {
                        return Err(HandshakeError::RateLimited);
                    }
                }

                // consume inner playload
                noise::consume_response(now, self, keyst, &msg.noise)
            }
            TYPE_COOKIE_REPLY => {
                let msg = CookieReply::parse(msg)?;

                // lookup peer
                let (peer, _) = self.lookup_id(msg.f_receiver.get())?;

                // validate cookie reply
                peer.macs.lock().process(now, &msg)?;

                // this prompts no new message and
                // DOES NOT cryptographically verify the peer
                Ok(Output {
                    id: None,
                    msg: None,
                    key_pair: None,
                })
            }
            _ => Err(HandshakeError::InvalidMessageFormat),
        }
    }

    // Internal function
    //
    // Return the peer associated with the public key
    pub(super) fn lookup_pk(&self, pk: &[u8; 32]) -> Result<&Peer<O, I, T>, HandshakeError> {
        self.pk_map.get(pk).ok_or(HandshakeError::UnknownPublicKey)
    }

    // Internal function
    //
    // Return the peer currently associated with the receiver identifier
    pub(super) fn lookup_id(&self, id: u32) -> Result<(&Peer<O, I, T>, PublicKey), HandshakeError> {
        // obtain a read reference to entry in the id_map
        let pk = self
            .id_map
            .get(&id)
            .ok_or(HandshakeError::UnknownReceiverId)?;

        // lookup the public key from the pk map
        match self.pk_map.get(&*pk) {
            Some(peer) => Ok((peer, PublicKey::from(*pk))),
            _ => unreachable!(),
        }
    }

    // Internal function
    //
    // Allocated a new receiver identifier for the peer.
    // Implemented via rejection sampling.
    fn allocate<R: RngCore + CryptoRng>(&self, rng: &mut R, pk: &PublicKey) -> u32 {
        loop {
            let id = rng.r#gen();

            // read lock the shard and do quick check
            if self.id_map.contains_key(&id) {
                continue;
            }

            // write lock the shard and insert
            if let Entry::Vacant(entry) = self.id_map.entry(id) {
                entry.insert(*pk.as_bytes());
                return id;
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::timestamp::StdTimestamp;

    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    proptest! {
        #[test]
        fn unique_shared_secrets(sk_bs: [u8; 32], pk1_bs: [u8; 32], pk2_bs: [u8; 32]) {
            let sk = StaticSecret::from(sk_bs);
            let pk1 = PublicKey::from(pk1_bs);
            let pk2 = PublicKey::from(pk2_bs);

            assert_eq!(pk1.as_bytes(), &pk1_bs);
            assert_eq!(pk2.as_bytes(), &pk2_bs);

            let mut dev : Device<u32, std::time::Instant, StdTimestamp> = Device::new();
            dev.set_sk(Some(sk));

            dev.add(pk1, 1).unwrap();
            if dev.add(pk2, 0).is_err() {
                assert_eq!(pk1_bs, pk2_bs);
                assert_eq!(*dev.get(&pk1).unwrap(), 1);
            }


            // every shared secret is unique
            let mut ss: HashSet<[u8; 32]> = HashSet::new();
            for peer in dev.pk_map.values() {
                ss.insert(peer.ss.as_ref()
                    .map(|ss| *ss.as_bytes()).unwrap_or_default());
            }
        }
    }
}
