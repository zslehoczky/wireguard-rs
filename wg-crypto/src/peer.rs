use spin::Mutex;
use subtle::ConstantTimeEq;

use core::marker::PhantomData;
use std::mem;
use std::time::Duration;

use x25519_dalek::StaticSecret;
use x25519_dalek::{PublicKey, SharedSecret};

use crate::noise::{ChainKey, Hash};
use crate::time::Instant;
use crate::timestamp::{TAI64N, Timestamp};

use super::device::Device;
use super::macs;
use super::timestamp;
use super::types::*;

const TIME_BETWEEN_INITIATIONS: Duration = Duration::from_millis(20);

// Represents the state of a peer.
//
// This type is only for internal use and not exposed.
pub(crate) struct Peer<O, I: Instant, T: Timestamp> {
    // opaque type which identifies a peer
    pub opaque: O,

    // mutable state
    pub state: Mutex<State>,
    pub timestamp: Mutex<Option<TAI64N>>,
    pub last_initiation_consumption: Mutex<Option<I>>,

    // state related to DoS mitigation fields
    pub macs: Mutex<macs::Generator<I>>,

    // constant state
    pub ss: Option<SharedSecret>, // precomputed DH(static, static)
    pub psk: PSK,                 // psk of peer
    _ph: PhantomData<T>,
}

#[derive(Clone)]
pub struct StInit {
    pub(crate) local: u32, // local id assigned
    pub(crate) eph_sk: StaticSecret,
    pub(crate) hs: Hash,
    pub(crate) ck: ChainKey,
}

impl PartialEq for StInit {
    fn eq(&self, other: &Self) -> bool {
        self.eph_sk.as_bytes().ct_eq(other.eph_sk.as_bytes()).into()
    }
}

#[derive(Clone, PartialEq)]
pub enum State {
    Reset,
    InitiationSent(StInit),
}

impl<O, I: Instant, T: Timestamp> Peer<O, I, T> {
    pub fn new(pk: PublicKey, ss: Option<SharedSecret>, opaque: O) -> Self {
        Self {
            opaque,
            macs: Mutex::new(macs::Generator::new(pk)),
            state: Mutex::new(State::Reset),
            timestamp: Mutex::new(None),
            last_initiation_consumption: Mutex::new(None),
            ss,
            psk: Default::default(),
            _ph: PhantomData,
        }
    }

    pub fn reset_state(&self) -> Option<u32> {
        match mem::replace(&mut *self.state.lock(), State::Reset) {
            State::InitiationSent(StInit { local, .. }) => Some(local),
            _ => None,
        }
    }

    /// Set the mutable state of the peer conditioned on the timestamp being newer
    ///
    /// # Arguments
    ///
    /// * st_new - The updated state of the peer
    /// * ts_new - The associated timestamp
    pub fn check_replay_flood(
        &self,
        now: I,
        device: &Device<O, I, T>,
        ts_new: timestamp::TAI64N,
    ) -> Result<(), HandshakeError> {
        let mut state = self.state.lock();
        let mut timestamp = self.timestamp.lock();
        let mut last_initiation_consumption = self.last_initiation_consumption.lock();

        // check replay attack
        match *timestamp {
            Some(ts_old) if ts_old >= ts_new => {
                return Err(HandshakeError::OldTimestamp);
            }
            _ => {}
        }

        // check flood attack
        if let Some(last) = *last_initiation_consumption
            && now.since(&last) < TIME_BETWEEN_INITIATIONS
        {
            return Err(HandshakeError::InitiationFlood);
        }

        // reset state
        if let State::InitiationSent(StInit { local, .. }) = *state {
            device.release(local)
        }

        // update replay & flood protection
        *state = State::Reset;
        *timestamp = Some(ts_new);
        *last_initiation_consumption = Some(now);
        Ok(())
    }
}
