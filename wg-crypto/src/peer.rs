use spin::Mutex;

use std::mem;
use std::time::{Duration, Instant};

use x25519_dalek::StaticSecret;
use x25519_dalek::{PublicKey, SharedSecret};

use crate::noise::{ChainKey, Hash};

use super::device::Device;
use super::macs;
use super::timestamp;
use super::types::*;

const TIME_BETWEEN_INITIATIONS: Duration = Duration::from_millis(20);

// Represents the state of a peer.
//
// This type is only for internal use and not exposed.
pub(crate) struct Peer<O> {
    // opaque type which identifies a peer
    pub opaque: O,

    // mutable state
    pub state: Mutex<State>,
    pub timestamp: Mutex<Option<timestamp::TAI64N>>,
    pub last_initiation_consumption: Mutex<Option<Instant>>,

    // state related to DoS mitigation fields
    pub macs: Mutex<macs::Generator>,

    // constant state
    pub ss: Option<SharedSecret>, // precomputed DH(static, static)
    pub psk: PSK,                 // psk of peer
}

pub enum State {
    Reset,
    InitiationSent {
        local: u32, // local id assigned
        eph_sk: StaticSecret,
        hs: Hash,
        ck: ChainKey,
    },
}

impl<O> Peer<O> {
    pub fn new(pk: PublicKey, ss: Option<SharedSecret>, opaque: O) -> Self {
        Self {
            opaque,
            macs: Mutex::new(macs::Generator::new(pk)),
            state: Mutex::new(State::Reset),
            timestamp: Mutex::new(None),
            last_initiation_consumption: Mutex::new(None),
            ss,
            psk: Default::default(),
        }
    }

    pub fn reset_state(&self) -> Option<u32> {
        match mem::replace(&mut *self.state.lock(), State::Reset) {
            State::InitiationSent { local, .. } => Some(local),
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
        device: &Device<O>,
        timestamp_new: &timestamp::TAI64N,
    ) -> Result<(), HandshakeError> {
        let mut state = self.state.lock();
        let mut timestamp = self.timestamp.lock();
        let mut last_initiation_consumption = self.last_initiation_consumption.lock();

        // check replay attack
        if let Some(timestamp_old) = *timestamp
            && !timestamp::compare(&timestamp_old, timestamp_new)
        {
            return Err(HandshakeError::OldTimestamp);
        };

        // check flood attack
        if let Some(last) = *last_initiation_consumption
            && last.elapsed() < TIME_BETWEEN_INITIATIONS
        {
            return Err(HandshakeError::InitiationFlood);
        }

        // reset state
        if let State::InitiationSent { local, .. } = *state {
            device.release(local)
        }

        // update replay & flood protection
        *state = State::Reset;
        *timestamp = Some(*timestamp_new);
        *last_initiation_consumption = Some(Instant::now());
        Ok(())
    }
}
