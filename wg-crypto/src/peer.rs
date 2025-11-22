use core::marker::PhantomData;
use std::mem;
use std::time::Duration;

use crate::Instance;
use crate::SecretKey;
use crate::SharedSecret;
use crate::noise::{ChainKey, Hash};
use crate::time::Instant;
use crate::timestamp::TAI64N;

use super::macs;
use super::timestamp;
use super::types::*;

const TIME_BETWEEN_INITIATIONS: Duration = Duration::from_millis(20);

// Represents the state of a peer.
//
// This type is only for internal use and not exposed.
pub(crate) struct Peer<I: Instance> {
    // mutable state
    pub state: State,
    pub timestamp: Option<TAI64N>,
    pub last_initiation_consumption: Option<I::Instant>,

    // state related to DoS mitigation fields
    pub macs: macs::Generator<I::Instant>,

    // constant state
    pub ss: Option<SharedSecret>, // precomputed DH(static, static)
    pub psk: Option<PSK>,         // psk of peer
    pub _ph: PhantomData<I>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct StInit {
    pub(crate) local: Identifier,
    pub(crate) ep: SecretKey,
    pub(crate) hs: Hash,
    pub(crate) ck: ChainKey,
}

#[derive(Clone, PartialEq)]
pub enum State {
    Reset,
    InitiationSent(StInit),
}

impl<I: Instance> Peer<I> {
    #[must_use]
    pub fn reset_state(&mut self) -> Option<Identifier> {
        match mem::replace(&mut self.state, State::Reset) {
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
        &mut self,
        now: I::Instant,
        ts_new: timestamp::TAI64N,
    ) -> Result<Option<Identifier>, HandshakeError> {
        // check replay attack
        match self.timestamp {
            Some(ts_old) if ts_old >= ts_new => {
                return Err(HandshakeError::OldTimestamp);
            }
            _ => {}
        }

        // check flood attack
        if let Some(last) = self.last_initiation_consumption
            && now.since(&last) < TIME_BETWEEN_INITIATIONS
        {
            return Err(HandshakeError::InitiationFlood);
        }

        // reset state
        let local = if let State::InitiationSent(StInit { local, .. }) = self.state {
            Some(local)
        } else {
            None
        };

        // update replay & flood protection
        self.state = State::Reset;
        self.timestamp = Some(ts_new);
        self.last_initiation_consumption = Some(now);
        Ok(local)
    }
}
