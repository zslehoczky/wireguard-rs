mod anti_replay;
mod decryption_state;
mod encryption_state;
mod key_wheel;
#[allow(clippy::module_inception)]
mod peer;

use std::sync::Arc;

use crate::router::KeyPair;

pub use decryption_state::DecryptionState;
use encryption_state::EncryptionState;
pub use peer::{Peer, PeerHandle, new_peer};

fn crypto_state<P>(peer: P, keypair: Arc<KeyPair>) -> (EncryptionState, DecryptionState<P>) {
    (
        EncryptionState::new(keypair.clone()),
        DecryptionState::new(peer, keypair),
    )
}
