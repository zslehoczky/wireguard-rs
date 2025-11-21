use std::collections::HashMap;
use std::sync::Arc;

use super::peer::DecryptionState;

pub struct ReceiverLookup<P> {
    lookup: HashMap<u32, Arc<DecryptionState<P>>>, /* receiver id -> decryption state */
}

impl<P> ReceiverLookup<P> {
    pub fn new() -> Self {
        Self {
            lookup: HashMap::new(),
        }
    }

    pub fn add_receiver(
        &mut self,
        prev_id: Option<u32>,
        new_id: u32,
        decryption_state: DecryptionState<P>,
    ) -> Option<u32> {
        let mut release = None;

        // purge recv map of previous id
        if let Some(prev_id) = prev_id {
            self.lookup.remove(&prev_id);
            release = Some(prev_id);
        }

        // map new id to decryption state
        debug_assert!(!self.lookup.contains_key(&new_id));
        self.lookup.insert(new_id, Arc::new(decryption_state));

        release
    }

    pub fn get(&self, id: &u32) -> Option<&Arc<DecryptionState<P>>> {
        self.lookup.get(id)
    }

    pub fn remove_receivers(&mut self, release: &[u32]) {
        for id in release {
            self.lookup.remove(id);
        }
    }
}

impl<P> Default for ReceiverLookup<P> {
    fn default() -> Self {
        Self::new()
    }
}
