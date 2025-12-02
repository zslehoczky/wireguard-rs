use std::collections::HashMap;

use crate::peer::{Peer, PeerDependencies};

pub struct PeerLookup<P: PeerDependencies> {
    lookup: HashMap<u32, Peer<P>>,
}

impl<P: PeerDependencies> PeerLookup<P> {
    pub fn new() -> Self {
        Self {
            lookup: HashMap::new(),
        }
    }

    pub fn add_receiver(
        &mut self,
        prev_id: Option<u32>,
        new_id: u32,
        peer: Peer<P>,
    ) -> Option<u32> {
        let mut release = None;

        // remove item with previous id
        if let Some(prev_id) = prev_id {
            self.lookup.remove(&prev_id);
            release = Some(prev_id);
        }

        // map new id to peer
        debug_assert!(!self.lookup.contains_key(&new_id));
        self.lookup.insert(new_id, peer);

        release
    }

    pub fn get(&self, id: &u32) -> Option<&Peer<P>> {
        self.lookup.get(id)
    }

    pub fn remove_receivers(&mut self, release: &[u32]) {
        for id in release {
            self.lookup.remove(id);
        }
    }
}

impl<P: PeerDependencies> Default for PeerLookup<P> {
    fn default() -> Self {
        Self::new()
    }
}
