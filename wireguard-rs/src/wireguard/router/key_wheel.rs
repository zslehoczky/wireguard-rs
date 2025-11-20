use std::mem::{swap, take};
use std::sync::Arc;

use crate::wireguard::peer::KeyPair;

pub struct KeyWheel {
    next: Option<Arc<KeyPair>>,     // next key state (unconfirmed)
    current: Option<Arc<KeyPair>>,  // current key state (used for encryption)
    previous: Option<Arc<KeyPair>>, // old key state (used for decryption)
    retired: Vec<u32>,              // retired ids
}

impl KeyWheel {
    pub fn new() -> Self {
        Self {
            next: None,
            current: None,
            previous: None,
            retired: vec![],
        }
    }

    pub fn get_next(&self) -> Option<&Arc<KeyPair>> {
        self.next.as_ref()
    }

    pub fn get_prev(&self) -> Option<&Arc<KeyPair>> {
        self.previous.as_ref()
    }

    pub fn reset(&mut self, retire: bool) -> Vec<u32> {
        let mut release = Vec::with_capacity(3);

        if let Some(k) = self.next.take() {
            release.push(k.recv.id)
        }
        if let Some(k) = self.current.take() {
            release.push(k.recv.id)
        }
        if let Some(k) = self.previous.take() {
            release.push(k.recv.id)
        }

        if retire {
            self.retired.extend(&release[..]);
        }

        release
    }

    pub fn rotate(&mut self) {
        let mut other = None;

        swap(&mut self.next, &mut other);
        swap(&mut self.current, &mut other);
        swap(&mut self.previous, &mut other);
    }

    pub fn take_retired(&mut self) -> Vec<u32> {
        take(&mut self.retired)
    }

    pub fn update(&mut self, new: Arc<KeyPair>) {
        let initiator = new.initiator;

        let mut temp = Some(new);

        if initiator {
            // use new as current
            swap(&mut temp, &mut self.current);
        } else {
            // store new as next and await confirmation
            swap(&mut temp, &mut self.next);
        };

        // store swapped-out key as previous
        swap(&mut self.previous, &mut temp);
    }
}
