use std::sync::{Arc, Weak};

use wg_traits::{Endpoint, tun, udp};

use super::encryption_decryption_state::DecryptionState;
use super::types::Callbacks;

type ElementType<E, C, T, B> = Option<Arc<DecryptionState<E, C, T, B>>>;

pub struct ReceiverDecryptionState<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    data: Vec<ElementType<E, C, T, B>>, /* receiver id -> decryption state */
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>
    ReceiverDecryptionState<E, C, T, B>
{
    pub fn new() -> Self {
        Self { data: vec![] }
    }

    pub fn extend(&mut self, n_new_elements: usize) {
        self.resize(self.len() + n_new_elements);
    }

    pub fn resize(&mut self, new_len: usize) {
        self.data.resize(new_len, None);
    }

    pub fn contains_key(&self, receiver_id: usize) -> bool {
        matches!(self.data.get(receiver_id), Some(Some(_)))
    }

    pub fn get(&self, receiver_id: usize) -> Weak<DecryptionState<E, C, T, B>> {
        if let Some(Some(arc)) = self.data.get(receiver_id) {
            return Arc::downgrade(arc);
        }

        Weak::new()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn insert(
        &mut self,
        receiver_id_hint: usize,
        state: DecryptionState<E, C, T, B>,
    ) -> Result<usize, &'static str> {
        if self.len() == 0 {
            return Err("len == 0");
        }

        let first_index = receiver_id_hint % self.len();

        let mut index = first_index;

        while let Some(Some(_)) = self.data.get(index) {
            index = (index + 1) % self.len();

            if index == first_index {
                return Err("container full");
            }
        }

        self.data[index] = Some(Arc::new(state));

        Ok(index)
    }

    pub fn remove(&mut self, receiver_id: usize) -> Result<(), &'static str> {
        match self.data.get_mut(receiver_id) {
            None => Err("id > len"),
            Some(None) => Err("unused id"),
            Some(opt) => {
                *opt = None;
                Ok(())
            }
        }
    }
}
