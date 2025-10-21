use core::fmt::Debug;

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, XChaCha20Poly1305};
use digest::KeyInit;
use generic_array::GenericArray;
use subtle::ConstantTimeEq;
use zerocopy::{AsBytes, FromBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    noise::{Hash, SecretBytes},
    types::HandshakeError,
};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, Default, PartialEq, Eq)]
pub struct Tag(pub [u8; 16]);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, ZeroizeOnDrop, Zeroize, Eq)]
pub struct SymKey([u8; 32]);

impl Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymKey")
            .field("hash(key)", &Hash::new([self.0.as_ref()]))
            .finish()
    }
}

impl From<[u8; 32]> for SymKey {
    fn from(key: [u8; 32]) -> Self {
        SymKey(key)
    }
}

// TODO: get rid of this
impl AsRef<[u8; 32]> for SymKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for SymKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl From<Hash> for SymKey {
    fn from(hash: Hash) -> Self {
        SymKey(hash.0)
    }
}

impl From<SecretBytes<32>> for SymKey {
    fn from(key: SecretBytes<32>) -> Self {
        SymKey(key.0)
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, AsBytes, FromBytes, PartialEq, Eq)]
pub struct XNonce(pub [u8; 24]);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Nonce([u8; 12]);

impl From<u64> for Nonce {
    fn from(value: u64) -> Self {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&value.to_be_bytes());
        Nonce(nonce)
    }
}

impl SymKey {
    pub fn seal<P: AsRef<[u8]>, A: AsRef<[u8]>, C: AsMut<[u8]>>(
        &self,
        pt: P,
        ad: A,
        nonce: &Nonce,
        ct: &mut C,
        tag: &mut Tag,
    ) {
        let ct = ct.as_mut();
        ct.copy_from_slice(pt.as_ref());
        let aead_tag = ChaCha20Poly1305::new_from_slice(&self.0)
            .unwrap()
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce.0), ad.as_ref(), ct)
            .unwrap();
        tag.0.copy_from_slice(&aead_tag);
    }

    pub fn open<A: AsRef<[u8]>, P: AsMut<[u8]>, C: AsRef<[u8]>>(
        &self,
        pt: &mut P,
        ad: A,
        nonce: &Nonce,
        ct: &C,
        tag: &Tag,
    ) -> Result<(), HandshakeError> {
        let pt = pt.as_mut();
        let ct = ct.as_ref();
        pt.copy_from_slice(ct);
        ChaCha20Poly1305::new_from_slice(&self.0)
            .unwrap()
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce.0),
                ad.as_ref(),
                pt,
                GenericArray::from_slice(&tag.0),
            )
            .map_err(|_err| HandshakeError::DecryptionFailure)
    }
}

impl SymKey {
    pub(crate) fn xseal<P: AsRef<[u8]>, A: AsRef<[u8]>, C: AsMut<[u8]>>(
        &self,
        pt: P,
        ad: A,
        nonce: &XNonce,
        ct: &mut C,
        tag: &mut Tag,
    ) {
        let ct = ct.as_mut();
        ct.copy_from_slice(pt.as_ref());
        let aead_tag = XChaCha20Poly1305::new_from_slice(&self.0)
            .unwrap()
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce.0), ad.as_ref(), ct)
            .unwrap();
        tag.0.copy_from_slice(&aead_tag);
    }

    pub(crate) fn xopen<A: AsRef<[u8]>, P: AsMut<[u8]>, C: AsRef<[u8]>>(
        &self,
        pt: &mut P,
        ad: A,
        nonce: &XNonce,
        ct: &C,
        tag: &Tag,
    ) -> Result<(), HandshakeError> {
        let pt = pt.as_mut();
        let ct = ct.as_ref();
        pt.copy_from_slice(ct);
        XChaCha20Poly1305::new_from_slice(&self.0)
            .unwrap()
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce.0),
                ad.as_ref(),
                pt,
                GenericArray::from_slice(&tag.0),
            )
            .map_err(|_err| HandshakeError::DecryptionFailure)
    }
}
