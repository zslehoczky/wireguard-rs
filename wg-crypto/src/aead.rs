use core::fmt::{self, Debug};

use aead::{AeadInOut, inout::InOutBuf};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, XChaCha20Poly1305};
use generic_array::GenericArray;
use subtle::ConstantTimeEq;
use zerocopy::{AsBytes, FromBytes, LayoutVerified, U32};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    messages::{TYPE_TRANSPORT, TransportHeader},
    noise::{Hash, SecretBytes},
    types::{HandshakeError, Identifier},
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

#[derive(Clone)]
pub struct Encryptor {
    id: Identifier,
    cipher: ChaCha20Poly1305,
}

#[derive(Clone)]
pub struct Decryptor {
    id: Identifier,
    cipher: ChaCha20Poly1305,
}

impl fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("key_id", &self.id)
            .finish()
    }
}

impl fmt::Debug for Decryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryptor")
            .field("key_id", &self.id)
            .finish()
    }
}

impl Encryptor {
    /// Encrypt a packet with a given counter, it's the callers responsibility to ensure that:
    ///
    /// - The counter is unique.
    /// - The packet buffer is larger than the header + tag size.
    fn encrypt(&self, packet: &mut [u8], counter: u64) -> Result<(), HandshakeError> {
        // "parse" message
        let (mut head, rest): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
            LayoutVerified::new_from_prefix(&mut packet[..])
                .ok_or(HandshakeError::InvalidMessageFormat)?;

        let (pt, mut tag): (&mut [u8], LayoutVerified<&mut [u8], Tag>) =
            LayoutVerified::new_from_suffix(rest) //
                .ok_or(HandshakeError::InvalidMessageFormat)?;

        // set the header
        *head = TransportHeader {
            f_type: U32::new(TYPE_TRANSPORT),
            f_counter: counter.into(),
            f_receiver: self.id,
        };

        // encrypt the packet and set the tag
        *tag = Tag(self
            .cipher
            .encrypt_inout_detached(&head.f_counter.into(), &[], InOutBuf::from(pt))
            .map_err(|_| HandshakeError::EncryptionFailure)?
            .into());

        Ok(())
    }
}

impl Decryptor {
    /// Decrypt a packet and return the nonce
    /// used for replay protection.
    #[must_use = "Result of decryption must be checked to ensure authentication"]
    fn decrypt(&self, packet: &mut [u8]) -> Result<u64, HandshakeError> {
        // "parse" message
        let (head, rest): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
            LayoutVerified::new_from_prefix(&mut packet[..])
                .ok_or(HandshakeError::InvalidMessageFormat)?;

        let (ct, tag): (&mut [u8], LayoutVerified<&mut [u8], Tag>) =
            LayoutVerified::new_from_suffix(rest) //
                .ok_or(HandshakeError::InvalidMessageFormat)?;

        // decrypt the ciphertext
        self.cipher
            .decrypt_inout_detached(
                &head.f_counter.into(),
                &[],
                InOutBuf::from(ct),
                &tag.0.into(),
            )
            .map_err(|_| HandshakeError::DecryptionFailure)?;

        // sanity checks
        debug_assert_eq!(
            head.f_type, //
            U32::new(TYPE_TRANSPORT),
            "Packet mismatch, this should never happen"
        );
        debug_assert_eq!(
            head.f_receiver, self.id,
            "ID mismatch, *after* successful decryption."
        );
        Ok(head.f_counter.into())
    }
}

impl SymKey {
    fn encrypt(&self, pt: &mut [u8], tag: &mut Tag, nonce: u64) {
        let nonce: [u8; 8] = nonce.to_le_bytes();
        let nonce: chacha20poly1305::Nonce = [
            0x0, 0x0, 0x0, 0x0, //
            nonce[0], nonce[1], nonce[2], nonce[3], //
            nonce[4], nonce[5], nonce[6], nonce[7], //
        ]
        .into();
        let cipher = ChaCha20Poly1305::new(&self.0.into());
        let tag = cipher
            .encrypt_inout_detached(&nonce, &[], InOutBuf::from(pt))
            .unwrap();
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(self.0.as_ref()));
        let mut plaintext = ciphertext.to_vec();
        cipher
            .decrypt_in_place(&[], aad, &mut plaintext)
            .map_err(|_| HandshakeError::CryptoError)?;
        Ok(plaintext)
    }
}

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
