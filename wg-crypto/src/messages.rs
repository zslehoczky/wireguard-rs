use crate::{
    PublicKey, TAI64N,
    aead::{Tag, XNonce},
    macs::MAC,
    types::*,
};
use byteorder::LittleEndian;
use zerocopy::{
    AsBytes, ByteSlice, FromBytes, LayoutVerified,
    byteorder::{U32, U64},
};

pub const SIZE_COOKIE: usize = 16; //
pub const SIZE_X25519_POINT: usize = 32; // x25519 public key
pub const SIZE_TIMESTAMP: usize = 12;

pub const TYPE_INITIATION: u32 = 1;
pub const TYPE_RESPONSE: u32 = 2;
pub const TYPE_COOKIE_REPLY: u32 = 3;
pub const TYPE_TRANSPORT: u32 = 4;

pub type Cookie = [u8; SIZE_COOKIE];
pub type Point = [u8; SIZE_X25519_POINT];

#[repr(C, packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct Counter(U64<LittleEndian>);

impl Into<u64> for Counter {
    fn into(self) -> u64 {
        self.0.get()
    }
}

impl From<u64> for Counter {
    fn from(value: u64) -> Self {
        Counter(U64::new(value))
    }
}

impl Into<chacha20poly1305::Nonce> for Counter {
    fn into(self) -> chacha20poly1305::Nonce {
        let n = self.0.as_bytes();
        [
            0x00, 0x00, 0x00, 0x00, //
            n[0], n[1], n[2], n[3], //
            n[4], n[5], n[6], n[7], //
        ]
        .into()
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct TransportHeader {
    pub f_type: U32<LittleEndian>,
    pub f_receiver: Identifier,
    pub f_counter: Counter,
}

#[repr(C, packed)]
#[derive(Copy, Clone, FromBytes, AsBytes, Debug, PartialEq, Eq)]
pub struct Response {
    pub noise: NoiseResponse, // inner message covered by macs
    pub macs: MACFooter,
}

#[repr(C, packed)]
#[derive(Copy, Clone, FromBytes, AsBytes, Debug, PartialEq, Eq)]
pub struct Initiation {
    pub noise: NoiseInitiation, // inner message covered by macs
    pub macs: MACFooter,
}

#[repr(C, packed)]
#[derive(Copy, Clone, FromBytes, AsBytes, Debug, PartialEq, Eq)]
pub struct CookieReply {
    pub f_type: U32<LittleEndian>, // message type
    pub f_receiver: Identifier,    // receiver id
    pub f_nonce: XNonce,           // xchacha20poly1305 nonce
    pub f_cookie: Cookie,          // encrypted cookie
    pub f_cookie_tag: Tag,         // encrypted cookie tag
}

#[repr(C, packed)]
#[derive(Copy, Clone, FromBytes, AsBytes, Debug, PartialEq, Eq)]
pub struct MACFooter {
    pub f_mac1: MAC,
    pub f_mac2: MAC,
}

#[repr(C, packed)]
#[derive(Copy, Clone, FromBytes, AsBytes, Debug, PartialEq, Eq)]
pub struct NoiseInitiation {
    pub f_type: U32<LittleEndian>, // message type
    pub f_sender: Identifier,      // sender id
    pub f_ephemeral: PublicKey,    // ephemeral key
    pub f_static: PublicKey,       // encrypted static key
    pub f_static_tag: Tag,         // encrypted static key tag
    pub f_timestamp: TAI64N,       // encrypted timestamp
    pub f_timestamp_tag: Tag,      // encrypted timestamp tag
}

#[repr(C, packed)]
#[derive(Copy, Clone, FromBytes, AsBytes, Debug, PartialEq, Eq)]
pub struct NoiseResponse {
    pub f_type: U32<LittleEndian>, // message type
    pub f_sender: Identifier,      // sender id
    pub f_receiver: Identifier,    // receiver id
    pub f_ephemeral: PublicKey,    // ephemeral key
    pub f_empty_tag: Tag,          // empty tag
}

impl Initiation {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.noise.f_type.get() != TYPE_INITIATION {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        Ok(msg)
    }
}

impl Response {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.noise.f_type.get() != TYPE_RESPONSE {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        Ok(msg)
    }
}

impl CookieReply {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.f_type.get() != TYPE_COOKIE_REPLY {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_response_identity() {
        let msg: Response = Response {
            noise: NoiseResponse {
                f_type: U32::new(TYPE_RESPONSE),
                f_sender: Identifier::from(146252),
                f_receiver: Identifier::from(554442),
                f_ephemeral: PublicKey([
                    0xc1, 0x66, 0x0a, 0x0c, 0xdc, 0x0f, 0x6c, 0x51, //
                    0x0f, 0xc2, 0xcc, 0x51, 0x52, 0x0c, 0xde, 0x1e, //
                    0xf7, 0xf1, 0xca, 0x90, 0x86, 0x72, 0xad, 0x67, //
                    0xea, 0x89, 0x45, 0x44, 0x13, 0x56, 0x52, 0x1f,
                ]),
                f_empty_tag: Tag([
                    0x60, 0x0e, 0x1e, 0x95, 0x41, 0x6b, 0x52, 0x05, //
                    0xa2, 0x09, 0xe1, 0xbf, 0x40, 0x05, 0x2f, 0xde,
                ]),
            },
            macs: MACFooter {
                f_mac1: MAC([
                    0xf2, 0xad, 0x40, 0xb5, 0xf7, 0xde, 0x77, 0x35, //
                    0x89, 0x19, 0xb7, 0x5c, 0xf9, 0x54, 0x69, 0x29,
                ]),
                f_mac2: MAC([
                    0x4f, 0xd2, 0x1b, 0xfe, 0x77, 0xe6, 0x2e, 0xc9, //
                    0x07, 0xe2, 0x87, 0x17, 0xbb, 0xe5, 0xdf, 0xbb,
                ]),
            },
        };
        let buf: Vec<u8> = msg.as_bytes().to_vec();
        let msg_p = Response::parse(&buf[..]).unwrap();
        assert_eq!(msg, *msg_p.into_ref());
    }

    #[test]
    fn message_initiate_identity() {
        let msg = Initiation {
            noise: NoiseInitiation {
                f_type: U32::new(TYPE_INITIATION),
                f_sender: 575757.into(),
                f_ephemeral: PublicKey([
                    0xc1, 0x66, 0x0a, 0x0c, 0xdc, 0x0f, 0x6c, 0x51, //
                    0x0f, 0xc2, 0xcc, 0x51, 0x52, 0x0c, 0xde, 0x1e, //
                    0xf7, 0xf1, 0xca, 0x90, 0x86, 0x72, 0xad, 0x67, //
                    0xea, 0x89, 0x45, 0x44, 0x13, 0x56, 0x52, 0x1f,
                ]),
                f_static: PublicKey([
                    0xdc, 0x33, 0x90, 0x15, 0x8f, 0x82, 0x3e, 0x06, //
                    0x44, 0xa0, 0xde, 0x4c, 0x15, 0x6c, 0x5d, 0xa4, //
                    0x65, 0x99, 0xf6, 0x6c, 0xa1, 0x14, 0x77, 0xf9, //
                    0xeb, 0x6a, 0xec, 0xc3, 0x3c, 0xda, 0x47, 0xe1,
                ]),
                f_static_tag: Tag([
                    0x45, 0xac, 0x8d, 0x43, 0xea, 0x1b, 0x2f, 0x02, //
                    0x45, 0x5d, 0x86, 0x37, 0xee, 0x83, 0x6b, 0x42,
                ]),
                f_timestamp: TAI64N([
                    0x4f, 0x1c, 0x60, 0xec, 0x0e, 0xf6, 0x36, 0xf0, //
                    0x78, 0x28, 0x57, 0x42,
                ]),
                f_timestamp_tag: Tag([
                    0x60, 0x0e, 0x1e, 0x95, 0x41, 0x6b, 0x52, 0x05, //
                    0xa2, 0x09, 0xe1, 0xbf, 0x40, 0x05, 0x2f, 0xde,
                ]),
            },
            macs: MACFooter {
                f_mac1: MAC([
                    0xf2, 0xad, 0x40, 0xb5, 0xf7, 0xde, 0x77, 0x35, //
                    0x89, 0x19, 0xb7, 0x5c, 0xf9, 0x54, 0x69, 0x29,
                ]),
                f_mac2: MAC([
                    0x4f, 0xd2, 0x1b, 0xfe, 0x77, 0xe6, 0x2e, 0xc9, //
                    0x07, 0xe2, 0x87, 0x17, 0xbb, 0xe5, 0xdf, 0xbb,
                ]),
            },
        };
        let buf: Vec<u8> = msg.as_bytes().to_vec();
        let msg_p = Initiation::parse(&buf[..]).unwrap();
        assert_eq!(msg, *msg_p.into_ref());
    }
}
