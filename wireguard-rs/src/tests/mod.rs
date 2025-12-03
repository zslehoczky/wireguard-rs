mod router_tests;
mod wireguard_tests;

use std::convert::TryInto;
use std::net::IpAddr;
use std::time::Instant;

use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use wg_crypto as crypto;
use wg_crypto::SymKey;

use crate::router::{KeyPair, SIZE_MESSAGE_PREFIX};

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn pad(msg: &[u8]) -> Vec<u8> {
    let mut o = vec![0; msg.len() + SIZE_MESSAGE_PREFIX];
    o[SIZE_MESSAGE_PREFIX..SIZE_MESSAGE_PREFIX + msg.len()].copy_from_slice(msg);
    o
}

fn dummy_keypair(initiator: bool) -> KeyPair {
    let k1 = crypto::Key {
        key: SymKey::from([0x53u8; 32]),
        id: 0x646e6573,
    };
    let k2 = crypto::Key {
        key: SymKey::from([0x52u8; 32]),
        id: 0x76636572,
    };
    if initiator {
        KeyPair {
            birth: Instant::now(),
            initiator: true,
            send: k1,
            recv: k2,
        }
    } else {
        KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: k2,
            recv: k1,
        }
    }
}

fn make_packet(size: usize, src: IpAddr, dst: IpAddr, id: u64) -> Vec<u8> {
    // expand pseudo random payload
    let mut rng = ChaCha8Rng::seed_from_u64(id);
    let mut p: Vec<u8> = vec![0; size];
    rng.fill_bytes(&mut p);

    // create "IP packet"
    let mut msg = Vec::with_capacity(size);
    match dst {
        IpAddr::V4(dst) => {
            let length = size + MutableIpv4Packet::minimum_packet_size();
            msg.resize(length, 0);

            let mut packet = MutableIpv4Packet::new(&mut msg[..]).unwrap();
            packet.set_destination(dst);
            packet.set_total_length(length.try_into().expect("length too great for IPv4 packet"));
            packet.set_source(if let IpAddr::V4(src) = src {
                src
            } else {
                panic!("src.version != dst.version")
            });
            packet.set_payload(&p);
            packet.set_version(4);
        }
        IpAddr::V6(dst) => {
            let length = size + MutableIpv6Packet::minimum_packet_size();
            msg.resize(length, 0);

            let mut packet = MutableIpv6Packet::new(&mut msg[..]).unwrap();
            packet.set_destination(dst);
            packet.set_payload_length(size.try_into().expect("length too great for IPv6 packet"));
            packet.set_source(if let IpAddr::V6(src) = src {
                src
            } else {
                panic!("src.version != dst.version")
            });
            packet.set_payload(&p);
            packet.set_version(6);
        }
    }
    msg
}
