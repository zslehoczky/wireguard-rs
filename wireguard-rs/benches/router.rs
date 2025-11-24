use bencher::{Bencher, benchmark_group, benchmark_main};
use wg_platform::dummy;
use wireguard_rs::router::{Device, KeyPair, SIZE_MESSAGE_PREFIX, TimerState};

use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use std::convert::TryInto;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::available_parallelism;
use std::time::Instant;
use wg_crypto as crypto;
use wg_crypto::SymKey;

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

struct BencherCallbacks {
    sent: AtomicUsize,
    recv: AtomicUsize,
}

impl BencherCallbacks {
    fn new() -> BencherCallbacks {
        BencherCallbacks {
            sent: AtomicUsize::new(0),
            recv: AtomicUsize::new(0),
        }
    }

    fn reset(&self) {
        self.sent.store(0, Ordering::SeqCst);
        self.recv.store(0, Ordering::SeqCst);
    }

    fn sent(&self) -> usize {
        self.sent.load(Ordering::Acquire)
    }
}

impl TimerState for BencherCallbacks {
    fn send(&self, size: usize, _sent: bool, _keypair: &Arc<KeyPair>, _counter: u64) {
        self.sent.fetch_add(size, Ordering::SeqCst);
    }
    fn recv(&self, size: usize, _sent: bool, _keypair: &Arc<KeyPair>) {
        self.recv.fetch_add(size, Ordering::SeqCst);
    }
    fn need_key(&self) {}
    fn key_confirmed(&self) {}
}

fn bench_router_outbound(b: &mut Bencher) {
    // 10 GB transmission per iteration
    const BYTES_PER_ITER: usize = 100 * 1024 * 1024 * 1024;

    // inner payload of IPv4 packet is 1440 bytes
    const BYTES_PER_PACKET: usize = 1440;

    // create device
    let (_fake, _reader, tun_writer, _mtu) = dummy::TunTest::create(false);
    let router: Device<_, BencherCallbacks, dummy::TunWriter, dummy::VoidBind> = Device::new(
        available_parallelism()
            .expect("parallelism info should be available")
            .get(),
        tun_writer,
    );

    // add peer to router
    let opaque = BencherCallbacks::new();
    let peer = router.new_peer(opaque);
    peer.add_keypair(dummy_keypair(true));

    // add subnet to peer
    let (mask, len, dst) = ("192.168.1.0", 24, "192.168.1.20");
    let mask: IpAddr = mask.parse().unwrap();
    peer.add_allowed_ip(mask, len);

    // create "IP packet"
    let dst = dst.parse().unwrap();
    let src = match dst {
        IpAddr::V4(_) => "127.0.0.1".parse().unwrap(),
        IpAddr::V6(_) => "::1".parse().unwrap(),
    };
    let packet = make_packet(BYTES_PER_PACKET, src, dst, 0);

    // suffix with zero and reserve capacity for tag
    // (normally done to enable in-place transport message construction)
    let mut msg = pad(&packet);
    msg.reserve(16);

    let opaque = peer.get_timer_state();
    // repeatedly transmit 10 GB
    b.iter(|| {
        opaque.reset();
        while opaque.sent() < BYTES_PER_ITER / packet.len() {
            router
                .send(msg.to_vec())
                .expect("failed to crypto-route packet");
        }
    });
}

benchmark_group!(benches, bench_router_outbound);
benchmark_main!(benches);
