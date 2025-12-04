use std::num::NonZeroUsize;
use std::thread;

use crossbeam_channel::Receiver;
use x25519_dalek::{PublicKey, StaticSecret};

use wg_platform::dummy::{self};

use crate::wireguard::WireGuard;
use crate::workers::HandshakeJob;

use super::{init, make_packet};

fn create_wireguard_device() -> (
    WireGuard<dummy::TunTest, dummy::PairBind>,
    Receiver<HandshakeJob<dummy::UnitEndpoint>>,
    dummy::TunFakeIO,
    dummy::TunReader,
) {
    const HANDSHAKE_QUEUE_SIZE: usize = 1;

    let (handshake_sender, handshake_receiver) = crossbeam_channel::bounded(HANDSHAKE_QUEUE_SIZE);

    let (tun_fake_io, tun_reader, tun_writer, _) = dummy::TunTest::create(true);

    let wireguard_device =
        WireGuard::<dummy::TunTest, dummy::PairBind>::new(tun_writer, handshake_sender);

    (
        wireguard_device,
        handshake_receiver,
        tun_fake_io,
        tun_reader,
    )
}

fn initialize_workers<'scope, 'wireguard>(
    thread_scope: &'scope thread::Scope<'scope, 'wireguard>,
    wireguard_device: &'wireguard WireGuard<dummy::TunTest, dummy::PairBind>,
    handshake_receiver: Receiver<HandshakeJob<dummy::UnitEndpoint>>,
    tun_reader: dummy::TunReader,
    bind_reader: dummy::PairReader<dummy::UnitEndpoint>,
    bind_writer: dummy::PairWriter<dummy::UnitEndpoint>,
) {
    wireguard_device.add_handshake_reader(
        thread_scope,
        handshake_receiver,
        NonZeroUsize::new(1).unwrap(),
    );
    wireguard_device.add_tun_readers(thread_scope, vec![tun_reader]);

    wireguard_device.up(1500);
    wireguard_device.set_writer(bind_writer);
    wireguard_device.add_udp_reader(thread_scope, bind_reader);
}

fn test_pure_wireguard_inner(
    wireguard_device_pair: (
        &WireGuard<dummy::TunTest, dummy::PairBind>,
        &WireGuard<dummy::TunTest, dummy::PairBind>,
    ),
    tun_fake_io_pair: (dummy::TunFakeIO, dummy::TunFakeIO),
) {
    init();

    // configure (public, private) key pairs

    let sk0 = StaticSecret::from([
        0x3f, 0x69, 0x86, 0xd1, 0xc0, 0xec, 0x25, 0xa0, 0x9c, 0x8e, 0x56, 0xb5, 0x1d, 0xb7, 0x3c,
        0xed, 0x56, 0x8e, 0x59, 0x9d, 0xd9, 0xc3, 0x98, 0x67, 0x74, 0x69, 0x90, 0xc3, 0x43, 0x36,
        0x78, 0x89,
    ]);

    let sk1 = StaticSecret::from([
        0xfb, 0xd1, 0xd6, 0xe4, 0x65, 0x06, 0xd2, 0xe5, 0xc5, 0xdf, 0x6e, 0xab, 0x51, 0x71, 0xd8,
        0x70, 0xb5, 0xb7, 0x77, 0x51, 0xb4, 0xbe, 0xfb, 0xbc, 0x88, 0x62, 0x40, 0xca, 0x2c, 0xc2,
        0x66, 0xe2,
    ]);

    let pk0 = PublicKey::from(&sk0);
    let pk1 = PublicKey::from(&sk1);

    let peer_state0 = wireguard_device_pair.1.add_peer(pk0).unwrap();
    let peer_state1 = wireguard_device_pair.0.add_peer(pk1).unwrap();

    wireguard_device_pair.0.set_key(Some(sk0));
    wireguard_device_pair.1.set_key(Some(sk1));

    // configure crypto-key router

    peer_state0
        .get_peer_handle()
        .add_allowed_ip("192.168.1.0".parse().unwrap(), 24);

    peer_state1
        .get_peer_handle()
        .add_allowed_ip("192.168.2.0".parse().unwrap(), 24);

    // set endpoint (the other should be learned dynamically)

    peer_state1
        .get_peer_handle()
        .set_endpoint(dummy::UnitEndpoint);

    let num_packets = 20;

    // send IP packets (causing a new handshake)

    {
        let mut packets: Vec<Vec<u8>> = Vec::with_capacity(num_packets);

        for id in 0..num_packets {
            packets.push(make_packet(
                50 * id,                         // size
                "192.168.1.20".parse().unwrap(), // src
                "192.168.2.10".parse().unwrap(), // dst
                id as u64,                       // prng seed
            ));
        }

        let mut backup = packets.clone();

        while let Some(p) = packets.pop() {
            println!("send");
            tun_fake_io_pair.0.write(p);
        }

        while let Some(p) = backup.pop() {
            println!("read");
            assert_eq!(
                hex::encode(tun_fake_io_pair.1.read()),
                hex::encode(p),
                "Failed to receive valid IPv4 packet unmodified and in-order"
            );
        }
    }

    // send IP packets (other direction)

    {
        let mut packets: Vec<Vec<u8>> = Vec::with_capacity(num_packets);

        for id in 0..num_packets {
            packets.push(make_packet(
                50 + 50 * id,                    // size
                "192.168.2.10".parse().unwrap(), // src
                "192.168.1.20".parse().unwrap(), // dst
                (id + 100) as u64,               // prng seed
            ));
        }

        let mut backup = packets.clone();

        while let Some(p) = packets.pop() {
            tun_fake_io_pair.1.write(p);
        }

        while let Some(p) = backup.pop() {
            assert_eq!(
                hex::encode(tun_fake_io_pair.0.read()),
                hex::encode(p),
                "Failed to receive valid IPv4 packet unmodified and in-order"
            );
        }
    }
}

/* Create and configure
 * two matching pure (no side-effects) instances of WireGuard.
 *
 * Test:
 *
 * - Handshaking completes successfully
 * - All packets up to MTU are delivered
 * - All packets are delivered in-order
 */
#[test]
fn test_pure_wireguard() {
    // create WG instances for dummy TUN devices
    let (wireguard_device_0, handshake_receiver_0, tun_fake_io_0, tun_reader_0) =
        create_wireguard_device();
    let (wireguard_device_1, handshake_receiver_1, tun_fake_io_1, tun_reader_1) =
        create_wireguard_device();

    // create pair bind to connect the interfaces "over the internet"
    let ((bind_reader_0, bind_writer_0), (bind_reader_1, bind_writer_1)) = dummy::PairBind::pair();

    thread::scope(|thread_scope| {
        initialize_workers(
            thread_scope,
            &wireguard_device_0,
            handshake_receiver_0,
            tun_reader_0,
            bind_reader_0,
            bind_writer_0,
        );
        initialize_workers(
            thread_scope,
            &wireguard_device_1,
            handshake_receiver_1,
            tun_reader_1,
            bind_reader_1,
            bind_writer_1,
        );

        let wireguard_device_pair = (&wireguard_device_0, &wireguard_device_1);
        let tun_fake_io_pair = (tun_fake_io_0, tun_fake_io_1);

        test_pure_wireguard_inner(wireguard_device_pair, tun_fake_io_pair);

        wireguard_device_0.down();
        wireguard_device_1.down();

        wireguard_device_0.close_handshake_queue();
        wireguard_device_1.close_handshake_queue();
    });
}
