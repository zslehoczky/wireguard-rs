// Integration tests for WireGuard handshake

mod common;

use common::MockInstant;
use core::net::SocketAddr;
use core::time::Duration;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use wg_crypto::{Device, Message, Output, SecretBytes, StdTimestamp};
use x25519_dalek::{PublicKey, StaticSecret};

fn setup_devices<R: RngCore + CryptoRng, O: Default>(
    rng1: &mut R,
    rng2: &mut R,
    rng3: &mut R,
) -> (
    PublicKey,
    Device<O, MockInstant, StdTimestamp>,
    PublicKey,
    Device<O, MockInstant, StdTimestamp>,
) {
    // generate new key pairs
    let sk1 = StaticSecret::random_from_rng(rng1);
    let pk1 = PublicKey::from(&sk1);

    let sk2 = StaticSecret::random_from_rng(rng2);
    let pk2 = PublicKey::from(&sk2);

    // pick random psk
    let mut psk = [0u8; 32];
    rng3.fill_bytes(&mut psk[..]);

    // initialize devices on both ends
    let mut dev1 = Device::new();
    let mut dev2 = Device::new();

    dev1.set_sk(Some(sk1));
    dev2.set_sk(Some(sk2));

    dev1.add(pk2, O::default()).unwrap();
    dev2.add(pk1, O::default()).unwrap();

    dev1.set_psk(pk2, SecretBytes(psk)).unwrap();
    dev2.set_psk(pk1, SecretBytes(psk)).unwrap();

    (pk1, dev1, pk2, dev2)
}

/// Test longest possible handshake interaction (7 messages):
///
/// 1. I -> R (initiation)
/// 2. I <- R (cookie reply)
/// 3. I -> R (initiation)
/// 4. I <- R (response)
/// 5. I -> R (cookie reply)
/// 6. I -> R (initiation)
/// 7. I <- R (response)
#[test]
fn handshake_under_load() {
    let (_pk1, dev1, pk2, dev2): (_, Device<usize, MockInstant, StdTimestamp>, _, _) =
        setup_devices(&mut OsRng, &mut OsRng, &mut OsRng);

    let now = MockInstant::default();
    let src1: SocketAddr = "172.16.0.1:8080".parse().unwrap();
    let src2: SocketAddr = "172.16.0.2:7070".parse().unwrap();

    // 1. device-1 : create first initiation
    let msg_init = dev1.begin(now, &mut OsRng, &pk2).unwrap();

    // 2. device-2 : responds with CookieReply
    let msg_cookie: Message = match dev2
        .process(now, &mut OsRng, msg_init.as_ref(), Some(src1))
        .unwrap()
    {
        Output { msg, .. } => msg.unwrap(),
    };

    // device-1 : processes CookieReply (no response)
    match dev1
        .process(now, &mut OsRng, msg_cookie.as_ref(), Some(src2))
        .unwrap()
    {
        Output {
            id: None,
            msg: None,
            key_pair: None,
        } => (),
        _ => panic!("unexpected response"),
    }

    // avoid initiation flood detection
    let now = now + Duration::from_millis(20);

    // 3. device-1 : create second initiation
    let msg_init = dev1.begin(now, &mut OsRng, &pk2).unwrap();

    // 4. device-2 : responds with noise response
    let msg_response = match dev2
        .process(now, &mut OsRng, msg_init.as_ref(), Some(src1))
        .unwrap()
    {
        Output {
            id: _,
            msg: Some(msg),
            key_pair: Some(kp),
        } => {
            assert_eq!(kp.initiator, false);
            msg
        }
        _ => panic!("unexpected response"),
    };

    // 5. device-1 : responds with CookieReply
    let msg_cookie = match dev1
        .process(now, &mut OsRng, msg_response.as_ref(), Some(src2))
        .unwrap()
    {
        Output {
            id: None,
            msg: Some(msg),
            key_pair: None,
        } => msg,
        _ => panic!("unexpected response"),
    };

    // device-2 : processes CookieReply (no response)
    match dev2
        .process(now, &mut OsRng, msg_cookie.as_ref(), Some(src1))
        .unwrap()
    {
        Output {
            id: None,
            msg: None,
            key_pair: None,
        } => (),
        _ => panic!("unexpected response"),
    }

    // avoid initiation flood detection
    let now = now + Duration::from_millis(20);

    // 6. device-1 : create third initiation
    let msg_init = dev1.begin(now, &mut OsRng, &pk2).unwrap();

    // 7. device-2 : responds with noise response
    let (msg_response, kp1) = match dev2
        .process(now, &mut OsRng, msg_init.as_ref(), Some(src1))
        .unwrap()
    {
        Output {
            id: Some(_),
            msg: Some(msg),
            key_pair: Some(kp),
        } => {
            assert_eq!(kp.initiator, false);
            (msg, kp)
        }
        _ => panic!("unexpected response"),
    };

    // device-1 : process noise response
    let kp2 = match dev1
        .process(now, &mut OsRng, msg_response.as_ref(), Some(src2))
        .unwrap()
    {
        Output {
            id: Some(_),
            msg: None,
            key_pair: Some(kp),
        } => {
            assert_eq!(kp.initiator, true);
            kp
        }
        _ => panic!("unexpected response"),
    };

    assert_eq!(kp1.send, kp2.recv);
    assert_eq!(kp1.recv, kp2.send);
}

#[test]
fn handshake_no_load() {
    let (pk1, mut dev1, pk2, mut dev2): (_, Device<usize, MockInstant, StdTimestamp>, _, _) =
        setup_devices(&mut OsRng, &mut OsRng, &mut OsRng);

    // do a few handshakes (every handshake should succeed)
    let mut now = MockInstant::default();
    for i in 0..10 {
        println!("handshake : {}", i);

        // create initiation
        let msg1 = dev1.begin(now, &mut OsRng, &pk2).unwrap();

        println!("msg1 = {:?} : {} bytes", msg1, msg1.as_ref().len());

        // process initiation and create response
        let Output {
            id: _,
            msg: msg2,
            key_pair: ks_r,
        } = dev2
            .process(now, &mut OsRng, msg1.as_ref(), None)
            .expect("failed to process initiation");

        let ks_r = ks_r.expect("failed to generate key pair");
        let msg2 = msg2.expect("failed to generate response");

        println!("msg2 = {:?} : {} bytes", msg2, msg2.as_ref().len());
        assert!(!ks_r.initiator, "Responders key-pair is confirmed");

        // process response and obtain confirmed key-pair
        let Output {
            id: _,
            msg: msg3,
            key_pair: ks_i,
        } = dev1
            .process(now, &mut OsRng, msg2.as_ref(), None)
            .expect("failed to process response");
        let ks_i = ks_i.expect("failed to generate key pair");

        assert!(msg3.is_none(), "Returned message after response");
        assert!(ks_i.initiator, "Initiators key-pair is not confirmed");

        assert_eq!(ks_i.send, ks_r.recv, "KeyI.send != KeyR.recv");
        assert_eq!(ks_i.recv, ks_r.send, "KeyI.recv != KeyR.send");

        dev1.release(ks_i.local_id());
        dev2.release(ks_r.local_id());

        // avoid initiation flood detection
        now = now + Duration::from_millis(20);
    }

    dev1.remove(&pk2).unwrap();
    dev2.remove(&pk1).unwrap();
}
