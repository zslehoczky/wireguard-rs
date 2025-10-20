// Test vector extraction and verification

mod common;

use common::{MockInstant, MockRng, setup_test_device_1, setup_test_device_2};
use wg_crypto::Output;
use x25519_dalek::{PublicKey, StaticSecret};

/// Extract and verify deterministic test vectors
#[test]
fn test_vectors_extraction() {
    // Fixed static keys (from predetermined bytes)
    let sk1_bytes = common::SK1_BYTES;
    let sk2_bytes = common::SK2_BYTES;
    let psk = common::PSK;

    let sk1 = StaticSecret::from(sk1_bytes);
    let pk1 = PublicKey::from(&sk1);

    let sk2 = StaticSecret::from(sk2_bytes);
    let pk2 = PublicKey::from(&sk2);

    println!("Input Parameters:");
    println!("Static Key 1 (secret): {}", hex::encode(&sk1_bytes));
    println!("Static Key 1 (public): {}", hex::encode(pk1.as_bytes()));
    println!("Static Key 2 (secret): {}", hex::encode(&sk2_bytes));
    println!("Static Key 2 (public): {}", hex::encode(pk2.as_bytes()));
    println!("PSK: {}", hex::encode(&psk));
    println!("Fixed Timestamp: Unix 1234567890, nanos 123456789");

    // Initialize devices
    let (dev1, pk2) = setup_test_device_1();
    let (dev2, _pk1) = setup_test_device_2();

    // Use MockRng for deterministic ephemeral keys
    let mut rng1 = MockRng::new(0);  // Initiator ephemeral starts at 0
    let mut rng2 = MockRng::new(100);  // Responder ephemeral starts at 100

    let now = MockInstant::default();

    // Create initiation from dev1 to dev2
    let msg1 = dev1.begin(now, &mut rng1, &pk2).unwrap();
    println!("Initiation: {} bytes, {}", msg1.as_ref().len(), hex::encode(msg1.as_ref()));

    // Process initiation and create response
    let Output {
        id: _,
        msg: msg2,
        key_pair: ks_r,
    } = dev2
        .process(now, &mut rng2, msg1.as_ref(), None)
        .expect("failed to process initiation");

    let ks_r = ks_r.expect("failed to generate key pair");
    let msg2 = msg2.expect("failed to generate response");

    println!("Response: {} bytes, {}", msg2.as_ref().len(), hex::encode(msg2.as_ref()));

    // Process response
    let Output {
        id: _,
        msg: msg3,
        key_pair: ks_i,
    } = dev1
        .process(now, &mut rng1, msg2.as_ref(), None)
        .expect("failed to process response");
    let ks_i = ks_i.expect("failed to generate key pair");

    assert!(msg3.is_none(), "Should not return message after response");

    println!("Initiator send key: {}", hex::encode(&ks_i.send.key.as_ref()));
    println!("Initiator recv key: {}", hex::encode(&ks_i.recv.key.as_ref()));
    println!("Responder send key: {}", hex::encode(&ks_r.send.key.as_ref()));
    println!("Responder recv key: {}", hex::encode(&ks_r.recv.key.as_ref()));

    // Verify keypairs match
    assert_eq!(ks_i.send, ks_r.recv, "KeyI.send != KeyR.recv");
    assert_eq!(ks_i.recv, ks_r.send, "KeyI.recv != KeyR.send");
}

/// Test that initiation message is deterministically generated
#[test]
fn test_initiation_message_deterministic() {
    // Expected test vector
    const EXPECTED_INITIATION: &str = "010000000001020366b76a4535f74c6f464c8f2395cb051864d00279ac88c3fc793fa00352e2ea5a8bfb10257a49104bf43cbb4163db1b0fbc5bb5e3c5910bf4e5fef9423238486374165bc756ea1c61ab6c14a65aaa54552627f2e9f96f1307cb86fe551183758bdc38dbce1f6091d0e5dcd8373dd1b8a1ecad78153239c80e10cceb8500000000000000000000000000000000";

    // Setup devices
    let (dev1, pk2) = setup_test_device_1();
    let mut rng = MockRng::new(0);
    let now = MockInstant::default();

    // Create initiation
    let msg = dev1.begin(now, &mut rng, &pk2).unwrap();

    // Verify it matches expected test vector
    assert_eq!(hex::encode(msg.as_ref()), EXPECTED_INITIATION,
        "Initiation message does not match test vector");
}

/// Test that response message is deterministically generated
#[test]
fn test_response_message_deterministic() {
    const EXPECTED_RESPONSE: &str = "0200000064656667000102037e7c5c7029242d2c69a88b65a089dcdb61806bf92eb758b247df929ea18ac40e8625b3e7473668acf7c985876664e90d7357489c3ebecd03b58d42a2b738412000000000000000000000000000000000";

    // Setup devices
    let (dev1, pk2) = setup_test_device_1();
    let (dev2, _pk1) = setup_test_device_2();

    let mut rng1 = MockRng::new(0);
    let mut rng2 = MockRng::new(100);
    let now = MockInstant::default();

    // Create initiation
    let msg_init = dev1.begin(now, &mut rng1, &pk2).unwrap();

    // Process and create response
    let Output { msg: msg_resp, .. } = dev2
        .process(now, &mut rng2, msg_init.as_ref(), None)
        .expect("failed to process initiation");

    let msg_resp = msg_resp.expect("no response generated");

    // Verify it matches expected test vector
    assert_eq!(hex::encode(msg_resp.as_ref()), EXPECTED_RESPONSE,
        "Response message does not match test vector");
}

/// Test that derived keypairs are deterministic
#[test]
fn test_derived_keypairs_deterministic() {
    const EXPECTED_SEND_KEY_I: &str = "7bf86f91cc6923deb4b0b767dc355c81e8d9f4c04043ef7305e65ce462e9a9ef";
    const EXPECTED_RECV_KEY_I: &str = "970cd42cd8358824a81d9dea77706eb1f33d6b63937bc3381541dda427a0fa65";
    const EXPECTED_SEND_KEY_R: &str = "970cd42cd8358824a81d9dea77706eb1f33d6b63937bc3381541dda427a0fa65";
    const EXPECTED_RECV_KEY_R: &str = "7bf86f91cc6923deb4b0b767dc355c81e8d9f4c04043ef7305e65ce462e9a9ef";

    // Setup devices
    let (dev1, pk2) = setup_test_device_1();
    let (dev2, _pk1) = setup_test_device_2();

    let mut rng1 = MockRng::new(0);
    let mut rng2 = MockRng::new(100);
    let now = MockInstant::default();

    // Full handshake
    let msg_init = dev1.begin(now, &mut rng1, &pk2).unwrap();

    let Output {
        msg: msg_resp,
        key_pair: kp_r,
        ..
    } = dev2.process(now, &mut rng2, msg_init.as_ref(), None)
        .expect("failed to process initiation");

    let kp_r = kp_r.expect("no keypair from responder");
    let msg_resp = msg_resp.expect("no response");

    let Output {
        key_pair: kp_i,
        ..
    } = dev1.process(now, &mut rng1, msg_resp.as_ref(), None)
        .expect("failed to process response");

    let kp_i = kp_i.expect("no keypair from initiator");

    // Verify initiator keypair
    assert_eq!(hex::encode(kp_i.send.key.as_ref()), EXPECTED_SEND_KEY_I,
        "Initiator send key does not match test vector");
    assert_eq!(hex::encode(kp_i.recv.key.as_ref()), EXPECTED_RECV_KEY_I,
        "Initiator recv key does not match test vector");

    // Verify responder keypair
    assert_eq!(hex::encode(kp_r.send.key.as_ref()), EXPECTED_SEND_KEY_R,
        "Responder send key does not match test vector");
    assert_eq!(hex::encode(kp_r.recv.key.as_ref()), EXPECTED_RECV_KEY_R,
        "Responder recv key does not match test vector");

    // Verify keypairs are complementary
    assert_eq!(kp_i.send, kp_r.recv);
    assert_eq!(kp_i.recv, kp_r.send);
}

/// Test that multiple runs produce identical results (true determinism)
#[test]
fn test_complete_handshake_reproducible() {
    // Run handshake 3 times and verify all produce identical results
    let mut initiations = Vec::new();
    let mut responses = Vec::new();

    for _ in 0..3 {
        let (dev1, pk2) = setup_test_device_1();
        let (dev2, _pk1) = setup_test_device_2();

        let mut rng1 = MockRng::new(0);
        let mut rng2 = MockRng::new(100);
        let now = MockInstant::default();

        let msg_init = dev1.begin(now, &mut rng1, &pk2).unwrap();
        initiations.push(msg_init.as_ref().to_vec());

        let Output { msg: msg_resp, .. } = dev2
            .process(now, &mut rng2, msg_init.as_ref(), None)
            .expect("failed to process initiation");

        responses.push(msg_resp.unwrap().as_ref().to_vec());
    }

    // Verify all initiations are identical
    assert_eq!(initiations[0], initiations[1], "First and second initiation differ");
    assert_eq!(initiations[1], initiations[2], "Second and third initiation differ");

    // Verify all responses are identical
    assert_eq!(responses[0], responses[1], "First and second response differ");
    assert_eq!(responses[1], responses[2], "Second and third response differ");
}
