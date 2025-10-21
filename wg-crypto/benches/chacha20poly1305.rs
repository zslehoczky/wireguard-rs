use aead::{AeadInOut, KeyInit};
use bencher::{Bencher, benchmark_group, benchmark_main};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::ChaCha20Poly1305;
use hybrid_array::Array;
use inout::InOutBuf;
use poly1305::Poly1305;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce as RingNonce, UnboundKey};

fn rust_chacha20poly1305(bench: &mut Bencher) {
    const N: usize = 1400;

    let key = [
        0x6b, 0x8a, 0x54, 0x8f, 0xf0, 0xa4, 0x4a, 0x5c, //
        0xeb, 0x8c, 0x29, 0x32, 0x7e, 0x62, 0xda, 0x63, //
        0xda, 0xad, 0xf6, 0xb1, 0x2e, 0x92, 0x9b, 0xd5, //
        0xc7, 0xc9, 0x02, 0xc0, 0x66, 0xef, 0xf0, 0x94,
    ];

    let pt = vec![0u8; N];
    let mut ct = vec![0u8; N];
    let mut cnt: u64 = 0;

    bench.iter(|| {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&cnt.to_le_bytes());
        let nonce_array = Array::try_from(&nonce[..]).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let buf = InOutBuf::new(&pt, &mut ct).expect("buffer length mismatch");
        let _tag = cipher
            .encrypt_inout_detached(&nonce_array, &[], buf)
            .unwrap();
        cnt += 1;
    });
    bench.bytes = N as u64;
}

fn rust_chacha20(bench: &mut Bencher) {
    const N: usize = 1400;

    let mut pt = vec![0u8; N];
    let mut cnt: u64 = 0;

    let key = [
        0x6b, 0x8a, 0x54, 0x8f, 0xf0, 0xa4, 0x4a, 0x5c, //
        0xeb, 0x8c, 0x29, 0x32, 0x7e, 0x62, 0xda, 0x63, //
        0xda, 0xad, 0xf6, 0xb1, 0x2e, 0x92, 0x9b, 0xd5, //
        0xc7, 0xc9, 0x02, 0xc0, 0x66, 0xef, 0xf0, 0x94,
    ];
    let key = Array::try_from(&key[..]).unwrap();

    bench.iter(|| {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&cnt.to_le_bytes());
        let nonce_array = Array::try_from(&nonce[..]).unwrap();
        let mut cipher = chacha20::ChaCha20::new(&key, &nonce_array);
        cipher.apply_keystream(&mut pt);
        cnt += 1;
    });

    bench.bytes = N as u64;
}

fn rust_poly1305(bench: &mut Bencher) {
    const N: usize = 1400;

    let ct = vec![0u8; N];

    let key = [
        0x6b, 0x8a, 0x54, 0x8f, 0xf0, 0xa4, 0x4a, 0x5c, //
        0xeb, 0x8c, 0x29, 0x32, 0x7e, 0x62, 0xda, 0x63, //
        0xda, 0xad, 0xf6, 0xb1, 0x2e, 0x92, 0x9b, 0xd5, //
        0xc7, 0xc9, 0x02, 0xc0, 0x66, 0xef, 0xf0, 0x94,
    ];

    let key = Array::try_from(&key[..]).unwrap();

    bench.iter(|| {
        let mac = Poly1305::new(&key);
        mac.compute_unpadded(&ct);
    });

    bench.bytes = N as u64;
}

fn ring_chacha20poly1305(bench: &mut Bencher) {
    const N: usize = 1400;

    let mut pt = vec![0u8; N];
    let mut cnt: u64 = 0;

    let key = [
        0x6b, 0x8a, 0x54, 0x8f, 0xf0, 0xa4, 0x4a, 0x5c, //
        0xeb, 0x8c, 0x29, 0x32, 0x7e, 0x62, 0xda, 0x63, //
        0xda, 0xad, 0xf6, 0xb1, 0x2e, 0x92, 0x9b, 0xd5, //
        0xc7, 0xc9, 0x02, 0xc0, 0x66, 0xef, 0xf0, 0x94,
    ];

    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap());

    bench.iter(|| {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&cnt.to_le_bytes());
        let nonce = RingNonce::assume_unique_for_key(nonce);
        let _tag = key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut pt)
            .unwrap();
        cnt += 1;
    });

    bench.bytes = N as u64;
}

benchmark_group!(
    benches,
    rust_chacha20poly1305,
    rust_chacha20,
    rust_poly1305,
    ring_chacha20poly1305
);
benchmark_main!(benches);
