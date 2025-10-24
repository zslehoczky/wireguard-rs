use std::sync::atomic::Ordering;

use log::{debug, error, trace};

use wg_traits::{
    tun::{Reader as TunReader, Tun},
    udp::UDP,
};

use crate::wireguard::{
    WireGuard,
    constants::MESSAGE_PADDING_MULTIPLE,
    router::{CAPACITY_MESSAGE_POSTFIX, SIZE_MESSAGE_PREFIX},
};

///
/// Returns the padded length of a message:
///
/// ### Arguments
///
/// - `size` : Size of unpadded message
/// - `mtu` : Maximum transmission unit of the device
///
/// ### Returns
///
/// The padded length (always less than or equal to the MTU)
///
#[inline(always)]
const fn padding(size: usize, mtu: usize) -> usize {
    #[inline(always)]
    const fn min(a: usize, b: usize) -> usize {
        let m = (a < b) as usize;
        a * m + (1 - m) * b
    }
    let pad = MESSAGE_PADDING_MULTIPLE;
    min(mtu, size + (pad - size % pad) % pad)
}

pub fn tun_worker<T: Tun, B: UDP>(wg: &WireGuard<T, B>, reader: T::Reader) {
    loop {
        // create vector big enough for any transport message (based on MTU)
        let mtu = wg.mtu.load(Ordering::Relaxed);
        let size = mtu + SIZE_MESSAGE_PREFIX + 1;
        let mut msg: Vec<u8> = vec![0; size + CAPACITY_MESSAGE_POSTFIX];

        // read a new IP packet
        let payload = match reader.read(&mut msg[..], SIZE_MESSAGE_PREFIX) {
            Ok(payload) => payload,
            Err(e) => {
                error!("TUN worker, failed to read from tun device: {}", e);
                break;
            }
        };
        debug!("TUN worker, IP packet of {} bytes (MTU = {})", payload, mtu);

        // check if device is down
        if mtu == 0 {
            continue;
        }

        // truncate padding
        let padded = padding(payload, mtu);
        trace!(
            "TUN worker, payload length = {}, padded length = {}",
            payload, padded
        );
        msg.truncate(SIZE_MESSAGE_PREFIX + padded);
        debug_assert!(padded <= mtu);
        debug_assert_eq!(
            if padded < mtu {
                (msg.len() - SIZE_MESSAGE_PREFIX) % MESSAGE_PADDING_MULTIPLE
            } else {
                0
            },
            0
        );

        // crypt-key route
        let e = wg.router.send(msg);
        debug!("TUN worker, router returned {:?}", e);
    }
}
