use std::process::exit;
use std::sync::atomic::Ordering;
use std::thread::{self, ScopedJoinHandle};

use log::{debug, error, trace};

use wg_traits::{
    tun::{Reader as TunReader, Status, Tun, TunEvent},
    udp::{PlatformUDP, UDP},
};

use crate::router::{CAPACITY_MESSAGE_POSTFIX, SIZE_MESSAGE_PREFIX};
use crate::run::{error::ExitCode, profiler::profiler_stop};
use crate::wireguard::{WireGuard, constants::MESSAGE_PADDING_MULTIPLE};

use super::uapi::ConfigMessage;

pub fn spawn_tun_workers<'scope, 'env, T: Tun, B: PlatformUDP>(
    thread_scope: &'scope thread::Scope<'scope, 'env>,
    wireguard_device: &'env WireGuard<T, B>,
    tun_readers: Vec<T::Reader>,
) -> Vec<ScopedJoinHandle<'scope, ()>> {
    tun_readers
        .into_iter()
        .map(|tun_reader| {
            thread_scope.spawn(|| {
                tun_worker(wireguard_device, tun_reader);
            })
        })
        .collect()
}

pub fn tun_event_loop_worker<S: Status>(
    mut tun_status: S,
    config_sender: crossbeam_channel::Sender<ConfigMessage>,
) {
    loop {
        match tun_status.event() {
            Err(e) => {
                log::error!("Tun device error {}", e);
                profiler_stop();
                exit(ExitCode::TUNDeviceError as i32);
            }
            Ok(TunEvent::Up(mtu)) => {
                config_sender
                    .send(ConfigMessage::TunUp(mtu))
                    .expect("channel is open while this loop is running");
            }
            Ok(TunEvent::Down) => {
                config_sender
                    .send(ConfigMessage::TunDown)
                    .expect("channel is open while this loop is running");
            }
        }
    }
}

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
