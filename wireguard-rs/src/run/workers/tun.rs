use std::process::exit;
use std::thread::{self, JoinHandle, ScopedJoinHandle};

use wg_traits::{
    tun::{Status, Tun, TunEvent},
    udp::PlatformUDP,
};

use crate::run::{error::ExitCode, profiler::profiler_stop};
use crate::wireguard::{WireGuard, tun_worker};

use super::uapi::ConfigMessage;

pub fn spawn_tun_event_loop<S: Status>(
    mut tun_status: S,
    config_sender: crossbeam_channel::Sender<ConfigMessage>,
) -> JoinHandle<()> {
    thread::spawn(move || {
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
    })
}

pub fn spawn_tun_readers<'scope, 'env, T: Tun, B: PlatformUDP>(
    thread_scope: &'scope thread::Scope<'scope, 'env>,
    wireguard_device: &'env WireGuard<T, B>,
    tun_readers: Vec<T::Reader>,
) -> Vec<ScopedJoinHandle<'scope, ()>> {
    tun_readers
        .into_iter()
        .map(|reader| {
            thread_scope.spawn(|| {
                tun_worker(wireguard_device, reader);
            })
        })
        .collect()
}
