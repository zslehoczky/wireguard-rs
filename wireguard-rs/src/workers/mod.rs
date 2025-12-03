mod constants;
pub mod handshake;
mod line_reader;
pub mod tun;
pub mod uapi;
pub mod udp;

use std::num::NonZeroUsize;
use std::thread;

use x25519_dalek::PublicKey;

use wg_platform as plt;
use wg_traits::{
    tun::{Status, Tun},
    uapi::PlatformUAPI,
    udp::PlatformUDP,
};

use crate::wireguard::{WireGuard, WireGuardConfig};

pub use handshake::spawn_handshake_workers;
pub use tun::spawn_tun_workers;
use tun::tun_event_loop_worker;
use uapi::{config_worker, uapi_server_worker};
pub use udp::udp_worker;

pub enum HandshakeJob<E> {
    Message(Vec<u8>, E),
    New(PublicKey),
}

pub fn run_workers<S: Status, T: Tun, B: PlatformUDP>(
    uapi_socket: <plt::UAPI as PlatformUAPI>::Bind,
    tun_readers: Vec<T::Reader>,
    tun_status: S,
    handshake_receiver: crossbeam_channel::Receiver<HandshakeJob<B::Endpoint>>,
    n_handshake_workers: NonZeroUsize,
    wireguard_device: WireGuard<T, B>,
) {
    thread::scope(|thread_scope| {
        wireguard_device.add_handshake_reader(
            thread_scope,
            handshake_receiver,
            n_handshake_workers,
        );

        let tun_reader_jobs = wireguard_device.add_tun_readers(thread_scope, tun_readers);

        let (config_sender, config_receiver) = crossbeam_channel::unbounded();

        // config producers
        let tun_event_loop = thread::spawn({
            let config_sender = config_sender.clone();
            || {
                tun_event_loop_worker(tun_status, config_sender);
            }
        });
        let uapi_server = thread::spawn(|| {
            uapi_server_worker(uapi_socket, config_sender);
        });

        // config consumer
        thread_scope.spawn(|| {
            let mut wireguard_config = WireGuardConfig::new(&wireguard_device);
            config_worker(&mut wireguard_config, config_receiver);
        });

        // wait until tun device is disconnected
        for handle in tun_reader_jobs {
            let _ = handle.join();
        }

        // signal shutdown to async workers (by closing producer channels)
        wireguard_device.close_handshake_queue();

        let _ = tun_event_loop.join();
        let _ = uapi_server.join();

        // scoped threads joined here
    })
}
