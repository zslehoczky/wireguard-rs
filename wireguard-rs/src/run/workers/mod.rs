pub mod handshake;
mod line_reader;
pub mod tun;
pub mod uapi;

use std::num::NonZeroUsize;
use std::thread;

use wg_platform as plt;
use wg_traits::{
    tun::{Status, Tun},
    uapi::PlatformUAPI,
    udp::PlatformUDP,
};

use crate::wireguard::{HandshakeJob, WireGuard};

use handshake::spawn_handshake_workers;
use tun::{spawn_tun_event_loop, spawn_tun_workers};
use uapi::{spawn_config_worker, spawn_uapi_server};

pub fn run_workers<S: Status, T: Tun, B: PlatformUDP>(
    uapi_socket: <plt::UAPI as PlatformUAPI>::Bind,
    tun_readers: Vec<T::Reader>,
    tun_status: S,
    handshake_receiver: crossbeam_channel::Receiver<HandshakeJob<B::Endpoint>>,
    n_handshake_workers: NonZeroUsize,
    wireguard_device: WireGuard<T, B>,
) {
    thread::scope(|thread_scope| {
        spawn_handshake_workers(
            thread_scope,
            &wireguard_device,
            handshake_receiver,
            n_handshake_workers,
        );

        let tun_reader_jobs = spawn_tun_workers(thread_scope, &wireguard_device, tun_readers);

        let (config_sender, config_receiver) = crossbeam_channel::unbounded();

        // config producers
        let tun_event_loop = spawn_tun_event_loop(tun_status, config_sender.clone());
        let uapi_server = spawn_uapi_server(uapi_socket, config_sender);

        // config consumer
        spawn_config_worker(thread_scope, &wireguard_device, config_receiver);

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
