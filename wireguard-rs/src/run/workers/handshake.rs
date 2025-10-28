use std::num::NonZeroUsize;
use std::thread::{self, ScopedJoinHandle};

use wg_traits::{tun::Tun, udp::PlatformUDP};

use crate::wireguard::{HandshakeJob, WireGuard, handshake_worker};

pub fn spawn_handshake_workers<'scope, 'env, T: Tun, B: PlatformUDP>(
    thread_scope: &'scope thread::Scope<'scope, 'env>,
    wireguard_device: &'env WireGuard<T, B>,
    handshake_receiver: crossbeam_channel::Receiver<HandshakeJob<B::Endpoint>>,
    n_workers: NonZeroUsize,
) -> Vec<ScopedJoinHandle<'scope, ()>> {
    (0..n_workers.get())
        .map(|_| {
            let handshake_receiver = handshake_receiver.clone();
            thread_scope.spawn(|| handshake_worker(wireguard_device, handshake_receiver))
        })
        .collect()
}
