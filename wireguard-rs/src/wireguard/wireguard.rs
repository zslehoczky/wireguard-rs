use std::fmt;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use dashmap::DashMap;
use log::debug;
use rand::Rng;
use rand::rngs::OsRng;
use spin::{Mutex, RwLock, RwLockReadGuard};
use x25519_dalek::{PublicKey, StaticSecret};

use wg_crypto::{self as crypto, PSK, StdTimestamp};
use wg_traits::{
    tun::{Tun, Writer as _},
    udp::{self, Reader as _, UDP},
};

use crate::peer::{DeviceInterface, PeerState};
use crate::router::{Router, RouterError};
use crate::workers::{HandshakeJob, spawn_handshake_workers, spawn_tun_workers, udp_worker};

use super::PeerDeps;
use super::constants::TIME_HORIZON;
use super::timers::Timers;
use super::udp_writer::UdpWriter;

type CryptoDevice = crypto::Device<PublicKey, Instant, StdTimestamp>;

pub struct WireguardInner<T: Tun, B: UDP> {
    id: u32, // internal id (for logging)
    enabled: RwLock<bool>,
    mtu: AtomicUsize,
    crypto_device: RwLock<CryptoDevice>,
    peers: DashMap<PublicKey, Arc<PeerState<T, B>>>,
    router: Router<PeerDeps<T, B>>,
    last_under_load: Mutex<Instant>,
    pending: AtomicUsize, // number of pending handshake packets in queue
    handshake_sender: Mutex<Option<Sender<HandshakeJob<B::Endpoint>>>>,
    timers: Timers,
    tun_writer: T::Writer,
    udp_writer: RwLock<UdpWriter<B>>,
}

impl<T: Tun, B: UDP> WireguardInner<T, B> {
    fn new(tun_writer: T::Writer, handshake_sender: Sender<HandshakeJob<B::Endpoint>>) -> Self {
        Self {
            enabled: RwLock::new(false),
            id: OsRng.r#gen(),
            mtu: AtomicUsize::new(0),
            last_under_load: Mutex::new(Instant::now() - TIME_HORIZON),
            router: Router::new(),
            pending: AtomicUsize::new(0),
            crypto_device: RwLock::new(crypto::Device::new()),
            peers: DashMap::default(),
            handshake_sender: Mutex::new(Some(handshake_sender)),
            timers: Timers::new(),
            tun_writer,
            udp_writer: RwLock::new(UdpWriter::default()),
        }
    }
}

impl<T: Tun, B: UDP> DeviceInterface<PeerDeps<T, B>> for WireguardInner<T, B> {
    fn add_receiver(
        &self,
        prev_id: Option<u32>,
        new_id: u32,
        peer: crate::peer::Peer<PeerDeps<T, B>>,
    ) -> Option<u32> {
        self.router.add_receiver(prev_id, new_id, peer)
    }

    fn check_route(&self, peer: &crate::peer::Peer<PeerDeps<T, B>>, packet: &mut [u8]) -> bool {
        self.router.check_route(peer, packet)
    }

    fn insert_route(
        &self,
        ip: std::net::IpAddr,
        cidr: u32,
        peer: crate::peer::Peer<PeerDeps<T, B>>,
    ) {
        self.router.insert_route(ip, cidr, peer);
    }

    fn list_routes(
        &self,
        peer: &crate::peer::Peer<PeerDeps<T, B>>,
    ) -> Vec<(std::net::IpAddr, u32)> {
        self.router.list_routes(peer)
    }

    fn remove_receivers(&self, release: &[u32]) {
        self.router.remove_receivers(release);
    }

    fn remove_route(&self, peer: &crate::peer::Peer<PeerDeps<T, B>>) {
        self.router.remove_route(peer);
    }

    fn write_inbound(&self, data: &[u8]) {
        self.tun_writer.write(data).unwrap_or_else(|e| {
            log::debug!("failed to write inbound packet to TUN: {:?}", e);
        })
    }

    fn write_outbound(&self, msg: &[u8], endpoint: &mut B::Endpoint) -> Result<(), RouterError> {
        self.udp_writer.read().send_checked(msg, endpoint)
    }
}

pub struct WireGuard<T: Tun, B: UDP> {
    inner: Arc<WireguardInner<T, B>>,
}

impl<T: Tun, B: UDP> fmt::Display for WireGuard<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wireguard({:x})", self.id)
    }
}

impl<T: Tun, B: UDP> Deref for WireGuard<T, B> {
    type Target = WireguardInner<T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Tun, B: UDP> Clone for WireGuard<T, B> {
    fn clone(&self) -> Self {
        WireGuard {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Tun, B: UDP> WireGuard<T, B> {
    /// Brings the WireGuard device down.
    /// Usually called when the associated interface is brought down.
    ///
    /// This stops any further action/timer on any peer
    /// and prevents transmission of further messages,
    /// however the device retrains its state.
    ///
    /// The instance will continue to consume and discard messages
    /// on both ends of the device.
    pub fn down(&self) {
        // ensure exclusive access (to avoid race with "up" call)
        let mut enabled = self.enabled.write();

        // check if already down
        if !(*enabled) {
            return;
        }

        // set mtu
        self.mtu.store(0, Ordering::Relaxed);

        // disable transmission
        self.udp_writer.write().set_enabled(false);

        // set all peers down (stops timers)
        self.for_each_peer(|_, peer_state| {
            peer_state.stop_timers();
            peer_state.get_peer_handle().down();
        });

        *enabled = false;
    }

    /// Brings the WireGuard device up.
    /// Usually called when the associated interface is brought up.
    pub fn up(&self, mtu: usize) {
        // ensure exclusive access (to avoid race with "up" call)
        let mut enabled = self.enabled.write();

        // set mtu
        self.mtu.store(mtu, Ordering::Relaxed);

        // check if already up
        if *enabled {
            return;
        }

        // enable transmission
        self.udp_writer.write().set_enabled(true);

        // set all peers up (restarts timers)
        self.for_each_peer(|_, peer_state| {
            peer_state.get_peer_handle().up();
            peer_state.start_timers();
        });

        *enabled = true;
    }

    pub fn set_key(&self, sk: Option<StaticSecret>) {
        let mut peers = self.crypto_device.write();
        peers.set_sk(sk);
        self.router.clear_sending_keys();
    }

    pub fn get_sk(&self) -> Option<StaticSecret> {
        self.crypto_device
            .read()
            .get_sk()
            .map(|sk| StaticSecret::from(sk.to_bytes()))
    }

    pub fn set_psk(&self, pk: PublicKey, psk: PSK) -> bool {
        self.crypto_device.write().set_psk(pk, psk).is_ok()
    }
    pub fn get_psk(&self, pk: &PublicKey) -> Option<PSK> {
        self.crypto_device.read().get_psk(pk).ok().cloned()
    }

    pub fn add_peer(&self, pk: PublicKey) -> Option<Arc<PeerState<T, B>>> {
        let mut peers = self.crypto_device.write();
        if peers.contains_key(&pk) {
            return None;
        }

        // prevent up/down while inserting
        let enabled = self.enabled.read();

        // create new router peer
        let peer_timers = Box::new(self.timers.create_peer_timers());

        let peer_state = PeerState::new_as_arc(
            OsRng.r#gen(),
            self.clone(),
            pk,
            peer_timers,
            *enabled,
            self.inner.clone(),
        );

        self.peers.insert(pk, peer_state.clone());

        // finally, add the peer to the handshake device
        peers.add(pk, pk).ok().map(|_| peer_state)
    }

    pub fn remove_peer(&self, pk: &PublicKey) {
        let _ = self.crypto_device.write().remove(pk);

        self.peers.remove(pk);
    }

    pub fn add_handshake_reader<'scope, 'wireguard>(
        &'wireguard self,
        thread_scope: &'scope thread::Scope<'scope, 'wireguard>,
        handshake_receiver: crossbeam_channel::Receiver<HandshakeJob<B::Endpoint>>,
        n_handshake_workers: NonZeroUsize,
    ) -> Vec<thread::ScopedJoinHandle<'scope, ()>> {
        spawn_handshake_workers(thread_scope, self, handshake_receiver, n_handshake_workers)
    }

    pub fn add_tun_readers<'scope, 'wireguard>(
        &'wireguard self,
        thread_scope: &'scope thread::Scope<'scope, 'wireguard>,
        tun_readers: Vec<T::Reader>,
    ) -> Vec<thread::ScopedJoinHandle<'scope, ()>> {
        spawn_tun_workers(thread_scope, self, tun_readers)
    }

    /// Begin consuming messages from the reader.
    /// Multiple readers can be added to support multi-queue and individual Ipv6/Ipv4 sockets interfaces
    ///
    /// Any previous reader thread is stopped by closing the previous reader,
    /// which unblocks the thread and causes an error on reader.read
    pub fn add_udp_reader<'scope, 'wireguard>(
        &'wireguard self,
        thread_scope: &'scope thread::Scope<'scope, 'wireguard>,
        reader: B::Reader,
    ) -> thread::ScopedJoinHandle<'scope, ()> {
        const MAX_UDP_PACKET_SIZE: usize = 4096; // TODO take this from mtu

        let (sender, receiver) = crossbeam_channel::unbounded();

        // TODO remove this and make UDP reader "cancelable": either by recv_timeout, or explicit close
        thread::spawn(move || {
            loop {
                let mut msg = vec![0; MAX_UDP_PACKET_SIZE];

                let (size, src) = match reader.read(&mut msg) {
                    Err(e) => {
                        debug!("Bind reader closed with {}", e);
                        return;
                    }
                    Ok(v) => v,
                };

                if sender.send((msg, size, src)).is_err() {
                    return;
                }
            }
        });

        let wireguard_device = self.clone();
        thread_scope.spawn(move || udp_worker(&wireguard_device, receiver))
    }

    pub fn set_writer(&self, writer: B::Writer) {
        self.udp_writer.write().set_writer(writer);
    }

    pub fn new(tun_writer: T::Writer, handshake_sender: Sender<HandshakeJob<B::Endpoint>>) -> Self {
        Self {
            inner: Arc::new(WireguardInner::new(tun_writer, handshake_sender)),
        }
    }

    pub fn close_handshake_queue(&self) {
        *self.handshake_sender.lock() = None;
    }

    pub fn send_to_handshake_queue(&self, handshake_job: HandshakeJob<B::Endpoint>) -> bool {
        if let Some(handshake_sender) = self.handshake_sender.lock().as_ref() {
            handshake_sender
                .send(handshake_job)
                .expect("channel is kept open until sender exists");

            return true;
        }

        false
    }

    pub fn get_peer(&self, public_key: &PublicKey) -> Option<Arc<PeerState<T, B>>> {
        self.peers.get(public_key).map(|e| e.clone())
    }

    pub fn for_each_peer<F>(&self, mut f: F)
    where
        F: FnMut(&PublicKey, &PeerState<T, B>),
    {
        for entry in &self.peers {
            let public_key = entry.key();
            let peer_state = entry.value();

            f(public_key, peer_state);
        }
    }

    pub fn get_crypto_device(&self) -> RwLockReadGuard<'_, CryptoDevice> {
        self.crypto_device.read()
    }

    pub fn get_mtu(&self) -> usize {
        self.mtu.load(Ordering::SeqCst)
    }

    pub fn increment_pending(&self) -> usize {
        self.pending.fetch_add(1, Ordering::SeqCst)
    }

    pub fn decrement_pending(&self) -> usize {
        self.pending.fetch_sub(1, Ordering::SeqCst)
    }

    pub fn get_elapsed_since_last_under_load(&self) -> Duration {
        self.last_under_load.lock().elapsed()
    }

    pub fn set_last_under_load(&self, value: Instant) {
        *self.last_under_load.lock() = value;
    }

    pub fn send_raw(
        &self,
        msg: &[u8],
        dst: &mut B::Endpoint,
    ) -> Result<(), <B::Writer as udp::Writer<B::Endpoint>>::Error> {
        self.udp_writer.read().send_unchecked(msg, dst)
    }

    pub fn send(&self, msg: Vec<u8>) -> Result<(), RouterError> {
        self.router.send(msg)
    }

    pub fn recv(&self, src: B::Endpoint, msg: Vec<u8>) -> Result<(), RouterError> {
        self.router.recv(src, msg)
    }

    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }
}
