use std::fmt;
use std::ops::Deref;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use dashmap::DashMap;
use rand::Rng;
use rand::rngs::OsRng;
use spin::{Mutex, RwLock, RwLockReadGuard};
use x25519_dalek::{PublicKey, StaticSecret};

use wg_crypto::{self as crypto, PSK, StdTimestamp};
use wg_traits::{
    tun::Tun,
    udp::{self, UDP},
};

use crate::peer::PeerState;
use crate::router::{Device as RouterDevice, PeerHandle, RouterError};
use crate::workers::{HandshakeJob, udp_worker};

use super::PeerDeps;
use super::constants::TIME_HORIZON;
use super::timers::Timers;

type CryptoDevice<T, B> = crypto::Device<PeerHandle<PeerDeps<T, B>>, Instant, StdTimestamp>;

pub struct WireguardInner<T: Tun, B: UDP> {
    id: u32, // internal id (for logging)
    enabled: RwLock<bool>,
    mtu: AtomicUsize,
    crypto_device: RwLock<CryptoDevice<T, B>>,
    peer_state_lookup: DashMap<PublicKey, Weak<PeerState<T, B>>>,
    router: RouterDevice<PeerDeps<T, B>>,
    last_under_load: Mutex<Instant>,
    pending: AtomicUsize, // number of pending handshake packets in queue
    handshake_sender: Mutex<Option<Sender<HandshakeJob<B::Endpoint>>>>,
    timers: Timers,
}

impl<T: Tun, B: UDP> WireguardInner<T, B> {
    fn new(
        router: RouterDevice<PeerDeps<T, B>>,
        sender: Sender<HandshakeJob<B::Endpoint>>,
    ) -> Self {
        Self {
            enabled: RwLock::new(false),
            id: OsRng.r#gen(),
            mtu: AtomicUsize::new(0),
            last_under_load: Mutex::new(Instant::now() - TIME_HORIZON),
            router,
            pending: AtomicUsize::new(0),
            crypto_device: RwLock::new(crypto::Device::new()),
            peer_state_lookup: DashMap::default(),
            handshake_sender: Mutex::new(Some(sender)),
            timers: Timers::new(),
        }
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

        // avoid transmission from router
        self.router.down();

        // set all peers down (stops timers)
        self.visit_peers(|_, peer_handle, peer_state| {
            peer_state.stop_timers();
            peer_handle.down();
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

        // enable transmission from router
        self.router.up();

        // set all peers up (restarts timers)
        self.visit_peers(|_, peer_handle, peer_state| {
            peer_handle.up();
            peer_state.start_timers();
        });

        *enabled = true;
    }

    pub fn remove_peer(&self, pk: &PublicKey) {
        let _ = self.crypto_device.write().remove(pk);
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

    pub fn add_peer(&self, pk: PublicKey) -> bool {
        let mut peers = self.crypto_device.write();
        if peers.contains_key(&pk) {
            return false;
        }

        // prevent up/down while inserting
        let enabled = self.enabled.read();

        let peer_timers = Box::new(self.timers.create_peer_timers());

        let peer_state =
            PeerState::new_as_arc(OsRng.r#gen(), self.clone(), pk, peer_timers, *enabled);

        self.peer_state_lookup
            .insert(pk, Arc::downgrade(&peer_state));

        // create new router peer
        let peer = self.router.new_peer(peer_state.clone());

        // finally, add the peer to the handshake device
        peers.add(pk, peer).is_ok()
    }

    /// Begin consuming messages from the reader.
    /// Multiple readers can be added to support multi-queue and individual Ipv6/Ipv4 sockets interfaces
    ///
    /// Any previous reader thread is stopped by closing the previous reader,
    /// which unblocks the thread and causes an error on reader.read
    pub fn add_udp_reader(&self, reader: B::Reader) {
        let wg = self.clone();
        thread::spawn(move || {
            udp_worker(&wg, reader);
        });
    }

    pub fn set_writer(&self, writer: B::Writer) {
        self.router.set_outbound_writer(writer);
    }

    pub fn new(
        writer: T::Writer,
        sender: Sender<HandshakeJob<B::Endpoint>>,
        n_cpus: usize,
    ) -> Self {
        let router = RouterDevice::new(n_cpus, writer);

        Self {
            inner: Arc::new(WireguardInner::new(router, sender)),
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

    fn find_peer_state(&self, public_key: &PublicKey) -> Option<Arc<PeerState<T, B>>> {
        if let Some(entry) = self.peer_state_lookup.get(public_key) {
            if let Some(peer_state) = entry.upgrade() {
                return Some(peer_state);
            }
        } else {
            return None;
        }

        // cleanup if weak has expired
        self.peer_state_lookup.remove(public_key);

        None
    }

    pub fn visit_peer<F>(&self, public_key: &PublicKey, mut f: F)
    where
        F: FnMut(&PeerHandle<PeerDeps<T, B>>, &PeerState<T, B>),
    {
        let peers = self.crypto_device.read();

        if let Some(peer_handle) = peers.get(public_key) {
            let peer_state = self
                .find_peer_state(public_key)
                .expect("peer state should exist");

            f(peer_handle, &peer_state);
        }
    }

    pub fn visit_peers<F>(&self, mut f: F)
    where
        F: FnMut(&PublicKey, &PeerHandle<PeerDeps<T, B>>, &PeerState<T, B>),
    {
        for (public_key, peer_handle) in self.crypto_device.read().iter() {
            let peer_state = self
                .find_peer_state(&public_key)
                .expect("peer state should exist");

            f(&public_key, peer_handle, &peer_state);
        }
    }

    pub fn get_crypto_device(&self) -> RwLockReadGuard<'_, CryptoDevice<T, B>> {
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
        self.router.send_raw(msg, dst)
    }

    pub fn send(&self, msg: Vec<u8>) -> Result<(), RouterError> {
        self.router.send(msg)
    }

    pub fn recv(&self, src: B::Endpoint, msg: Vec<u8>) -> Result<(), RouterError> {
        self.router.recv(src, msg)
    }
}
