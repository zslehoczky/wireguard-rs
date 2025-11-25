use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::Instant;

use crossbeam_channel::Sender;
use dashmap::DashMap;
use hjul::Runner;
use rand::Rng;
use rand::rngs::OsRng;
use spin::{Mutex, RwLock, RwLockReadGuard};
use x25519_dalek::{PublicKey, StaticSecret};

use wg_crypto::{self as crypto, PSK, StdTimestamp};
use wg_traits::{tun::Tun, udp::UDP};

use crate::router::{Device as RouterDevice, PeerHandle};
use crate::timers::{
    PeerState,
    constants::{TIME_HORIZON, TIMERS_CAPACITY, TIMERS_SLOTS, TIMERS_TICK},
};
use crate::workers::{HandshakeJob, udp_worker};

pub struct WireguardInner<T: Tun, B: UDP> {
    // identifier (for logging)
    pub id: u32,

    // timer wheel
    pub runner: Mutex<Runner>,

    // device enabled
    pub enabled: RwLock<bool>,

    // current MTU
    pub mtu: AtomicUsize,

    crypto_device: RwLock<
        crypto::Device<PeerHandle<B::Endpoint, T::Writer, B::Writer>, Instant, StdTimestamp>,
    >,

    peer_state_lookup: DashMap<PublicKey, Weak<PeerState<T, B>>>,

    // cryptokey router
    pub router: RouterDevice<B::Endpoint, T::Writer, B::Writer>,

    // handshake related state
    pub last_under_load: Mutex<Instant>,
    pub pending: AtomicUsize, // number of pending handshake packets in queue
    handshake_sender: Mutex<Option<Sender<HandshakeJob<B::Endpoint>>>>,
}

impl<T: Tun, B: UDP> WireguardInner<T, B> {
    fn new(
        router: RouterDevice<B::Endpoint, T::Writer, B::Writer>,
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
            runner: Mutex::new(Runner::new(TIMERS_TICK, TIMERS_SLOTS, TIMERS_CAPACITY)),
            handshake_sender: Mutex::new(Some(sender)),
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

        let peer_state = Arc::new(PeerState::new(OsRng.r#gen(), self.clone(), pk, *enabled));

        self.peer_state_lookup
            .insert(pk, Arc::downgrade(&peer_state));

        // create new router peer
        let peer = self.router.new_peer(peer_state);

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
        F: FnMut(&PeerHandle<B::Endpoint, T::Writer, B::Writer>, &PeerState<T, B>),
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
        F: FnMut(&PublicKey, &PeerHandle<B::Endpoint, T::Writer, B::Writer>, &PeerState<T, B>),
    {
        for (public_key, peer_handle) in self.crypto_device.read().iter() {
            let peer_state = self
                .find_peer_state(&public_key)
                .expect("peer state should exist");

            f(&public_key, peer_handle, &peer_state);
        }
    }

    pub fn get_crypto_device(
        &self,
    ) -> RwLockReadGuard<
        '_,
        crypto::Device<PeerHandle<B::Endpoint, T::Writer, B::Writer>, Instant, StdTimestamp>,
    > {
        self.crypto_device.read()
    }
}
