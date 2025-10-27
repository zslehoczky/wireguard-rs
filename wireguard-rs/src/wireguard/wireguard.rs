use super::constants::*;
use super::peer::PeerInner;
use super::router;
use super::timers::Timers;
use super::{HandshakeJob, udp_worker};

use std::fmt;
use std::thread;

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use crossbeam_channel::Sender;
use rand::Rng;
use rand::rngs::OsRng;

use hjul::Runner;
use spin::{Mutex, RwLock};
use wg_crypto::{self as crypto, PSK, StdTimestamp};
use wg_traits::{tun::Tun, udp::UDP};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct WireguardInner<T: Tun, B: UDP> {
    // identifier (for logging)
    pub id: u32,

    // timer wheel
    pub runner: Mutex<Runner>,

    // device enabled
    pub enabled: RwLock<bool>,

    // current MTU
    pub mtu: AtomicUsize,

    // peer map
    #[allow(clippy::type_complexity)]
    pub peers: RwLock<
        crypto::Device<
            router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>,
            std::time::Instant,
            StdTimestamp,
        >,
    >,

    // cryptokey router
    pub router: router::Device<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>,

    // handshake related state
    pub last_under_load: Mutex<Instant>,
    pub pending: AtomicUsize, // number of pending handshake packets in queue
    handshake_sender: Mutex<Option<Sender<HandshakeJob<B::Endpoint>>>>,
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
        for (_pk, peer) in self.peers.write().iter() {
            peer.stop_timers();
            peer.down();
        }

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
        for (_pk, peer) in self.peers.write().iter() {
            peer.up();
            peer.start_timers();
        }

        *enabled = true;
    }

    pub fn _clear_peers(&self) {
        self.peers.write()._clear();
    }

    pub fn remove_peer(&self, pk: &PublicKey) {
        let _ = self.peers.write().remove(pk);
    }

    pub fn set_key(&self, sk: Option<StaticSecret>) {
        let mut peers = self.peers.write();
        peers.set_sk(sk);
        self.router.clear_sending_keys();
    }

    pub fn get_sk(&self) -> Option<StaticSecret> {
        self.peers
            .read()
            .get_sk()
            .map(|sk| StaticSecret::from(sk.to_bytes()))
    }

    pub fn set_psk(&self, pk: PublicKey, psk: PSK) -> bool {
        self.peers.write().set_psk(pk, psk).is_ok()
    }
    pub fn get_psk(&self, pk: &PublicKey) -> Option<PSK> {
        self.peers.read().get_psk(pk).ok().cloned()
    }

    pub fn add_peer(&self, pk: PublicKey) -> bool {
        let mut peers = self.peers.write();
        if peers.contains_key(&pk) {
            return false;
        }

        // prevent up/down while inserting
        let enabled = self.enabled.read();

        // create timers (lookup by public key)
        let timers = Timers::new::<T, B>(self.clone(), pk, *enabled);

        // create new router peer
        let peer: router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer> =
            self.router.new_peer(PeerInner {
                id: OsRng.r#gen(),
                pk,
                wg: self.clone(),
                walltime_last_handshake: Mutex::new(None),
                last_handshake_sent: Mutex::new(Instant::now() - TIME_HORIZON),
                handshake_queued: AtomicBool::new(false),
                rx_bytes: AtomicU64::new(0),
                tx_bytes: AtomicU64::new(0),
                timers: RwLock::new(timers),
            });

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
    ) -> WireGuard<T, B> {
        // create router
        let router: router::Device<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer> =
            router::Device::new(n_cpus, writer);

        // create arc to state

        WireGuard {
            inner: Arc::new(WireguardInner {
                enabled: RwLock::new(false),
                id: OsRng.r#gen(),
                mtu: AtomicUsize::new(0),
                last_under_load: Mutex::new(Instant::now() - TIME_HORIZON),
                router,
                pending: AtomicUsize::new(0),
                peers: RwLock::new(crypto::Device::new()),
                runner: Mutex::new(Runner::new(TIMERS_TICK, TIMERS_SLOTS, TIMERS_CAPACITY)),
                handshake_sender: Mutex::new(Some(sender)),
            }),
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
}
