use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Weak};

use arraydeque::{ArrayDeque, Wrapping};
use spin::{Mutex, RwLock};

use wg_traits::Endpoint as _;

use crate::router::{
    KeyPair, MAX_QUEUED_PACKETS, REJECT_AFTER_MESSAGES, RouterError, SIZE_MESSAGE_PREFIX,
};

use super::decryption_state::DecryptionState;
use super::device_interface::DeviceInterface;
use super::encryption_state::EncryptionState;
use super::inbound_job::{DecryptionJob, InboundJob};
use super::key_wheel::KeyWheel;
use super::outbound_job::{EncryptionJob, OutboundJob};
use super::peer_handle_interface::PeerHandleInterface;
use super::send_queue::SendQueue;
use super::{PeerDependencies, PeerStateInterface};

type InboundQueue<P> = SendQueue<P, InboundJob<P>>;
type OutboundQueue<P> = SendQueue<P, OutboundJob<P>>;

pub struct PeerInner<P: PeerDependencies> {
    device: Arc<dyn DeviceInterface<P>>,
    peer_state: RwLock<Option<Weak<dyn PeerStateInterface>>>,
    staged_packets: Mutex<ArrayDeque<[Vec<u8>; MAX_QUEUED_PACKETS], Wrapping>>,
    keys: Mutex<KeyWheel>,
    enc_key: Mutex<Option<EncryptionState>>,
    dec_key: Mutex<Option<Arc<DecryptionState>>>,
    endpoint: Mutex<Option<P::UdpEndpoint>>,
    inbound_queue: RwLock<Option<Arc<InboundQueue<P>>>>,
    outbound_queue: RwLock<Option<Arc<OutboundQueue<P>>>>,
}

impl<P: PeerDependencies> PeerInner<P> {
    fn new(device: Arc<dyn DeviceInterface<P>>) -> Self {
        Self {
            device,
            peer_state: RwLock::new(None),
            enc_key: spin::Mutex::new(None),
            dec_key: spin::Mutex::new(None),
            endpoint: spin::Mutex::new(None),
            keys: spin::Mutex::new(KeyWheel::new()),
            staged_packets: spin::Mutex::new(ArrayDeque::new()),
            inbound_queue: RwLock::new(None),
            outbound_queue: RwLock::new(None),
        }
    }
}

/// A Peer represents a reference to the router state associated with a peer
pub struct Peer<P: PeerDependencies> {
    inner: Arc<PeerInner<P>>,
}

impl<P: PeerDependencies> Clone for Peer<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// Equality of peers is defined as pointer equality of
// the atomic reference counted pointer.
impl<P: PeerDependencies> PartialEq for Peer<P> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<P: PeerDependencies> Eq for Peer<P> {}

// A peer is transparently dereferenced to the inner type
impl<P: PeerDependencies> Deref for Peer<P> {
    type Target = PeerInner<P>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<P: PeerDependencies> PeerInner<P> {
    pub fn send_raw(&self, msg: &[u8]) -> Result<(), RouterError> {
        // send to endpoint (if known)
        match self.endpoint.lock().as_mut() {
            Some(endpoint) => self.device.write_outbound(msg, endpoint),
            None => Err(RouterError::NoEndpoint),
        }
    }

    pub fn get_peer_state(&self) -> Arc<dyn PeerStateInterface> {
        self.peer_state
            .read()
            .as_ref()
            .and_then(Weak::upgrade)
            .expect("peer state should always exist")
    }
}

impl<P: PeerDependencies> Peer<P> {
    fn new(device: Arc<dyn DeviceInterface<P>>) -> Self {
        let result = Self {
            inner: Arc::new(PeerInner::new(device)),
        };

        let inbound_queue = SendQueue::new(result.clone());
        *result.inner.inbound_queue.write() = Some(Arc::new(inbound_queue));

        let outbound_queue = SendQueue::new(result.clone());
        *result.inner.outbound_queue.write() = Some(Arc::new(outbound_queue));

        result
    }

    pub fn get_decryption_key(&self) -> Arc<DecryptionState> {
        self.dec_key
            .lock()
            .as_ref()
            .expect("decryption key should exist")
            .clone()
    }

    pub fn recv(&self, endpoint: P::UdpEndpoint, buffer: Vec<u8>) {
        self.enqueue_decryption_job(DecryptionJob::new(
            buffer,
            endpoint,
            self.get_decryption_key().get_keypair(),
        ));
    }

    /// Encrypt and send a message to the peer
    ///
    /// Arguments:
    ///
    /// - `msg` : A padded vector holding the message (allows in-place construction of the transport header)
    /// - `stage`: Should the message be staged if no key is available
    pub fn send(&self, msg: Vec<u8>, stage: bool) {
        // check if key available
        let (job, need_key) = {
            let mut enc_key = self.enc_key.lock();
            match enc_key.as_mut() {
                None => {
                    log::debug!("no key encryption key available");
                    if stage {
                        self.staged_packets.lock().push_back(msg);
                    };
                    (None, true)
                }
                Some(state) => {
                    // avoid integer overflow in nonce
                    if state.get_nonce() >= REJECT_AFTER_MESSAGES - 1 {
                        log::debug!("encryption key expired");
                        *enc_key = None;
                        if stage {
                            self.staged_packets.lock().push_back(msg);
                        }
                        (None, true)
                    } else {
                        log::debug!("encryption state available, nonce = {}", state.get_nonce());
                        let job = EncryptionJob::new(msg, state.get_nonce(), state.get_keypair());
                        state.increment_nonce();
                        (Some(job), false)
                    }
                }
            }
        };

        if need_key {
            log::debug!("request new key");
            debug_assert!(job.is_none());
            self.get_peer_state().need_key();
        };

        if let Some(job) = job {
            log::debug!("schedule encryption job");
            self.enqueue_encryption_job(job);
        }
    }

    // Transmit all staged packets
    fn send_staged(&self) -> bool {
        log::trace!("peer.send_staged");
        let mut sent = false;
        let mut staged = self.staged_packets.lock();
        loop {
            match staged.pop_front() {
                Some(msg) => {
                    sent = true;
                    self.send(msg, false);
                }
                None => break sent,
            }
        }
    }

    pub fn confirm_key(&self, keypair: &Arc<KeyPair>) {
        log::trace!("peer.confirm_key");
        {
            // take lock and check keypair = keys.next
            let mut keys = self.keys.lock();

            let next = match keys.get_next() {
                Some(next) => next,
                None => {
                    return;
                }
            };

            if !Arc::ptr_eq(next, keypair) {
                return;
            }

            // allocate new encryption state
            let ekey = Some(EncryptionState::new(next.clone()));

            keys.rotate();

            // tell the world outside the router that a key was confirmed
            self.get_peer_state().key_confirmed();

            // set new key for encryption
            *self.enc_key.lock() = ekey;
        }

        // start transmission of staged packets
        self.send_staged();
    }

    pub fn check_route(&self, packet: &mut [u8]) -> bool {
        self.device.check_route(self, packet)
    }

    pub fn write_inbound(&self, data: &[u8]) {
        self.device.write_inbound(data)
    }

    pub fn update_endpoint(&self, new_endpoint: Option<P::UdpEndpoint>) {
        *self.endpoint.lock() = new_endpoint;
    }

    pub fn enqueue_decryption_job(&self, job: DecryptionJob<P>) {
        self.get_inbound_queue()
            .enqueue_job(InboundJob::Decryption { job });
    }

    pub fn enqueue_encryption_job(&self, job: EncryptionJob<P>) {
        self.get_outbound_queue()
            .enqueue_job(OutboundJob::Encryption { job });
    }

    fn get_inbound_queue(&self) -> Arc<SendQueue<P, InboundJob<P>>> {
        self.inbound_queue
            .read()
            .as_ref()
            .expect("inbound queue should always exist")
            .clone()
    }

    fn get_outbound_queue(&self) -> Arc<SendQueue<P, OutboundJob<P>>> {
        self.outbound_queue
            .read()
            .as_ref()
            .expect("outbound queue should always exist")
            .clone()
    }
}

/// A PeerHandle is a specially designated reference to the peer
/// which removes the peer from the device when dropped.
///
/// A PeerHandle cannot be cloned (unlike the wrapped type).
/// A PeerHandle dereferences to a Peer (meaning you can use it like a Peer struct)
pub struct PeerHandle<P: PeerDependencies> {
    peer: Peer<P>,
}

impl<P: PeerDependencies> PeerHandle<P> {
    pub fn new(device: Arc<dyn DeviceInterface<P>>) -> Self {
        Self {
            peer: Peer::new(device),
        }
    }
}

impl<P: PeerDependencies> Deref for PeerHandle<P> {
    type Target = PeerInner<P>;
    fn deref(&self) -> &Self::Target {
        &self.peer
    }
}

impl<P: PeerDependencies> Drop for PeerHandle<P> {
    fn drop(&mut self) {
        let peer = &self.peer;

        // remove from cryptkey router
        self.peer.device.remove_route(peer);

        // release ids from the receiver map
        let released_ids = peer.keys.lock().reset();
        if !released_ids.is_empty() {
            peer.device.remove_receivers(&released_ids[..]);
        }

        *peer.enc_key.lock() = None;
        *peer.dec_key.lock() = None;
        *peer.endpoint.lock() = None;

        log::debug!("peer dropped & removed from device");
    }
}

impl<P: PeerDependencies> fmt::Display for PeerHandle<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerHandle").finish()
    }
}

impl<P: PeerDependencies> PeerHandleInterface<P> for PeerHandle<P> {
    fn set_endpoint(&self, endpoint: P::UdpEndpoint) {
        log::trace!("peer.set_endpoint");
        *self.peer.endpoint.lock() = Some(endpoint);
    }

    fn get_endpoint(&self) -> Option<SocketAddr> {
        log::trace!("peer.get_endpoint");
        self.peer.endpoint.lock().as_ref().map(|e| e.to_address())
    }

    fn zero_keys(&self) {
        log::trace!("peer.zero_keys");

        // reset key-wheel and release keys
        let released_ids = self.keys.lock().reset();
        if !released_ids.is_empty() {
            self.device.remove_receivers(&released_ids[..]);
        }

        // clear encryption state
        *self.peer.enc_key.lock() = None;
        *self.peer.dec_key.lock() = None;
    }

    fn down(&self) {
        self.zero_keys();
    }

    fn up(&self) {}

    fn add_keypair(&self, new: KeyPair) -> Vec<u32> {
        log::trace!("Router, add_keypair: {:?}", new);

        let initiator = new.initiator;
        let released_id = {
            let mut keys = self.peer.keys.lock();

            let prev_id = keys.get_prev().map(|k| k.local_id());
            let new_id = new.recv.id;

            let new = Arc::new(new);

            let encryption_state = EncryptionState::new(new.clone());
            let decryption_state = DecryptionState::new(new.clone());

            // update key-wheel
            keys.update(new);

            if initiator {
                // start using key for encryption
                *self.peer.enc_key.lock() = Some(encryption_state);
            }

            log::trace!("peer.add_keypair: updating inbound id map");

            *self.peer.dec_key.lock() = Some(Arc::new(decryption_state));

            // update incoming packet id map
            self.peer
                .device
                .add_receiver(prev_id, new_id, self.peer.clone())
        };

        // schedule confirmation
        if initiator {
            debug_assert!(self.peer.enc_key.lock().is_some());
            log::trace!("peer.add_keypair: is initiator, must confirm the key");
            // attempt to confirm using staged packets
            if !self.peer.send_staged() {
                // fall back to keepalive packet
                self.send_keepalive();
                log::debug!("peer.add_keypair: keepalive for confirmation",);
            }
            log::trace!("peer.add_keypair: key attempted confirmed");
        }

        match released_id {
            Some(id) => vec![id],
            None => vec![],
        }
    }

    fn send_keepalive(&self) {
        log::trace!("peer.send_keepalive");
        self.peer.send(vec![0u8; SIZE_MESSAGE_PREFIX], false)
    }

    fn add_allowed_ip(&self, ip: IpAddr, masklen: u32) {
        self.peer
            .device
            .insert_route(ip, masklen, self.peer.clone())
    }

    fn list_allowed_ips(&self) -> Vec<(IpAddr, u32)> {
        self.peer.device.list_routes(&self.peer)
    }

    fn clear_src(&self) {
        if let Some(e) = (*self.peer.endpoint.lock()).as_mut() {
            e.clear_src()
        }
    }

    fn purge_staged_packets(&self) {
        self.peer.staged_packets.lock().clear();
    }

    fn send_raw(&self, msg: &[u8]) -> Result<(), RouterError> {
        self.peer.send_raw(msg)
    }

    fn set_peer_state(&self, peer_state: Arc<dyn PeerStateInterface>) {
        *self.peer_state.write() = Some(Arc::downgrade(&peer_state));
    }
}
