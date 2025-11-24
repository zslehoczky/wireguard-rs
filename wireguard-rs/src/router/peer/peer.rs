use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;

use arraydeque::{ArrayDeque, Wrapping};
use spin::Mutex;

use wg_traits::{Endpoint, tun, udp};

use crate::router::{
    KeyPair, MAX_QUEUED_PACKETS, REJECT_AFTER_MESSAGES, SIZE_MESSAGE_PREFIX, device::Device,
    parallel_queue::ParallelJobUnion, receive::ReceiveJob, router_error::RouterError,
    send::SendJob, sequential_queue::SequentialQueue,
};

use super::TimerState;
use super::crypto_state;
use super::encryption_state::EncryptionState;
use super::key_wheel::KeyWheel;

pub struct PeerInner<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> {
    device: Device<E, C, T, B>,
    timer_state: C,
    outbound: SequentialQueue<SendJob<E, C, T, B>>,
    inbound: SequentialQueue<ReceiveJob<E, C, T, B>>,
    staged_packets: Mutex<ArrayDeque<[Vec<u8>; MAX_QUEUED_PACKETS], Wrapping>>,
    keys: Mutex<KeyWheel>,
    enc_key: Mutex<Option<EncryptionState>>,
    endpoint: Mutex<Option<E>>,
}

impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> PeerInner<E, C, T, B> {
    fn new(device: Device<E, C, T, B>, timer_state: C) -> Self {
        Self {
            timer_state,
            device,
            inbound: SequentialQueue::new(),
            outbound: SequentialQueue::new(),
            enc_key: spin::Mutex::new(None),
            endpoint: spin::Mutex::new(None),
            keys: spin::Mutex::new(KeyWheel::new()),
            staged_packets: spin::Mutex::new(ArrayDeque::new()),
        }
    }
}

/// A Peer dereferences to its opaque type:
/// This allows the router code to take ownership of the opaque type
/// used for callback events, while still enabling the rest of the code to access the opaque type
/// (which might expose other functionality in their scope) from a Peer pointer.
///
/// e.g. it can take ownership of the timer state of a peer.
impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> Deref
    for PeerInner<E, C, T, B>
{
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.timer_state
    }
}

/// A Peer represents a reference to the router state associated with a peer
pub struct Peer<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> {
    inner: Arc<PeerInner<E, C, T, B>>,
}

/// A PeerHandle is a specially designated reference to the peer
/// which removes the peer from the device when dropped.
///
/// A PeerHandle cannot be cloned (unlike the wrapped type).
/// A PeerHandle dereferences to a Peer (meaning you can use it like a Peer struct)
pub struct PeerHandle<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> {
    peer: Peer<E, C, T, B>,
}

impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> Clone for Peer<E, C, T, B> {
    fn clone(&self) -> Self {
        Peer {
            inner: self.inner.clone(),
        }
    }
}

/* Equality of peers is defined as pointer equality of
 * the atomic reference counted pointer.
 */
impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> PartialEq for Peer<E, C, T, B> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> Eq for Peer<E, C, T, B> {}

/* A peer is transparently dereferenced to the inner type
 *
 */

impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> Deref for Peer<E, C, T, B> {
    type Target = PeerInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> Deref
    for PeerHandle<E, C, T, B>
{
    type Target = PeerInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.peer
    }
}

impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> fmt::Display
    for PeerHandle<E, C, T, B>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerHandle(format: TODO)")
    }
}

impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> Drop
    for PeerHandle<E, C, T, B>
{
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
        *peer.endpoint.lock() = None;

        log::debug!("peer dropped & removed from device");
    }
}

impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> PeerInner<E, C, T, B> {
    /// Send a raw message to the peer (used for handshake messages)
    ///
    /// # Arguments
    ///
    /// - `msg`, message body to send to peer
    ///
    /// # Returns
    ///
    /// Unit if packet was sent, or an error indicating why sending failed
    pub fn send_raw(&self, msg: &[u8]) -> Result<(), RouterError> {
        // send to endpoint (if known)
        match self.endpoint.lock().as_mut() {
            Some(endpoint) => self.device.read_outbound(msg, endpoint),
            None => Err(RouterError::NoEndpoint),
        }
    }
}

impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> Peer<E, C, T, B> {
    fn new(device: Device<E, C, T, B>, timer_state: C) -> Self {
        Self {
            inner: Arc::new(PeerInner::new(device, timer_state)),
        }
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
                        let job =
                            SendJob::new(msg, state.get_nonce(), state.get_keypair(), self.clone());
                        if self.outbound.push(job.clone()) {
                            state.increment_nonce();
                            (Some(job), false)
                        } else {
                            (None, false)
                        }
                    }
                }
            }
        };

        if need_key {
            log::debug!("request new key");
            debug_assert!(job.is_none());
            self.timer_state.need_key();
        };

        if let Some(job) = job {
            log::debug!("schedule outbound job");
            self.device.queue_job(ParallelJobUnion::Outbound(job))
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
            self.timer_state.key_confirmed();

            // set new key for encryption
            *self.enc_key.lock() = ekey;
        }

        // start transmission of staged packets
        self.send_staged();
    }

    pub fn check_route(&self, peer: &Self, packet: &mut [u8]) -> bool {
        self.device.check_route(peer, packet)
    }

    pub fn write_inbound(&self, data: &[u8]) {
        self.device.write_inbound(data)
    }

    pub fn get_timer_state(&self) -> &C {
        &self.timer_state
    }

    pub fn get_outbound(&self) -> &SequentialQueue<SendJob<E, C, T, B>> {
        &self.outbound
    }

    pub fn get_inbound(&self) -> &SequentialQueue<ReceiveJob<E, C, T, B>> {
        &self.inbound
    }

    pub fn update_endpoint(&self, new_endpoint: Option<E>) {
        *self.endpoint.lock() = new_endpoint;
    }
}

impl<E: Endpoint, C: TimerState, T: tun::Writer, B: udp::Writer<E>> PeerHandle<E, C, T, B> {
    pub fn new(device: Device<E, C, T, B>, timer_state: C) -> Self {
        Self {
            peer: Peer::new(device, timer_state),
        }
    }

    /// Set the endpoint of the peer
    ///
    /// # Arguments
    ///
    /// - `endpoint`, socket address converted to bind endpoint
    ///
    /// # Note
    ///
    /// This API still permits support for the "sticky socket" behavior,
    /// as sockets should be "unsticked" when manually updating the endpoint
    pub fn set_endpoint(&self, endpoint: E) {
        log::trace!("peer.set_endpoint");
        *self.peer.endpoint.lock() = Some(endpoint);
    }

    pub fn get_timer_state(&self) -> &C {
        self.peer.get_timer_state()
    }

    /// Returns the current endpoint of the peer (for configuration)
    ///
    /// # Note
    ///
    /// Does not convey potential "sticky socket" information
    pub fn get_endpoint(&self) -> Option<SocketAddr> {
        log::trace!("peer.get_endpoint");
        self.peer.endpoint.lock().as_ref().map(|e| e.to_address())
    }

    /// Zero all key-material related to the peer
    pub fn zero_keys(&self) {
        log::trace!("peer.zero_keys");

        // reset key-wheel and release keys
        let released_ids = self.keys.lock().reset();
        if !released_ids.is_empty() {
            self.device.remove_receivers(&released_ids[..]);
        }

        // clear encryption state
        *self.peer.enc_key.lock() = None;
    }

    pub fn down(&self) {
        self.zero_keys();
    }

    pub fn up(&self) {}

    /// Add a new keypair
    ///
    /// # Arguments
    ///
    /// - new: The new confirmed/unconfirmed key pair
    ///
    /// # Returns
    ///
    /// A vector of ids which has been released.
    /// These should be released in the handshake module.
    ///
    /// # Note
    ///
    /// The number of ids to be released can be at most 3,
    /// since the only way to add additional keys to the peer is by using this method
    /// and a peer can have at most 3 keys allocated in the router at any time.
    pub fn add_keypair(&self, new: KeyPair) -> Vec<u32> {
        log::trace!("Router, add_keypair: {:?}", new);

        let initiator = new.initiator;
        let released_id = {
            let mut keys = self.peer.keys.lock();

            let prev_id = keys.get_prev().map(|k| k.local_id());
            let new_id = new.recv.id;

            let new = Arc::new(new);

            let (encryption_state, decryption_state) = crypto_state(self.peer.clone(), new.clone());

            // update key-wheel
            keys.update(new);

            if initiator {
                // start using key for encryption
                *self.peer.enc_key.lock() = Some(encryption_state);
            }

            log::trace!("peer.add_keypair: updating inbound id map");

            // update incoming packet id map
            self.peer
                .device
                .add_receiver(prev_id, new_id, decryption_state)
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

    pub fn send_keepalive(&self) {
        log::trace!("peer.send_keepalive");
        self.peer.send(vec![0u8; SIZE_MESSAGE_PREFIX], false)
    }

    /// Map a subnet to the peer
    ///
    /// # Arguments
    ///
    /// - `ip`, the mask of the subnet
    /// - `masklen`, the length of the mask
    ///
    /// # Note
    ///
    /// The `ip` must not have any bits set right of `masklen`.
    /// e.g. `192.168.1.0/24` is valid, while `192.168.1.128/24` is not.
    ///
    /// If an identical value already exists as part of a prior peer,
    /// the allowed IP entry will be removed from that peer and added to this peer.
    pub fn add_allowed_ip(&self, ip: IpAddr, masklen: u32) {
        self.peer
            .device
            .insert_route(ip, masklen, self.peer.clone())
    }

    /// List subnets mapped to the peer
    ///
    /// # Returns
    ///
    /// A vector of subnets, represented by as mask/size
    pub fn list_allowed_ips(&self) -> Vec<(IpAddr, u32)> {
        self.peer.device.list_routes(&self.peer)
    }

    pub fn clear_src(&self) {
        if let Some(e) = (*self.peer.endpoint.lock()).as_mut() {
            e.clear_src()
        }
    }

    pub fn purge_staged_packets(&self) {
        self.peer.staged_packets.lock().clear();
    }
}
