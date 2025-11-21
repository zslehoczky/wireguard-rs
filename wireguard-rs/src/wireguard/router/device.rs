use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;

use spin::RwLock;
use zerocopy::LayoutVerified;

use wg_traits::{Endpoint, tun, udp};

use super::callbacks::Callbacks;
use super::constants::{PARALLEL_QUEUE_SIZE, SIZE_MESSAGE_PREFIX};
use super::parallel_queue::{NonZeroUsize, ParallelJobUnion, ParallelQueue};
use super::peer::{DecryptionState, Peer, PeerHandle, new_peer};
use super::receive::ReceiveJob;
use super::router_error::RouterError;
use super::routing_table::RoutingTable;
use super::transport::{TYPE_TRANSPORT, TransportHeader};

type ReceiverLookup<P> = HashMap<u32, Arc<DecryptionState<P>>>; /* receiver id -> decryption state */

pub struct DeviceInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    // inbound writer (TUN)
    inbound: T,

    // outbound writer (Bind)
    outbound: RwLock<(bool, Option<B>)>,

    // routing
    recv: RwLock<ReceiverLookup<Peer<E, C, T, B>>>,
    table: RoutingTable<Peer<E, C, T, B>>,

    // work queue
    parallel_queue: ParallelQueue<E, C, T, B>,
}

pub struct Device<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    inner: Arc<DeviceInner<E, C, T, B>>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Device<E, C, T, B> {
    pub fn new(num_workers: usize, tun: T) -> Self {
        let parallel_queue = ParallelQueue::new(
            NonZeroUsize::new(num_workers).expect("should not be zero"),
            PARALLEL_QUEUE_SIZE,
        );

        Self {
            inner: Arc::new(DeviceInner {
                parallel_queue,
                inbound: tun,
                outbound: RwLock::new((true, None)),
                recv: RwLock::new(HashMap::new()),
                table: RoutingTable::new(),
            }),
        }
    }

    pub fn send_raw(&self, msg: &[u8], dst: &mut E) -> Result<(), B::Error> {
        let bind = self.outbound.read();
        if bind.0
            && let Some(bind) = bind.1.as_ref()
        {
            return bind.write(msg, dst);
        }
        Ok(())
    }

    /// Brings the router down.
    /// When the router is brought down it:
    /// - Prevents transmission of outbound messages.
    pub fn down(&self) {
        self.outbound.write().0 = false;
    }

    /// Brints the router up
    /// When the router is brought up it enables the transmission of outbound messages.
    pub fn up(&self) {
        self.outbound.write().0 = true;
    }

    /// A new secret key has been set for the device.
    /// According to WireGuard semantics, this should cause all "sending" keys to be discarded.
    pub fn clear_sending_keys(&self) {
        log::debug!("Clear sending keys");
        // TODO: Implement. Consider: The device does not have an explicit list of peers
    }

    /// Adds a new peer to the device
    ///
    /// # Returns
    ///
    /// A atomic ref. counted peer (with liftime matching the device)
    pub fn new_peer(&self, opaque: C::Opaque) -> PeerHandle<E, C, T, B> {
        new_peer(self.clone(), opaque)
    }

    /// Cryptkey routes and sends a plaintext message (IP packet)
    ///
    /// # Arguments
    ///
    /// - msg: IP packet to crypt-key route
    pub fn send(&self, msg: Vec<u8>) -> Result<(), RouterError> {
        debug_assert!(msg.len() > SIZE_MESSAGE_PREFIX);
        log::trace!(
            "send, packet = {}",
            hex::encode(&msg[SIZE_MESSAGE_PREFIX..])
        );

        // ignore header prefix (for in-place transport message construction)
        let packet = &msg[SIZE_MESSAGE_PREFIX..];

        // lookup peer based on IP packet destination address
        let peer = self
            .table
            .get_route(packet)
            .ok_or(RouterError::NoCryptoKeyRoute)?;

        // schedule for encryption and transmission to peer
        peer.send(msg, true);
        Ok(())
    }

    /// Receive an encrypted transport message
    ///
    /// # Arguments
    ///
    /// - src: Source address of the packet
    /// - msg: Encrypted transport message
    ///
    /// # Returns
    pub fn recv(&self, src: E, msg: Vec<u8>) -> Result<(), RouterError> {
        log::trace!("receive, src: {}", src.to_address());

        // parse / cast
        let (header, _) = match LayoutVerified::new_from_prefix(&msg[..]) {
            Some(v) => v,
            None => {
                return Err(RouterError::MalformedTransportMessage);
            }
        };

        let header: LayoutVerified<&[u8], TransportHeader> = header;

        debug_assert!(
            header.f_type.get() == TYPE_TRANSPORT,
            "this should be checked by the message type multiplexer"
        );

        log::trace!(
            "handle transport message: (receiver = {}, counter = {})",
            header.f_receiver,
            header.f_counter
        );

        // lookup peer based on receiver id
        let dec = self.recv.read();
        let dec = dec
            .get(&header.f_receiver.get())
            .ok_or(RouterError::UnknownReceiverId)?;

        // create inbound job
        let job = ReceiveJob::new(msg, dec.clone(), src);

        // 1. add to sequential queue (drop if full)
        // 2. then add to parallel work queue (wait if full)
        if dec.get_peer().get_inbound().push(job.clone()) {
            self.parallel_queue
                .queue_job(ParallelJobUnion::Inbound(job));
        }
        Ok(())
    }

    /// Set outbound writer
    pub fn set_outbound_writer(&self, new: B) {
        self.outbound.write().1 = Some(new);
    }

    pub fn queue_job(&self, job: ParallelJobUnion<E, C, T, B>) {
        self.parallel_queue.queue_job(job);
    }

    pub fn add_receiver(
        &self,
        prev_id: Option<u32>,
        new_id: u32,
        decryption_state: DecryptionState<Peer<E, C, T, B>>,
    ) -> Option<u32> {
        let mut release = None;

        log::trace!("peer.add_keypair: updating inbound id map");
        let mut recv = self.inner.recv.write();

        // purge recv map of previous id
        if let Some(prev_id) = prev_id {
            recv.remove(&prev_id);
            release = Some(prev_id);
        }

        // map new id to decryption state
        debug_assert!(!recv.contains_key(&new_id));
        recv.insert(new_id, Arc::new(decryption_state));

        release
    }

    pub fn remove_receivers(&self, release: &[u32]) {
        let mut recv = self.inner.recv.write();
        for id in release {
            recv.remove(id);
        }
    }

    pub fn write_inbound(&self, data: &[u8]) {
        self.inbound.write(data).unwrap_or_else(|e| {
            log::debug!("failed to write inbound packet to TUN: {:?}", e);
        })
    }

    pub fn read_outbound(&self, msg: &[u8], endpoint: &mut E) -> Result<(), RouterError> {
        let outbound = self.outbound.read();
        let (open, outbound) = outbound.deref();
        if *open {
            outbound
                .as_ref()
                .ok_or(RouterError::SendError)
                .and_then(|w| w.write(msg, endpoint).map_err(|_| RouterError::SendError))
        } else {
            Ok(())
        }
    }

    pub fn check_route(&self, peer: &Peer<E, C, T, B>, packet: &mut [u8]) -> bool {
        self.table.check_route(peer, packet)
    }

    pub fn insert_route(&self, ip: IpAddr, cidr: u32, peer: Peer<E, C, T, B>) {
        self.table.insert(ip, cidr, peer)
    }

    pub fn list_routes(&self, peer: &Peer<E, C, T, B>) -> Vec<(IpAddr, u32)> {
        self.table.list(peer)
    }

    pub fn remove_route(&self, peer: &Peer<E, C, T, B>) {
        self.table.remove(peer)
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Clone for Device<E, C, T, B> {
    fn clone(&self) -> Self {
        Device {
            inner: self.inner.clone(),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> PartialEq
    for Device<E, C, T, B>
{
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Eq for Device<E, C, T, B> {}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Deref for Device<E, C, T, B> {
    type Target = DeviceInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
