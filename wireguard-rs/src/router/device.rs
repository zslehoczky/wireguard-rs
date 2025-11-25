use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;

use spin::RwLock;
use wg_traits::udp;
use zerocopy::LayoutVerified;

use wg_traits::{Endpoint as _, tun::Writer as _, udp::Writer as _};

use super::constants::{PARALLEL_QUEUE_SIZE, SIZE_MESSAGE_PREFIX};
use super::parallel_queue::{NonZeroUsize, ParallelJobUnion, ParallelQueue};
use super::peer::{DecryptionState, Peer, PeerDependencies, PeerHandle, PeerState};
use super::receive::ReceiveJob;
use super::receiver_lookup::ReceiverLookup;
use super::router_error::RouterError;
use super::routing_table::RoutingTable;
use super::transport::{TYPE_TRANSPORT, TransportHeader};

pub struct DeviceInner<P: PeerDependencies> {
    inbound: P::TunWriter,
    outbound: RwLock<(bool, Option<P::UdpWriter>)>,
    recv: RwLock<ReceiverLookup<Peer<P>>>,
    table: RoutingTable<Peer<P>>,
    parallel_queue: ParallelQueue<P>,
}

pub struct Device<P: PeerDependencies> {
    inner: Arc<DeviceInner<P>>,
}

impl<P: PeerDependencies> Device<P> {
    pub fn new(num_workers: usize, tun: P::TunWriter) -> Self {
        let parallel_queue = ParallelQueue::new(
            NonZeroUsize::new(num_workers).expect("should not be zero"),
            PARALLEL_QUEUE_SIZE,
        );

        Self {
            inner: Arc::new(DeviceInner {
                parallel_queue,
                inbound: tun,
                outbound: RwLock::new((true, None)),
                recv: RwLock::new(ReceiverLookup::new()),
                table: RoutingTable::new(),
            }),
        }
    }

    pub fn send_raw(
        &self,
        msg: &[u8],
        dst: &mut P::UdpEndpoint,
    ) -> Result<(), <P::UdpWriter as udp::Writer<P::UdpEndpoint>>::Error> {
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
    pub fn new_peer(&self, peer_state: Arc<dyn PeerState>) -> PeerHandle<P> {
        PeerHandle::new(self.clone(), peer_state)
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
    pub fn recv(&self, src: P::UdpEndpoint, msg: Vec<u8>) -> Result<(), RouterError> {
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
        let dec = self
            .recv
            .read()
            .get(&header.f_receiver.get())
            .ok_or(RouterError::UnknownReceiverId)?
            .clone();

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
    pub fn set_outbound_writer(&self, new: P::UdpWriter) {
        self.outbound.write().1 = Some(new);
    }

    pub fn queue_job(&self, job: ParallelJobUnion<P>) {
        self.parallel_queue.queue_job(job);
    }

    pub fn add_receiver(
        &self,
        prev_id: Option<u32>,
        new_id: u32,
        decryption_state: DecryptionState<Peer<P>>,
    ) -> Option<u32> {
        self.inner
            .recv
            .write()
            .add_receiver(prev_id, new_id, decryption_state)
    }

    pub fn remove_receivers(&self, release: &[u32]) {
        self.inner.recv.write().remove_receivers(release)
    }

    pub fn write_inbound(&self, data: &[u8]) {
        self.inbound.write(data).unwrap_or_else(|e| {
            log::debug!("failed to write inbound packet to TUN: {:?}", e);
        })
    }

    pub fn read_outbound(
        &self,
        msg: &[u8],
        endpoint: &mut P::UdpEndpoint,
    ) -> Result<(), RouterError> {
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

    pub fn check_route(&self, peer: &Peer<P>, packet: &mut [u8]) -> bool {
        self.table.check_route(peer, packet)
    }

    pub fn insert_route(&self, ip: IpAddr, cidr: u32, peer: Peer<P>) {
        self.table.insert(ip, cidr, peer)
    }

    pub fn list_routes(&self, peer: &Peer<P>) -> Vec<(IpAddr, u32)> {
        self.table.list(peer)
    }

    pub fn remove_route(&self, peer: &Peer<P>) {
        self.table.remove(peer)
    }
}

impl<P: PeerDependencies> Clone for Device<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<P: PeerDependencies> PartialEq for Device<P> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<P: PeerDependencies> Eq for Device<P> {}

impl<P: PeerDependencies> Deref for Device<P> {
    type Target = DeviceInner<P>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
