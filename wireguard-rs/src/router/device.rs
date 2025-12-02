use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;

use spin::RwLock;
use wg_traits::udp;
use zerocopy::LayoutVerified;

use wg_traits::{Endpoint as _, tun::Writer as _, udp::Writer as _};

use crate::peer::{Peer, PeerDependencies, PeerHandle, PeerHandleInterface};

use super::constants::SIZE_MESSAGE_PREFIX;
use super::peer_lookup::PeerLookup;
use super::router_error::RouterError;
use super::routing_table::RoutingTable;
use super::transport::{TYPE_TRANSPORT, TransportHeader};

pub struct DeviceInner<P: PeerDependencies> {
    inbound: P::TunWriter,
    outbound: RwLock<(bool, Option<P::UdpWriter>)>,
    inbound_peer_lookup: RwLock<PeerLookup<P>>,
    outbound_routing_table: RoutingTable<P>,
}

pub struct Device<P: PeerDependencies> {
    inner: Arc<DeviceInner<P>>,
}

impl<P: PeerDependencies> Device<P> {
    pub fn new(tun: P::TunWriter) -> Self {
        Self {
            inner: Arc::new(DeviceInner {
                inbound: tun,
                outbound: RwLock::new((true, None)),
                inbound_peer_lookup: RwLock::new(PeerLookup::new()),
                outbound_routing_table: RoutingTable::new(),
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

    /// Brings the router up
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
    pub fn new_peer(&self) -> Arc<dyn PeerHandleInterface<P>> {
        Arc::new(PeerHandle::new(self.clone()))
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
            .outbound_routing_table
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
        let peer = self
            .inbound_peer_lookup
            .read()
            .get(&header.f_receiver.get())
            .ok_or(RouterError::UnknownReceiverId)?
            .clone();

        peer.recv(src, msg);
        Ok(())
    }

    /// Set outbound writer
    pub fn set_outbound_writer(&self, new: P::UdpWriter) {
        self.outbound.write().1 = Some(new);
    }

    pub fn add_receiver(&self, prev_id: Option<u32>, new_id: u32, peer: Peer<P>) -> Option<u32> {
        self.inner
            .inbound_peer_lookup
            .write()
            .add_receiver(prev_id, new_id, peer)
    }

    pub fn remove_receivers(&self, release: &[u32]) {
        self.inner
            .inbound_peer_lookup
            .write()
            .remove_receivers(release)
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
        self.outbound_routing_table.check_route(peer, packet)
    }

    pub fn insert_route(&self, ip: IpAddr, cidr: u32, peer: Peer<P>) {
        self.outbound_routing_table.insert(ip, cidr, peer)
    }

    pub fn list_routes(&self, peer: &Peer<P>) -> Vec<(IpAddr, u32)> {
        self.outbound_routing_table.list(peer)
    }

    pub fn remove_route(&self, peer: &Peer<P>) {
        self.outbound_routing_table.remove(peer)
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
