use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::router::{KeyPair, PeerDependencies, PeerState, RouterError};

pub trait PeerHandle<P: PeerDependencies>: Send + Sync + fmt::Display {
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
    fn set_endpoint(&self, endpoint: P::UdpEndpoint);

    /// Returns the current endpoint of the peer (for configuration)
    ///
    /// # Note
    ///
    /// Does not convey potential "sticky socket" information
    fn get_endpoint(&self) -> Option<SocketAddr>;

    /// Zero all key-material related to the peer
    fn zero_keys(&self);

    fn down(&self);

    fn up(&self);

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
    fn add_keypair(&self, new: KeyPair) -> Vec<u32>;

    fn send_keepalive(&self);

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
    fn add_allowed_ip(&self, ip: IpAddr, masklen: u32);

    /// List subnets mapped to the peer
    ///
    /// # Returns
    ///
    /// A vector of subnets, represented by as mask/size
    fn list_allowed_ips(&self) -> Vec<(IpAddr, u32)>;

    fn clear_src(&self);

    fn purge_staged_packets(&self);

    /// Send a raw message to the peer (used for handshake messages)
    ///
    /// # Arguments
    ///
    /// - `msg`, message body to send to peer
    ///
    /// # Returns
    ///
    /// Unit if packet was sent, or an error indicating why sending failed
    fn send_raw(&self, msg: &[u8]) -> Result<(), RouterError>;

    fn set_peer_state(&self, peer_state: Arc<dyn PeerState>);
}
