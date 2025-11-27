use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use wg_crypto::PSK;
use wg_traits::{
    Configuration, Endpoint, tun,
    udp::{self, Owner},
};
use wg_uapi::uapi::{ConfigError, PeerState};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::wireguard::WireGuard;

const PROTOCOL_VERSION: usize = 1;

pub struct WireGuardConfig<'device, T: tun::Tun, B: udp::PlatformUDP> {
    wireguard: &'device WireGuard<T, B>,
    port: u16,
    bind: Option<B::Owner>,
    fwmark: Option<u32>,
}

impl<'device, T: tun::Tun, B: udp::PlatformUDP> WireGuardConfig<'device, T, B> {
    pub fn new(wg: &'device WireGuard<T, B>) -> Self {
        WireGuardConfig {
            wireguard: wg,
            port: 0,
            bind: None,
            fwmark: None,
        }
    }
}

/// Exposed configuration interface
fn start_listener<T: tun::Tun, B: udp::PlatformUDP>(
    cfg: &mut WireGuardConfig<T, B>,
) -> Result<(), ConfigError> {
    cfg.bind = None;

    // create new listener
    let (mut readers, writer, mut owner) = match B::bind(cfg.port) {
        Ok(r) => r,
        Err(_) => {
            return Err(ConfigError::FailedToBind);
        }
    };

    // set fwmark
    let _ = owner.set_fwmark(cfg.fwmark); // TODO: handle

    // set writer on WireGuard
    cfg.wireguard.set_writer(writer);

    // add readers
    while let Some(reader) = readers.pop() {
        cfg.wireguard.add_udp_reader(reader);
    }

    // create new UDP state
    cfg.bind = Some(owner);
    Ok(())
}

impl<'device, T: tun::Tun, B: udp::PlatformUDP>
    Configuration<ConfigError, PeerState, PublicKey, StaticSecret>
    for WireGuardConfig<'device, T, B>
{
    fn up(&mut self, mtu: usize) -> Result<(), ConfigError> {
        log::info!("configuration, set device up");
        self.wireguard.up(mtu);
        start_listener(self)
    }

    fn down(&mut self) {
        log::info!("configuration, set device down");
        self.wireguard.down();
        self.bind = None;
    }

    fn get_fwmark(&self) -> Option<u32> {
        self.fwmark
    }

    fn set_private_key(&self, sk: Option<StaticSecret>) {
        log::info!("configuration, set private key");
        self.wireguard.set_key(sk)
    }

    fn get_private_key(&self) -> Option<StaticSecret> {
        self.wireguard.get_sk()
    }

    fn get_protocol_version(&self) -> usize {
        PROTOCOL_VERSION
    }

    fn get_listen_port(&self) -> Option<u16> {
        log::trace!("Config, Get listen port, bound: {}", self.bind.is_some());
        self.bind.as_ref().map(|bind| bind.get_port())
    }

    fn set_listen_port(&mut self, port: u16) -> Result<(), ConfigError> {
        log::trace!("Config, Set listen port: {:?}", port);

        self.port = port;

        // start or restart listener
        // Always call start_listener to ensure the port is bound
        let result = start_listener(self);

        // Workaround for macOS: manually bring device up if not already
        // On macOS, RTM_IFINFO events aren't always sent when ifconfig is run
        // so we manually check and set the MTU here
        // TODO: Investigate why RTM_IFINFO events are not reliably delivered on macOS
        #[cfg(target_os = "macos")]
        {
            if self.wireguard.get_mtu() == 0 {
                // Try to bring up with a default MTU
                // The TUN event handler should update this if the real MTU changes
                self.up(1420)?; // Standard WireGuard MTU
            }
        }

        result
    }

    fn set_fwmark(&mut self, mark: Option<u32>) -> Result<(), ConfigError> {
        log::trace!("Config, Set fwmark: {:?}", mark);
        match self.bind.as_mut() {
            Some(bind) => {
                if bind.set_fwmark(mark).is_err() {
                    Err(ConfigError::IOError)
                } else {
                    Ok(())
                }
            }
            None => Ok(()),
        }
    }

    fn remove_peer(&self, peer: &PublicKey) {
        self.wireguard.remove_peer(peer);
    }

    fn add_peer(&self, peer: &PublicKey) -> bool {
        self.wireguard.add_peer(*peer).is_some()
    }

    fn set_preshared_key(&self, peer: &PublicKey, psk: [u8; 32]) {
        self.wireguard.set_psk(*peer, PSK::from(psk));
    }

    fn set_endpoint(&self, peer: &PublicKey, addr: SocketAddr) {
        if let Some(peer_state) = self.wireguard.get_peer(peer) {
            peer_state
                .get_peer_handle()
                .set_endpoint(<B::Endpoint as Endpoint>::from_address(addr));
        }
    }

    fn set_persistent_keepalive_interval(&self, peer: &PublicKey, secs: u64) {
        if let Some(peer_state) = self.wireguard.get_peer(peer) {
            peer_state.set_persistent_keepalive_interval(secs);
        }
    }

    fn add_allowed_ip(&self, peer: &PublicKey, ip: IpAddr, masklen: u32) {
        if let Some(peer_state) = self.wireguard.get_peer(peer) {
            peer_state.get_peer_handle().add_allowed_ip(ip, masklen);
        }
    }

    fn get_peers(&self) -> Vec<PeerState> {
        let mut state = vec![];

        self.wireguard.for_each_peer(|&public_key, peer_state| {
            // convert the system time to (secs, nano) since epoch
            let last_handshake_time = peer_state.get_walltime_last_handshake().map(|t| {
                let duration = t
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0));
                (duration.as_secs(), duration.subsec_nanos() as u64)
            });

            if let Some(psk) = self.wireguard.get_psk(&public_key) {
                // extract state into PeerState
                state.push(PeerState {
                    preshared_key: psk,
                    endpoint: peer_state.get_peer_handle().get_endpoint(),
                    rx_bytes: peer_state.get_rx_bytes(),
                    tx_bytes: peer_state.get_tx_bytes(),
                    persistent_keepalive_interval: peer_state.get_keepalive_interval(),
                    allowed_ips: peer_state.get_peer_handle().list_allowed_ips(),
                    last_handshake_time,
                    public_key,
                })
            }
        });

        state
    }
}
