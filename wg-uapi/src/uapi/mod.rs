mod config_operation;
mod config_response;
mod error;
mod get;
mod set;

pub use config_operation::{ConfigOperation, parse_config_operation, parse_non_empty_lines};
pub use config_response::write_config_response;
pub use error::ConfigError;

use std::net::{IpAddr, SocketAddr};

use x25519_dalek::{PublicKey, StaticSecret};

use wg_crypto::PSK;
use wg_traits::Configuration;

use get::serialize;
use set::LineParser;

/// The goal of the configuration interface is, among others,
/// to hide the IO implementations (over which the WG device is generic),
/// from the configuration and UAPI code.
///
/// Furthermore it forms the simpler interface for embedding WireGuard in other applications,
/// and hides the complex types of the implementation from the host application.
///
/// Describes a snapshot of the state of a peer
pub struct PeerState {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_time: Option<(u64, u64)>,
    pub public_key: PublicKey,
    pub allowed_ips: Vec<(IpAddr, u32)>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: u64,
    pub preshared_key: PSK,
}

pub fn handle_config_operation<
    C: Configuration<ConfigError, PeerState, PublicKey, StaticSecret>,
>(
    config_operation: ConfigOperation,
    config: &mut C,
) -> Result<String, ConfigError> {
    match config_operation {
        ConfigOperation::Get => {
            log::debug!("UAPI, Get operation");

            Ok(serialize(config))
        }
        ConfigOperation::Set(key_value_pairs) => {
            log::debug!("UAPI, Set operation");

            let mut parser = LineParser::new(config);
            for (k, v) in key_value_pairs {
                parser.parse_line(&k, &v)?;
            }
            parser.finalize();

            Ok(String::new())
        }
    }
}
