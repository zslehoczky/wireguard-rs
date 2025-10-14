mod config;
mod error;
pub mod uapi;

use super::wireguard::WireGuard;

pub use error::ConfigError;

pub use config::Configuration;
pub use config::WireGuardConfig;
