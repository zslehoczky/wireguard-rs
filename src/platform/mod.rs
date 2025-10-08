mod endpoint;

pub mod tun;
pub mod uapi;
pub mod udp;

pub use endpoint::Endpoint;

#[cfg(target_os = "linux")]
#[path = "linux/mod.rs"]
pub mod plt;

#[cfg(target_os = "macos")]
#[path = "macos/mod.rs"]
pub mod plt;

pub(crate) mod unix;

#[cfg(test)]
pub mod dummy;
