// Platform-specific implementations

#[cfg(target_os = "macos")]
mod macos {
    pub mod fd;
    pub mod tun;
}

#[cfg(target_os = "linux")]
mod linux {
    pub mod tun;
}

mod std_udp;
mod unix;

// Dummy implementations for testing
#[cfg(feature = "dummy")]
pub mod dummy;

// Export the platform-specific types with unified names
#[cfg(target_os = "macos")]
pub use macos::tun::MacosTun as Tun;

#[cfg(target_os = "linux")]
pub use linux::tun::LinuxTun as Tun;

pub use std_udp::StdUDP as UDP;

// UAPI is shared across Unix platforms
pub use unix::uapi::UnixUAPI as UAPI;
