#[cfg(test)]
pub mod tests;

#[allow(clippy::module_inception)]
mod wireguard;

// represents a WireGuard interface
pub use wireguard::WireGuard;
