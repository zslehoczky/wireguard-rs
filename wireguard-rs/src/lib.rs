extern crate alloc;

#[cfg(feature = "profiler")]
extern crate cpuprofiler;

mod configuration;
pub mod router;
pub mod run;
pub mod timers;
pub mod wireguard;
pub mod workers;
