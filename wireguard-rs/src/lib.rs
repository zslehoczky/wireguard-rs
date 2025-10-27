extern crate alloc;

#[cfg(feature = "profiler")]
extern crate cpuprofiler;

pub mod run;

mod configuration;
pub mod wireguard;
