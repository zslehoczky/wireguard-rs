#![cfg_attr(feature = "unstable", feature(test))]

extern crate alloc;

#[cfg(feature = "profiler")]
extern crate cpuprofiler;

pub mod run;

mod configuration;
mod platform;
mod wireguard;
