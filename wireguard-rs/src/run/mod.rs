pub mod error;

mod config;
pub mod profiler;
mod runner;
mod util;

pub use runner::create_config_and_run;
