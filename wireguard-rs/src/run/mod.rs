pub mod error;

mod config;
mod profiler;
mod runner;
mod util;
mod workers;

pub use runner::create_config_and_run;
