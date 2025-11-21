pub mod error;

mod config;
pub mod profiler;
#[allow(clippy::module_inception)]
mod run;
mod util;

pub use run::create_config_and_run;
