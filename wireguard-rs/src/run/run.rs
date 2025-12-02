use std::env;

use anyhow::anyhow;

use wg_platform as plt;
use wg_traits::uapi::PlatformUAPI;

use crate::wireguard::WireGuard;
use crate::workers::run_workers;

use super::config::Config;
use super::error::ErrorReason;
use super::profiler::{profiler_start, profiler_stop};
use super::util;

pub fn create_config_and_run() -> Result<(), ErrorReason> {
    // parse command line arguments
    let config = Config::from_args(env::args())?;

    run(config)
}

fn run(config: Config) -> Result<(), ErrorReason> {
    let name = &config.name;

    let uapi_socket = plt::UAPI::bind(name.as_str())
        .map_err(|e| ErrorReason::UAPIListenerCreationFailed(anyhow!(e)))?;

    let (tun_readers, tun_writer, tun_status) = plt::Tun::create(name.as_str())
        .map_err(|e| ErrorReason::TUNDeviceCreationFailed(anyhow!(e)))?;

    if config.drop_privileges {
        util::drop_privileges().map_err(|e| ErrorReason::DropPriviligesFailed(anyhow!(e)))?;
    }

    if !config.foreground {
        util::daemonize().map_err(|e| ErrorReason::DaemonizeFailed(anyhow!(e)))?;
    }

    initialize_logger();

    log::info!("Starting {} WireGuard device.", name);

    profiler_start(name.as_str());

    let n_cpus =
        std::thread::available_parallelism().expect("parallelism info should be available");

    let (handshake_sender, handshake_receiver) = crossbeam_channel::bounded(n_cpus.get());

    let wireguard_device = WireGuard::<plt::Tun, plt::UDP>::new(tun_writer, handshake_sender);

    run_workers(
        uapi_socket,
        tun_readers,
        tun_status,
        handshake_receiver,
        n_cpus,
        wireguard_device,
    );

    profiler_stop();

    Ok(())
}

fn initialize_logger() {
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");
}
