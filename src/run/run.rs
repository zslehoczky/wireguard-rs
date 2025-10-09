#![cfg_attr(feature = "unstable", feature(test))]

use std::thread::{JoinHandle, ScopedJoinHandle, scope};
use std::{env, process::exit, thread};

use anyhow::anyhow;

use crate::configuration::{Configuration, WireGuardConfig, uapi};
use crate::platform::{
    plt,
    tun::{PlatformTun, Status, Tun, TunEvent},
    uapi::{BindUAPI, PlatformUAPI},
    udp::PlatformUDP,
};
use crate::wireguard::{WireGuard, tun_worker};

use super::config::Config;
use super::error::{ErrorReason, ExitCode};
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

    let wireguard_device = WireGuard::<plt::Tun, plt::UDP>::new(tun_writer);
    let wireguard_config = WireGuardConfig::new(wireguard_device.clone());

    scope(|s| {
        let _tun_reader_jobs: Vec<ScopedJoinHandle<'_, ()>> = tun_readers
            .into_iter()
            .map(|reader| {
                s.spawn(|| {
                    tun_worker(&wireguard_device, reader);
                })
            })
            .collect();

        spawn_tun_event_loop(wireguard_config.clone(), tun_status);

        spawn_uapi_server(wireguard_config, uapi_socket);

        // block until all tun reader jobs join
    });

    profiler_stop();

    Ok(())
}

fn initialize_logger() {
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");
}

fn spawn_tun_event_loop<T: Tun, B: PlatformUDP, S: Status>(
    wireguard_config: WireGuardConfig<T, B>,
    mut tun_status: S,
) -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            match tun_status.event() {
                Err(e) => {
                    log::error!("Tun device error {}", e);
                    profiler_stop();
                    exit(ExitCode::TUNDeviceError as i32);
                }
                Ok(TunEvent::Up(mtu)) => {
                    log::info!("Tun up (mtu = {})", mtu);
                    let _ = wireguard_config.up(mtu); // TODO: handle
                }
                Ok(TunEvent::Down) => {
                    log::info!("Tun down");
                    wireguard_config.down();
                }
            }
        }
    })
}

fn spawn_uapi_server<T: Tun, B: PlatformUDP, U: BindUAPI + Send + 'static>(
    wireguard_config: WireGuardConfig<T, B>,
    uapi: U,
) -> JoinHandle<()>
where
    <U as BindUAPI>::Stream: Send,
    <U as BindUAPI>::Stream: 'static,
{
    thread::spawn(move || {
        loop {
            // accept and handle UAPI config connections
            match uapi.connect() {
                Ok(mut stream) => {
                    let wireguard_config = wireguard_config.clone();
                    thread::spawn(move || {
                        uapi::handle(&mut stream, &wireguard_config);
                    });
                }
                Err(err) => {
                    log::error!("UAPI connection error: {}", err);
                    profiler_stop();
                    exit(ExitCode::UAPIConnectionError as i32);
                }
            }
        }
    })
}
