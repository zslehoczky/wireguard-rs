#![cfg_attr(feature = "unstable", feature(test))]

use super::config::Config;
use super::main_result::MainResult;
use super::profiler::{profiler_start, profiler_stop};

use std::thread::JoinHandle;
use std::{env, process::exit, thread};

use anyhow::anyhow;

use crate::configuration::{Configuration, WireGuardConfig, uapi};
use crate::platform::{
    plt,
    tun::{PlatformTun, Status, Tun, TunEvent},
    uapi::{BindUAPI, PlatformUAPI},
    udp::PlatformUDP,
};
use crate::util;
use crate::wireguard::WireGuard;

pub fn create_config_and_run() -> Result<(), MainResult> {
    // parse command line arguments
    let config = Config::from_args(env::args())?;

    run(config)
}

fn run(config: Config) -> Result<(), MainResult> {
    let name = &config.name;
    let drop_privileges = config.drop_privileges;
    let foreground = config.foreground;

    // create UAPI socket
    let uapi = plt::UAPI::bind(name.as_str())
        .map_err(|e| return MainResult::UAPIListenerCreationFailed(anyhow!(e)))?;

    // create TUN device
    let (mut readers, writer, status) = plt::Tun::create(name.as_str())
        .map_err(|e| return MainResult::TUNDeviceCreationFailed(anyhow!(e)))?;

    // drop privileges
    if drop_privileges {
        util::drop_privileges().map_err(|e| return MainResult::DropPriviligesFailed(anyhow!(e)))?;
    }

    // daemonize to background
    if !foreground {
        util::daemonize().map_err(|e| return MainResult::DaemonizeFailed(anyhow!(e)))?;
    }

    initialize_logger();

    log::info!("Starting {} WireGuard device.", name);

    // start profiler (if enabled)
    profiler_start(name.as_str());

    // create WireGuard device
    let wg: WireGuard<plt::Tun, plt::UDP> = WireGuard::new(writer);

    // add all Tun readers
    while let Some(reader) = readers.pop() {
        wg.add_tun_reader(reader);
    }

    // wrap in configuration interface
    let cfg = WireGuardConfig::new(wg.clone());

    // start Tun event thread
    spawn_tun_event_loop(cfg.clone(), status);

    // start UAPI server
    spawn_uapi_server(cfg, uapi);

    // block until all tun readers closed
    wg.wait();
    profiler_stop();

    Ok(())
}

fn initialize_logger() {
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");
}

fn spawn_tun_event_loop<T: Tun, B: PlatformUDP, S: Status>(
    cfg: WireGuardConfig<T, B>,
    mut status: S,
) -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            match status.event() {
                Err(e) => {
                    log::info!("Tun device error {}", e);
                    profiler_stop();
                    exit(0);
                }
                Ok(TunEvent::Up(mtu)) => {
                    log::info!("Tun up (mtu = {})", mtu);
                    let _ = cfg.up(mtu); // TODO: handle
                }
                Ok(TunEvent::Down) => {
                    log::info!("Tun down");
                    cfg.down();
                }
            }
        }
    })
}

fn spawn_uapi_server<T: Tun, B: PlatformUDP, U: BindUAPI + Send + 'static>(
    cfg: WireGuardConfig<T, B>,
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
                    let cfg = cfg.clone();
                    thread::spawn(move || {
                        uapi::handle(&mut stream, &cfg);
                    });
                }
                Err(err) => {
                    log::info!("UAPI connection error: {}", err);
                    profiler_stop();
                    exit(-1);
                }
            }
        }
    })
}
