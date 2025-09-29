#![cfg_attr(feature = "unstable", feature(test))]

#[cfg(feature = "profiler")]
use cpuprofiler::PROFILER;

use super::config::Config;
use super::main_result::MainResult;

use std::{env, process::exit, thread};

use anyhow::anyhow;

use crate::configuration::{Configuration, WireGuardConfig, uapi};
use crate::platform::{
    plt,
    tun::{PlatformTun, Status, TunEvent},
    uapi::{BindUAPI, PlatformUAPI},
};
use crate::util;
use crate::wireguard::WireGuard;

pub fn create_config_and_run() -> Result<(), MainResult> {
    // parse command line arguments
    let config = Config::from_args(env::args())?;

    run(config)
}

#[cfg(not(feature = "profiler"))]
fn profiler_start(_name: &str) {}

#[cfg(feature = "profiler")]
fn profiler_start(name: &str) {
    use std::path::Path;

    // find first available path to save profiler output
    let mut n = 0;
    loop {
        let path = format!("./{}-{}.profile", name, n);
        if !Path::new(path.as_str()).exists() {
            println!("Starting profiler: {}", path);
            PROFILER.lock().unwrap().start(path).unwrap();
            break;
        };
        n += 1;
    }
}

#[cfg(not(feature = "profiler"))]
fn profiler_stop() {}

#[cfg(feature = "profiler")]
fn profiler_stop() {
    println!("Stopping profiler");
    PROFILER.lock().unwrap().stop().unwrap();
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

    // start logging
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");

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
    {
        let cfg = cfg.clone();
        let mut status = status;
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
        });
    }

    // start UAPI server
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
    });

    // block until all tun readers closed
    wg.wait();
    profiler_stop();

    Ok(())
}
