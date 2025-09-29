#![cfg_attr(feature = "unstable", feature(test))]

#[cfg(feature = "profiler")]
use cpuprofiler::PROFILER;

use std::{
    env,
    process::{ExitCode, Termination, exit},
    thread,
};

use anyhow::anyhow;

use crate::configuration::{Configuration, WireGuardConfig, uapi};
use crate::platform::{
    plt,
    tun::{PlatformTun, Status, TunEvent},
    uapi::{BindUAPI, PlatformUAPI},
};
use crate::util;
use crate::wireguard::WireGuard;

#[cfg(feature = "profiler")]
fn profiler_stop() {
    println!("Stopping profiler");
    PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(not(feature = "profiler"))]
fn profiler_stop() {}

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

pub enum MainResult {
    Good,
    NoDeviceNameSupplied,
    UAPIListenerCreationFailed(anyhow::Error),
    TUNDeviceCreationFailed(anyhow::Error),
    DropPriviligesFailed(anyhow::Error),
    DaemonizeFailed(anyhow::Error),
}

impl Termination for MainResult {
    fn report(self) -> ExitCode {
        match self {
            MainResult::Good => ExitCode::from(0),
            MainResult::NoDeviceNameSupplied => {
                eprintln!("No device name supplied");
                ExitCode::from(1)
            }
            MainResult::UAPIListenerCreationFailed(e) => {
                eprintln!("Failed to create UAPI listener: {}", e);
                ExitCode::from(2)
            }
            MainResult::TUNDeviceCreationFailed(e) => {
                eprintln!("Failed to create TUN device: {}", e);
                ExitCode::from(3)
            }
            MainResult::DropPriviligesFailed(e) => {
                eprintln!("Failed to drop privileges: {}", e);
                ExitCode::from(4)
            }
            MainResult::DaemonizeFailed(e) => {
                eprintln!("Failed to daemonize: {}", e);
                ExitCode::from(5)
            }
        }
    }
}

struct Config {
    name: String,
    drop_privileges: bool,
    foreground: bool,
}

impl Config {
    fn from_args(mut args: env::Args) -> Result<Config, MainResult> {
        let mut name = None;
        let mut drop_privileges = true;
        let mut foreground = false;

        // skip path (argv[0])
        args.next();
        for arg in args {
            match arg.as_str() {
                "--foreground" | "-f" => {
                    foreground = true;
                }
                "--disable-drop-privileges" => {
                    drop_privileges = false;
                }
                dev => name = Some(dev.to_owned()),
            }
        }

        let name = name.ok_or(MainResult::NoDeviceNameSupplied)?;

        Ok(Config {
            name,
            drop_privileges,
            foreground,
        })
    }
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
    #[cfg(feature = "profiler")]
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

pub fn create_config_and_run() -> Result<(), MainResult> {
    // parse command line arguments
    let config = Config::from_args(env::args())?;

    run(config)
}
