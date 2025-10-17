#![cfg_attr(feature = "unstable", feature(test))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, ScopedJoinHandle};
use std::{env, process::exit};

use anyhow::anyhow;
use wg_platform as plt;
use wg_traits::{
    tun::{Status, Tun, TunEvent},
    uapi::{BindUAPI, PlatformUAPI},
    udp::PlatformUDP,
};

use crate::configuration::{Configuration, WireGuardConfig, uapi};
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

    let (tun_readers, tun_writer, mut tun_status) = plt::Tun::create(name.as_str())
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
    let tun_reader_jobs_running = AtomicBool::new(true);

    thread::scope(|thread_scope| {
        let tun_reader_jobs: Vec<ScopedJoinHandle<'_, ()>> = tun_readers
            .into_iter()
            .map(|reader| {
                thread_scope.spawn(|| {
                    tun_worker(&wireguard_device, reader);
                })
            })
            .collect();

        spawn_tun_event_loop(
            thread_scope,
            &wireguard_config,
            &mut tun_status,
            &tun_reader_jobs_running,
        );

        spawn_uapi_server(
            thread_scope,
            &wireguard_config,
            &uapi_socket,
            &tun_reader_jobs_running,
        );

        let _: Vec<_> = tun_reader_jobs
            .into_iter()
            .map(|handle| {
                let _ = handle.join();
            })
            .collect();

        tun_reader_jobs_running.store(false, Ordering::Release);

        // tun_event_loop and uapi_server joined here
    });

    profiler_stop();

    Ok(())
}

fn initialize_logger() {
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");
}

fn spawn_tun_event_loop<'scope, 'env, T: Tun, B: PlatformUDP, S: Status>(
    thread_scope: &'scope thread::Scope<'scope, 'env>,
    wireguard_config: &'env WireGuardConfig<T, B>,
    tun_status: &'env mut S,
    tun_reader_jobs_running: &'env AtomicBool,
) -> ScopedJoinHandle<'scope, ()> {
    thread_scope.spawn(|| {
        while tun_reader_jobs_running.load(Ordering::Acquire) {
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

fn spawn_uapi_server<'scope, 'env, T: Tun, B: PlatformUDP, U: BindUAPI + Send + Sync>(
    thread_scope: &'scope thread::Scope<'scope, 'env>,
    wireguard_config: &'env WireGuardConfig<T, B>,
    uapi: &'env U,
    tun_reader_jobs_running: &'env AtomicBool,
) -> ScopedJoinHandle<'scope, ()>
where
    <U as BindUAPI>::Stream: Send,
    <U as BindUAPI>::Stream: 'env,
{
    thread_scope.spawn(|| {
        while tun_reader_jobs_running.load(Ordering::Acquire) {
            // accept and handle UAPI config connections
            match uapi.connect() {
                Ok(stream) => {
                    thread_scope.spawn(|| {
                        let mut stream = stream;
                        uapi::handle(&mut stream, wireguard_config);
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
