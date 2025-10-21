#![cfg_attr(feature = "unstable", feature(test))]

use std::env;
use std::io::Write;
use std::process::exit;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, ScopedJoinHandle};

use anyhow::anyhow;

use crate::configuration::{ConfigError, Configuration, WireGuardConfig, uapi};
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

enum ConfigMessage {
    UapiConfigOperation(
        uapi::ConfigOperation,
        mpsc::Sender<Result<String, ConfigError>>,
    ),
    TunUp(usize),
    TunDown,
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

        let (config_sender, config_receiver) = mpsc::channel();

        spawn_tun_event_loop(
            &thread_scope,
            &tun_reader_jobs_running,
            &mut tun_status,
            config_sender.clone(),
        );

        spawn_uapi_server(
            &thread_scope,
            &tun_reader_jobs_running,
            &uapi_socket,
            config_sender,
        );

        spawn_config_worker(&thread_scope, &wireguard_device, config_receiver);

        for handle in tun_reader_jobs {
            let _ = handle.join();
        }

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

fn spawn_tun_event_loop<'scope, 'env, S: Status>(
    thread_scope: &'scope thread::Scope<'scope, 'env>,
    tun_reader_jobs_running: &'env AtomicBool,
    tun_status: &'env mut S,
    config_sender: mpsc::Sender<ConfigMessage>,
) -> ScopedJoinHandle<'scope, ()> {
    thread_scope.spawn(|| {
        let config_sender = config_sender;

        while tun_reader_jobs_running.load(Ordering::Acquire) {
            match tun_status.event() {
                Err(e) => {
                    log::error!("Tun device error {}", e);
                    profiler_stop();
                    exit(ExitCode::TUNDeviceError as i32);
                }
                Ok(TunEvent::Up(mtu)) => {
                    config_sender
                        .send(ConfigMessage::TunUp(mtu))
                        .expect("channel is open while this loop is running");
                }
                Ok(TunEvent::Down) => {
                    config_sender
                        .send(ConfigMessage::TunDown)
                        .expect("channel is open while this loop is running");
                }
            }
        }
    })
}

fn spawn_uapi_server<'scope, 'env>(
    thread_scope: &'scope thread::Scope<'scope, 'env>,
    tun_reader_jobs_running: &'env AtomicBool,
    uapi: &'env <plt::UAPI as PlatformUAPI>::Bind,
    config_sender: mpsc::Sender<ConfigMessage>,
) -> ScopedJoinHandle<'scope, ()> {
    thread_scope.spawn(|| {
        let uapi_stream_sender = config_sender;

        while tun_reader_jobs_running.load(Ordering::Acquire) {
            // accept and handle UAPI config connections
            match uapi.connect() {
                Ok(stream) => {
                    let uapi_stream_sender = uapi_stream_sender.clone();

                    thread_scope.spawn(|| {
                        let mut stream = stream;
                        let uapi_stream_sender = uapi_stream_sender;

                        while tun_reader_jobs_running.load(Ordering::Acquire) {
                            let result = uapi::parse_config_operation(&mut stream).and_then(
                                |config_operation| {
                                    let (sender, receiver) = mpsc::channel();

                                    uapi_stream_sender
                                        .send(ConfigMessage::UapiConfigOperation(
                                            config_operation,
                                            sender,
                                        ))
                                        .expect("channel is open while this loop is running");

                                    receiver
                                        .recv()
                                        .expect("channel is open while this loop is running")
                                },
                            );

                            let mut errno = 0;

                            let mut response = match result {
                                Ok(response) => response,
                                Err(err) => {
                                    log::error!("Error while parsing config operation: {err}");

                                    errno = err.errno();

                                    String::new()
                                }
                            };

                            response.push_str(&format!("errno={errno}\n\n"));

                            if let Err(err) = stream.write(response.as_bytes()) {
                                log::error!("Error while writing to Unix socket: {err}");
                            }
                        }
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

fn spawn_config_worker<'scope, 'env, T: Tun, B: PlatformUDP>(
    thread_scope: &'scope thread::Scope<'scope, 'env>,
    wireguard_device: &'env WireGuard<T, B>,
    config_receiver: mpsc::Receiver<ConfigMessage>,
) -> ScopedJoinHandle<'scope, ()> {
    thread_scope.spawn(|| {
        let mut wireguard_config = WireGuardConfig::new(wireguard_device.clone());
        let config_receiver = config_receiver;

        while let Ok(message) = config_receiver.recv() {
            match message {
                ConfigMessage::UapiConfigOperation(config_operation, sender) => {
                    sender
                        .send(uapi::handle_config_operation(
                            config_operation,
                            &mut wireguard_config,
                        ))
                        .expect("channel is open until result is received");
                }
                ConfigMessage::TunUp(mtu) => {
                    log::info!("Tun up (mtu = {})", mtu);
                    let _ = wireguard_config.up(mtu); // TODO: handle
                }
                ConfigMessage::TunDown => {
                    log::info!("Tun down");
                    wireguard_config.down();
                }
            }
        }
    })
}
