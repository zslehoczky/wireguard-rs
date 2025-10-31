use std::io::{BufReader, BufWriter};
use std::process::exit;
use std::thread::{self, JoinHandle, ScopedJoinHandle};

use wg_platform as plt;
use wg_traits::{
    Configuration,
    tun::Tun,
    uapi::{BindUAPI, PlatformUAPI},
    udp::PlatformUDP,
};
use wg_uapi::uapi::{
    ConfigError, ConfigOperation, ReadNonEmptyLinesResult, handle_config_operation,
    parse_config_operation, read_non_empty_lines, write_config_response,
};

use crate::configuration::WireGuardConfig;
use crate::run::{error::ExitCode, profiler::profiler_stop};
use crate::wireguard::WireGuard;

pub enum ConfigMessage {
    UapiConfigOperation(
        ConfigOperation,
        crossbeam_channel::Sender<Result<String, ConfigError>>,
    ),
    TunUp(usize),
    TunDown,
}

pub fn spawn_config_worker<'scope, 'env, T: Tun, B: PlatformUDP>(
    thread_scope: &'scope thread::Scope<'scope, 'env>,
    wireguard_device: &'env WireGuard<T, B>,
    config_receiver: crossbeam_channel::Receiver<ConfigMessage>,
) -> ScopedJoinHandle<'scope, ()> {
    thread_scope.spawn(|| {
        config_worker(wireguard_device, config_receiver);
    })
}

pub fn spawn_uapi_server(
    uapi: <plt::UAPI as PlatformUAPI>::Bind,
    config_sender: crossbeam_channel::Sender<ConfigMessage>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        uapi_server(uapi, config_sender);
    })
}

fn config_worker<T: Tun, B: PlatformUDP>(
    wireguard_device: &WireGuard<T, B>,
    config_receiver: crossbeam_channel::Receiver<ConfigMessage>,
) {
    let mut wireguard_config = WireGuardConfig::new(wireguard_device);

    while let Ok(message) = config_receiver.recv() {
        match message {
            ConfigMessage::UapiConfigOperation(config_operation, sender) => {
                sender
                    .send(handle_config_operation(
                        config_operation,
                        &mut wireguard_config,
                    ))
                    .expect("channel is open until result is received");
            }
            ConfigMessage::TunUp(mtu) => {
                log::info!("Tun up (mtu = {})", mtu);
                if let Err(err) = wireguard_config.up(mtu) {
                    log::error!("Error during TUN setup: {err}");
                }
            }
            ConfigMessage::TunDown => {
                log::info!("Tun down");
                wireguard_config.down();
            }
        }
    }
}

fn uapi_server(
    uapi: <plt::UAPI as PlatformUAPI>::Bind,
    config_sender: crossbeam_channel::Sender<ConfigMessage>,
) {
    loop {
        // accept and handle UAPI config connections
        match uapi.connect() {
            Ok(stream) => {
                let config_sender = config_sender.clone();

                thread::spawn(move || {
                    uapi_config_message_handler(config_sender, stream);
                });
            }
            Err(err) => {
                log::error!("UAPI connection error: {}", err);
                profiler_stop();
                exit(ExitCode::UAPIConnectionError as i32);
            }
        }
    }
}

fn uapi_config_message_handler(
    config_sender: crossbeam_channel::Sender<ConfigMessage>,
    mut stream: <<plt::UAPI as PlatformUAPI>::Bind as BindUAPI>::Stream,
) {
    let mut reader = BufReader::new(&mut stream);
    let mut string_buffer = String::new();

    loop {
        let lines_result = match read_non_empty_lines(&mut reader, &mut string_buffer) {
            ReadNonEmptyLinesResult::StreamOpen(val) => val,
            ReadNonEmptyLinesResult::StreamClosed => {
                return;
            }
        };

        let response = lines_result
            .and_then(parse_config_operation)
            .and_then(|config_operation| {
                let (config_result_sender, config_result_receiver) = crossbeam_channel::unbounded();

                config_sender
                    .send(ConfigMessage::UapiConfigOperation(
                        config_operation,
                        config_result_sender,
                    ))
                    .expect("channel should be open while this loop is running");

                config_result_receiver
                    .recv()
                    .expect("channel should be open until result is received")
            });

        let mut writer = BufWriter::new(reader.get_mut());

        if let Err(err) = write_config_response(&mut writer, response) {
            log::error!("Error while writing to Unix socket: {err}");
        }
    }
}
