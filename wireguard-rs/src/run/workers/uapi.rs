use std::io::{BufReader, BufWriter, Write};
use std::process::exit;
use std::thread;

use wg_platform as plt;
use wg_traits::{
    Configuration,
    tun::Tun,
    uapi::{BindUAPI, PlatformUAPI},
    udp::PlatformUDP,
};
use wg_uapi::uapi::{
    ConfigError, ConfigOperation, handle_config_operation, parse_config_operation,
    write_config_response,
};

use crate::configuration::WireGuardConfig;
use crate::run::{error::ExitCode, profiler::profiler_stop};
use crate::wireguard::WireGuard;

use super::line_reader::{ReadOutcome, read_line_block};

pub enum ConfigMessage {
    UapiConfigOperation(
        ConfigOperation,
        crossbeam_channel::Sender<Result<String, ConfigError>>,
    ),
    TunUp(usize),
    TunDown,
}

pub fn config_worker<T: Tun, B: PlatformUDP>(
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

pub fn uapi_server_worker(
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

    loop {
        let request_text = match read_line_block(&mut reader) {
            Ok(ReadOutcome::Ready(val)) => val,
            Ok(ReadOutcome::Eof) => {
                return;
            }
            Err(err) => {
                log::error!("Error while reading from Unix socket: {err}. Closing socket.");

                let mut writer = BufWriter::new(reader.get_mut());

                handle_config_response(&mut writer, Err(ConfigError::IOError));

                return;
            }
        };

        let request_lines = request_text.lines().take_while(|&line| !line.is_empty());

        let response = parse_config_operation(request_lines).and_then(|config_operation| {
            let (config_result_sender, config_result_receiver) = crossbeam_channel::bounded(1);

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

        handle_config_response(&mut writer, response);
    }
}

fn handle_config_response<W: Write>(
    writer: &mut BufWriter<W>,
    response: Result<String, ConfigError>,
) {
    if let Err(err) = write_config_response(writer, response) {
        log::error!("Error while writing to Unix socket: {err}");
    }
}
