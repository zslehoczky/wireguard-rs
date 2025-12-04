use std::time::Duration;

use byteorder::{ByteOrder, LittleEndian};
use crossbeam_channel::Receiver;
use log::debug;

use wg_traits::{tun::Tun, udp::UDP};

use crate::router::TYPE_TRANSPORT;
use crate::wireguard::WireGuard;

use super::HandshakeJob;

type Received<E> = (Vec<u8>, usize, E);

pub fn udp_worker<T: Tun, B: UDP>(
    wireguard_device: &WireGuard<T, B>,
    reader: Receiver<Received<B::Endpoint>>,
) {
    while wireguard_device.is_enabled() {
        // read UDP packet into vector
        let (mut msg, size, src) = match reader.recv_timeout(Duration::from_millis(100)) {
            Ok(v) => v,
            Err(_) => {
                continue;
            }
        };
        msg.truncate(size);

        // message type de-multiplexer
        if msg.len() < std::mem::size_of::<u32>() {
            continue;
        }
        match LittleEndian::read_u32(&msg[..]) {
            TYPE_TRANSPORT => {
                debug!("{} : reader, received transport message", wireguard_device);

                // transport message
                let _ = wireguard_device.recv(src, msg).map_err(|e| {
                    debug!("Failed to handle incoming transport message: {}", e);
                });
            }
            _ => {
                debug!(
                    "{} : reader, received (possible) handshake message",
                    wireguard_device
                );
                wireguard_device.send_to_handshake_queue(HandshakeJob::Message(msg, src));
            }
        }
    }
}
