use byteorder::{ByteOrder, LittleEndian};
use log::debug;

use wg_crypto::MAX_HANDSHAKE_MSG_SIZE;
use wg_traits::{
    tun::Tun,
    udp::{Reader as UdpReader, UDP},
};

use crate::router::TYPE_TRANSPORT;
use crate::wireguard::WireGuard;

use super::HandshakeJob;

pub fn udp_worker<T: Tun, B: UDP>(wg: &WireGuard<T, B>, reader: B::Reader) {
    loop {
        // create vector big enough for any message given current MTU
        let mtu = wg.get_mtu();
        let size = mtu + MAX_HANDSHAKE_MSG_SIZE;
        let mut msg: Vec<u8> = vec![0; size];

        // read UDP packet into vector
        let (size, src) = match reader.read(&mut msg) {
            Err(e) => {
                debug!("Bind reader closed with {}", e);
                return;
            }
            Ok(v) => v,
        };
        msg.truncate(size);

        // TODO: start device down
        if mtu == 0 {
            continue;
        }

        // message type de-multiplexer
        if msg.len() < std::mem::size_of::<u32>() {
            continue;
        }
        match LittleEndian::read_u32(&msg[..]) {
            TYPE_TRANSPORT => {
                debug!("{} : reader, received transport message", wg);

                // transport message
                let _ = wg.recv(src, msg).map_err(|e| {
                    debug!("Failed to handle incoming transport message: {}", e);
                });
            }
            _ => {
                debug!("{} : reader, received (possible) handshake message", wg);
                wg.increment_pending();
                wg.send_to_handshake_queue(HandshakeJob::Message(msg, src));
            }
        }
    }
}
