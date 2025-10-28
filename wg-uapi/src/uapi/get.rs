use x25519_dalek::{PublicKey, StaticSecret};

use wg_traits::Configuration;

use super::{PeerState, error::ConfigError};

pub fn serialize<C: Configuration<ConfigError, PeerState, PublicKey, StaticSecret>>(
    config: &C,
) -> String {
    let mut result_pieces = Vec::new();

    let mut write = |key: &'static str, value: String| {
        debug_assert!(value.is_ascii());
        debug_assert!(key.is_ascii());

        log::trace!("UAPI: return : {}={}", key, value);

        result_pieces.push(format!("{key}={value}\n"));
    };

    // serialize interface
    if let Some(sk) = config.get_private_key() {
        write("private_key", hex::encode(sk.to_bytes()))
    }

    if let Some(port) = config.get_listen_port() {
        write("listen_port", port.to_string())
    }

    if let Some(fwmark) = config.get_fwmark() {
        write("fwmark", fwmark.to_string())
    }

    // serialize all peers
    let mut peers = config.get_peers();
    while let Some(p) = peers.pop() {
        write("public_key", hex::encode(p.public_key.as_bytes()));
        write("preshared_key", hex::encode(p.preshared_key));
        write("rx_bytes", p.rx_bytes.to_string());
        write("tx_bytes", p.tx_bytes.to_string());
        write(
            "persistent_keepalive_interval",
            p.persistent_keepalive_interval.to_string(),
        );

        if let Some((secs, nsecs)) = p.last_handshake_time {
            write("last_handshake_time_sec", secs.to_string());
            write("last_handshake_time_nsec", nsecs.to_string());
        }

        if let Some(endpoint) = p.endpoint {
            write("endpoint", endpoint.to_string());
        }

        for (ip, cidr) in p.allowed_ips {
            write("allowed_ip", ip.to_string() + "/" + &cidr.to_string());
        }
    }

    result_pieces.join("")
}
