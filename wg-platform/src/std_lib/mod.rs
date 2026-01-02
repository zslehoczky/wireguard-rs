pub mod udp;
pub mod udp_endpoint;
pub mod udp_reader;
pub mod udp_socket_pair;
pub mod udp_writer;

use std::io;

fn get_connection_aborted_err() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "UDP socket closed")
}
