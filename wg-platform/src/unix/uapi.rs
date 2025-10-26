use std::fs;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};

use wg_traits::uapi::{BindUAPI, PlatformUAPI};

const SOCK_DIR: &str = "/var/run/wireguard/";

pub struct UnixUAPI {}

pub struct UnixUAPIBind {
    listener: UnixListener,
}

impl BindUAPI for UnixUAPIBind {
    type Stream = UnixStream;
    type Error = io::Error;

    fn connect(&self) -> Result<Self::Stream, Self::Error> {
        self.listener.accept().map(|(stream, _)| stream)
    }
}

impl PlatformUAPI for UnixUAPI {
    type Error = io::Error;
    type Bind = UnixUAPIBind;

    fn bind(name: &str) -> Result<Self::Bind, Self::Error> {
        let socket_path = format!("{}{}.sock", SOCK_DIR, name);
        fs::create_dir_all(SOCK_DIR)?;
        let _ = fs::remove_file(&socket_path);
        let listener = UnixListener::bind(socket_path)?;
        Ok(UnixUAPIBind { listener })
    }
}
