use std::{
    io,
    os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Arc,
};

#[derive(Clone)]
pub(super) struct Fd {
    fd: Arc<OwnedFd>,
}

impl Fd {
    pub fn new(fd: RawFd) -> Self {
        Self {
            fd: Arc::new(unsafe { OwnedFd::from_raw_fd(fd) }),
        }
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let bytes_read = unsafe { libc::write(self.fd.as_raw_fd(), buf.as_ptr() as _, buf.len()) };
        if bytes_read < 0 {
            return Err(io::Error::from_raw_os_error(-bytes_read as i32));
        }
        Ok(bytes_read as usize)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_written =
            unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as _, buf.len()) };
        if bytes_written < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes_written as usize)
    }
}
