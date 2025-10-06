use crate::platform::tun::Tun;
use crate::platform::udp::UDP;

use super::wireguard::WireGuard;

use super::workers::tun_worker;

use std::thread::{self, JoinHandle};

pub struct WireGuardHandle<T: Tun, B: UDP> {
    wireguard_device: WireGuard<T, B>,

    tun_readers: Vec<JoinHandle<()>>,
}

impl<T: Tun, B: UDP> WireGuardHandle<T, B> {
    pub fn new(readers: Vec<T::Reader>, writer: T::Writer) -> WireGuardHandle<T, B> {
        let wireguard_device = WireGuard::new(writer);
        let tun_readers = Self::start_tun_reader_jobs(&wireguard_device, readers);

        WireGuardHandle {
            wireguard_device,
            tun_readers,
        }
    }

    pub fn get_device(&self) -> &WireGuard<T, B> {
        &self.wireguard_device
    }

    fn start_tun_reader_jobs(
        wireguard_device: &WireGuard<T, B>,
        readers: Vec<T::Reader>,
    ) -> Vec<JoinHandle<()>> {
        let mut result = Vec::with_capacity(readers.len());

        for reader in readers {
            result.push({
                let wireguard_device = wireguard_device.clone();

                thread::spawn(move || {
                    tun_worker(&wireguard_device, reader);
                })
            });
        }

        result
    }

    pub fn wait(self) {
        for tun_reader in self.tun_readers {
            let _ = tun_reader.join();
        }
    }
}
