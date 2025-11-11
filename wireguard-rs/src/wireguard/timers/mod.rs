mod callbacks;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use hjul::{Runner, Timer};
use x25519_dalek::PublicKey;

use wg_traits::{tun::Tun, udp::UDP};

use crate::wireguard::WireGuard;
use crate::wireguard::constants::*;

pub fn spawn_timer<F, T: Tun, B: UDP>(
    wireguard_device: WireGuard<T, B>,
    public_key_of_peer: PublicKey,
    runner: &Runner,
    callback: F,
) -> Timer
where
    F: 'static + Fn(&WireGuard<T, B>, &PublicKey) + Send + Sync,
{
    runner.timer(move || callback(&wireguard_device, &public_key_of_peer))
}

pub struct Timers {
    // only updated during configuration
    enabled: bool,
    keepalive_interval: u64,

    handshake_attempts: AtomicUsize,
    sent_lastminute_handshake: AtomicBool,
    need_another_keepalive: AtomicBool,

    retransmit_handshake: Timer,
    send_keepalive: Timer,
    send_persistent_keepalive: Timer,
    zero_key_material: Timer,
    new_handshake: Timer,
}

impl Timers {
    #[inline(always)]
    fn needs_another_keepalive(&self) -> bool {
        self.need_another_keepalive.swap(false, Ordering::SeqCst)
    }

    pub fn new<T: Tun, B: UDP>(
        wireguard_device: &WireGuard<T, B>,
        public_key_of_peer: &PublicKey,
        timers_started: bool,
    ) -> Timers {
        let runner = wireguard_device.runner.lock();

        // create a timer instance for the provided peer
        Timers {
            enabled: timers_started,
            keepalive_interval: 0, // disabled
            need_another_keepalive: AtomicBool::new(false),
            sent_lastminute_handshake: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: spawn_timer(
                wireguard_device.clone(),
                *public_key_of_peer,
                &runner,
                Self::retransmit_handshake,
            ),
            send_keepalive: spawn_timer(
                wireguard_device.clone(),
                *public_key_of_peer,
                &runner,
                Self::send_keepalive,
            ),
            new_handshake: spawn_timer(
                wireguard_device.clone(),
                *public_key_of_peer,
                &runner,
                Self::new_handshake,
            ),
            zero_key_material: spawn_timer(
                wireguard_device.clone(),
                *public_key_of_peer,
                &runner,
                Self::zero_key_material,
            ),
            send_persistent_keepalive: spawn_timer(
                wireguard_device.clone(),
                *public_key_of_peer,
                &runner,
                Self::send_persistent_keepalive,
            ),
        }
    }

    pub fn get_keepalive_interval(&self) -> u64 {
        self.keepalive_interval
    }

    pub fn enable(&mut self) {
        // set flag to reenable timer events
        if self.enabled {
            return;
        }
        self.enabled = true;

        // start send_persistent_keepalive
        if self.keepalive_interval > 0 {
            self.send_persistent_keepalive.start(Duration::from_secs(0));
        }
    }

    pub fn disable(&mut self) {
        // set flag to prevent future timer events
        if !self.enabled {
            return;
        }
        self.enabled = false;

        // stop all pending timers
        self.retransmit_handshake.stop();
        self.send_keepalive.stop();
        self.send_persistent_keepalive.stop();
        self.zero_key_material.stop();
        self.new_handshake.stop();

        // reset all timer state
        self.handshake_attempts.store(0, Ordering::SeqCst);
        self.sent_lastminute_handshake
            .store(false, Ordering::SeqCst);
        self.need_another_keepalive.store(false, Ordering::SeqCst);
    }

    pub fn start_new_handshake_timer(&self) {
        if self.enabled {
            self.new_handshake.start(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
        }
    }

    pub fn queue_another_keepalive(&self) {
        if self.enabled && !self.send_keepalive.start(KEEPALIVE_TIMEOUT) {
            self.need_another_keepalive.store(true, Ordering::SeqCst)
        }
    }

    pub fn stop_send_keepalive_timer(&self) {
        if self.enabled {
            self.send_keepalive.stop()
        }
    }

    pub fn stop_new_handshake_timer(&self) {
        if self.enabled {
            self.new_handshake.stop();
        }
    }

    pub fn restart_retransmit_handshake_timer(&self) {
        if self.enabled {
            self.send_keepalive.stop();
            self.retransmit_handshake.reset(REKEY_TIMEOUT);
        }
    }

    /// Return Some(()) if timers are enabled, None otherwise
    pub fn stop_retransmit_handshake_timer(&self) -> Option<()> {
        if self.enabled {
            self.retransmit_handshake.stop();
            self.handshake_attempts.store(0, Ordering::SeqCst);
            self.sent_lastminute_handshake
                .store(false, Ordering::SeqCst);

            return Some(());
        }

        None
    }

    pub fn restart_zero_key_material_timer(&self) {
        if self.enabled {
            self.zero_key_material.reset(REJECT_AFTER_TIME * 3);
        }
    }

    pub fn push_persistent_keepalive_into_future(&self) {
        if self.enabled && self.keepalive_interval > 0 {
            self.send_persistent_keepalive
                .reset(Duration::from_secs(self.keepalive_interval));
        }
    }

    pub fn set_persistent_keepalive_interval(&mut self, secs: u64) {
        // update the stored keepalive_interval
        self.keepalive_interval = secs;

        // stop the keepalive timer with the old interval
        self.send_persistent_keepalive.stop();

        // cause immediate expiry of persistent_keepalive timer
        if secs > 0 && self.enabled {
            self.send_persistent_keepalive.reset(Duration::from_secs(0));
        }
    }

    pub fn reset_handshake_attempts(&self) {
        self.handshake_attempts.store(0, Ordering::SeqCst);
    }

    /// Return true if the event hasn't been registered before this call, otherwise false
    pub fn register_lastminute_handshake_sent(&self) -> bool {
        !self.sent_lastminute_handshake.swap(true, Ordering::Acquire)
    }
}
