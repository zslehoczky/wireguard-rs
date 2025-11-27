use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crate::wireguard::TimerCallbacks;

use super::PeerTimers;
use super::constants::{KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_TIMEOUT};

// only updated during configuration
pub struct TimerState {
    timers: Box<dyn PeerTimers>,

    enabled: AtomicBool,

    keepalive_interval: AtomicU64,
    need_another_keepalive: AtomicBool,

    handshake_attempts: AtomicUsize,
    sent_lastminute_handshake: AtomicBool,
}

impl TimerState {
    pub fn new(timers: Box<dyn PeerTimers>, enabled: bool) -> TimerState {
        // create a timer instance for the provided peer
        TimerState {
            timers,

            enabled: AtomicBool::new(enabled),

            keepalive_interval: AtomicU64::new(0), // disabled
            need_another_keepalive: AtomicBool::new(false),

            handshake_attempts: AtomicUsize::new(0),
            sent_lastminute_handshake: AtomicBool::new(false),
        }
    }

    pub fn needs_another_keepalive(&self) -> bool {
        self.need_another_keepalive.swap(false, Ordering::SeqCst)
    }

    pub fn get_keepalive_interval(&self) -> u64 {
        self.keepalive_interval.load(Ordering::SeqCst)
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    fn set_enabled(&self, value: bool) {
        self.enabled.store(value, Ordering::SeqCst)
    }

    pub fn enable(&self) {
        // set flag to reenable timer events
        if self.is_enabled() {
            return;
        }

        self.set_enabled(true);

        // start send_persistent_keepalive
        if self.get_keepalive_interval() > 0 {
            self.timers
                .send_persistent_keepalive()
                .start(Duration::from_secs(0));
        }
    }

    pub fn disable(&self) {
        // set flag to prevent future timer events
        if !self.is_enabled() {
            return;
        }
        self.set_enabled(false);

        // stop all pending timers
        self.timers.all().stop();

        // reset all timer state
        self.handshake_attempts.store(0, Ordering::SeqCst);
        self.sent_lastminute_handshake
            .store(false, Ordering::SeqCst);
        self.need_another_keepalive.store(false, Ordering::SeqCst);
    }

    pub fn start_new_handshake_timer(&self) {
        if self.is_enabled() {
            self.timers
                .new_handshake()
                .start(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
        }
    }

    pub fn queue_another_keepalive(&self) {
        if self.is_enabled() && !self.timers.send_keepalive().start(KEEPALIVE_TIMEOUT) {
            self.need_another_keepalive.store(true, Ordering::SeqCst)
        }
    }

    pub fn stop_send_keepalive_timer(&self) {
        if self.is_enabled() {
            self.timers.send_keepalive().stop()
        }
    }

    pub fn stop_new_handshake_timer(&self) {
        if self.is_enabled() {
            self.timers.new_handshake().stop();
        }
    }

    pub fn restart_retransmit_handshake_timer(&self) {
        if self.is_enabled() {
            self.timers.send_keepalive().stop();
            self.timers.retransmit_handshake().reset(REKEY_TIMEOUT);
        }
    }

    /// Return Some(()) if timers are enabled, None otherwise
    pub fn stop_retransmit_handshake_timer(&self) -> Option<()> {
        if self.is_enabled() {
            self.timers.retransmit_handshake().stop();
            self.handshake_attempts.store(0, Ordering::SeqCst);
            self.sent_lastminute_handshake
                .store(false, Ordering::SeqCst);

            return Some(());
        }

        None
    }

    pub fn restart_zero_key_material_timer(&self) {
        if self.is_enabled() {
            self.timers.zero_key_material().reset(REJECT_AFTER_TIME * 3);
        }
    }

    pub fn push_persistent_keepalive_into_future(&self) {
        if self.is_enabled() && self.get_keepalive_interval() > 0 {
            self.timers
                .send_persistent_keepalive()
                .reset(Duration::from_secs(self.get_keepalive_interval()));
        }
    }

    pub fn set_persistent_keepalive_interval(&self, secs: u64) {
        // update the stored keepalive_interval
        self.keepalive_interval.store(secs, Ordering::SeqCst);

        // stop the keepalive timer with the old interval
        self.timers.send_persistent_keepalive().stop();

        // cause immediate expiry of persistent_keepalive timer
        if secs > 0 && self.is_enabled() {
            self.timers
                .send_persistent_keepalive()
                .reset(Duration::from_secs(0));
        }
    }

    pub fn reset_handshake_attempts(&self) {
        self.handshake_attempts.store(0, Ordering::SeqCst);
    }

    /// Return true if the event hasn't been registered before this call, otherwise false
    pub fn register_lastminute_handshake_sent(&self) -> bool {
        !self.sent_lastminute_handshake.swap(true, Ordering::Acquire)
    }

    pub fn increment_handshake_attempts(&self) -> usize {
        self.handshake_attempts.fetch_add(1, Ordering::SeqCst)
    }

    pub fn get_timers(&self) -> &dyn PeerTimers {
        self.timers.as_ref()
    }

    pub fn set_timer_callbacks(&self, timer_callbacks: Arc<dyn TimerCallbacks>) {
        self.timers.set_timer_callbacks(timer_callbacks);
    }
}
