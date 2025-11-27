use std::sync::{Arc, Weak};
use std::time::Duration;

use spin::RwLock;

use super::constants::{TIMERS_CAPACITY, TIMERS_SLOTS, TIMERS_TICK};
use super::peer::{self, TimerControls, TimerStopControl};

pub trait TimerCallbacks: Send + Sync {
    fn retransmit_handshake(&self);
    fn send_keepalive(&self);
    fn new_handshake(&self);
    fn zero_key_material(&self);
    fn send_persistent_keepalive(&self);
}

fn retransmit_handshake(timer_callbacks: &dyn TimerCallbacks) {
    timer_callbacks.retransmit_handshake();
}

fn send_keepalive(timer_callbacks: &dyn TimerCallbacks) {
    timer_callbacks.send_keepalive();
}

fn new_handshake(timer_callbacks: &dyn TimerCallbacks) {
    timer_callbacks.new_handshake();
}

fn zero_key_material(timer_callbacks: &dyn TimerCallbacks) {
    timer_callbacks.zero_key_material();
}

fn send_persistent_keepalive(timer_callbacks: &dyn TimerCallbacks) {
    timer_callbacks.send_persistent_keepalive();
}

struct Timer {
    wrapped: hjul::Timer,
}

impl Timer {
    fn new(timer: hjul::Timer) -> Self {
        Self { wrapped: timer }
    }
}

impl peer::TimerStopControl for Timer {
    fn stop(&self) {
        self.wrapped.stop()
    }
}

impl peer::TimerControls for Timer {
    fn start(&self, duration: Duration) -> bool {
        self.wrapped.start(duration)
    }

    fn reset(&self, duration: Duration) {
        self.wrapped.reset(duration)
    }
}

pub struct PeerTimers {
    timer_callbacks: Arc<RwLock<Option<Weak<dyn TimerCallbacks>>>>,

    retransmit_handshake: Timer,
    send_keepalive: Timer,
    send_persistent_keepalive: Timer,
    zero_key_material: Timer,
    new_handshake: Timer,
}

impl PeerTimers {
    fn new(runner: &hjul::Runner) -> Self {
        let timer_callbacks: Arc<RwLock<Option<Weak<dyn TimerCallbacks>>>> =
            Arc::new(RwLock::new(None));

        let spawn_timer = |callback: fn(&dyn TimerCallbacks)| {
            let timer_callbacks = timer_callbacks.clone();
            runner.timer(move || {
                if let Some(timer_callbacks) = timer_callbacks
                    .read()
                    .as_ref()
                    .and_then(Weak::<dyn TimerCallbacks>::upgrade)
                {
                    callback(timer_callbacks.as_ref());
                }
            })
        };

        Self {
            timer_callbacks: timer_callbacks.clone(),

            retransmit_handshake: Timer::new(spawn_timer(retransmit_handshake)),
            send_keepalive: Timer::new(spawn_timer(send_keepalive)),
            send_persistent_keepalive: Timer::new(spawn_timer(send_persistent_keepalive)),
            zero_key_material: Timer::new(spawn_timer(zero_key_material)),
            new_handshake: Timer::new(spawn_timer(new_handshake)),
        }
    }
}

impl peer::TimerStopControl for PeerTimers {
    fn stop(&self) {
        self.retransmit_handshake.stop();
        self.send_keepalive.stop();
        self.send_persistent_keepalive.stop();
        self.zero_key_material.stop();
        self.new_handshake.stop();
    }
}

impl peer::PeerTimers for PeerTimers {
    fn set_timer_callbacks(&self, timer_callbacks: Arc<dyn TimerCallbacks>) {
        *self.timer_callbacks.write() = Some(Arc::downgrade(&timer_callbacks));
    }

    fn all(&self) -> &dyn TimerStopControl {
        self
    }

    fn retransmit_handshake(&self) -> &dyn TimerControls {
        &self.retransmit_handshake
    }

    fn send_keepalive(&self) -> &dyn TimerControls {
        &self.send_keepalive
    }

    fn new_handshake(&self) -> &dyn TimerControls {
        &self.new_handshake
    }

    fn zero_key_material(&self) -> &dyn TimerControls {
        &self.zero_key_material
    }

    fn send_persistent_keepalive(&self) -> &dyn TimerControls {
        &self.send_persistent_keepalive
    }
}

pub struct Timers {
    runner: hjul::Runner,
}

impl Timers {
    pub fn new() -> Self {
        Self {
            runner: hjul::Runner::new(TIMERS_TICK, TIMERS_SLOTS, TIMERS_CAPACITY),
        }
    }

    pub fn create_peer_timers(&self) -> PeerTimers {
        PeerTimers::new(&self.runner)
    }
}
