use std::time::Duration;

use crossbeam_channel::Sender;

use crate::peer::{self, TimerControls, TimerStopControl};

use super::constants::{TIMERS_CAPACITY, TIMERS_SLOTS, TIMERS_TICK};

#[derive(Clone, Copy)]
pub enum TimerEvent {
    NewHandshake,
    RetransmitHandshake,
    SendKeepalive,
    SendPersistentKeepalive,
    ZeroKeyMaterial,
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
    new_handshake: Timer,
    retransmit_handshake: Timer,
    send_keepalive: Timer,
    send_persistent_keepalive: Timer,
    zero_key_material: Timer,
}

impl PeerTimers {
    fn new(runner: &hjul::Runner, timer_event_sender: Sender<TimerEvent>) -> Self {
        let spawn_timer = |timer_event: TimerEvent| {
            let timer_event_sender = timer_event_sender.clone();
            runner.timer(move || {
                let _ = timer_event_sender.send(timer_event);
            })
        };

        Self {
            new_handshake: Timer::new(spawn_timer(TimerEvent::NewHandshake)),
            retransmit_handshake: Timer::new(spawn_timer(TimerEvent::RetransmitHandshake)),
            send_keepalive: Timer::new(spawn_timer(TimerEvent::SendKeepalive)),
            send_persistent_keepalive: Timer::new(spawn_timer(TimerEvent::SendPersistentKeepalive)),
            zero_key_material: Timer::new(spawn_timer(TimerEvent::ZeroKeyMaterial)),
        }
    }
}

impl peer::TimerStopControl for PeerTimers {
    fn stop(&self) {
        self.new_handshake.stop();
        self.retransmit_handshake.stop();
        self.send_keepalive.stop();
        self.send_persistent_keepalive.stop();
        self.zero_key_material.stop();
    }
}

impl peer::PeerTimers for PeerTimers {
    fn all(&self) -> &dyn TimerStopControl {
        self
    }

    fn new_handshake(&self) -> &dyn TimerControls {
        &self.new_handshake
    }

    fn retransmit_handshake(&self) -> &dyn TimerControls {
        &self.retransmit_handshake
    }

    fn send_keepalive(&self) -> &dyn TimerControls {
        &self.send_keepalive
    }

    fn send_persistent_keepalive(&self) -> &dyn TimerControls {
        &self.send_persistent_keepalive
    }

    fn zero_key_material(&self) -> &dyn TimerControls {
        &self.zero_key_material
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

    pub fn create_peer_timers(&self, timer_event_sender: Sender<TimerEvent>) -> PeerTimers {
        PeerTimers::new(&self.runner, timer_event_sender)
    }
}
