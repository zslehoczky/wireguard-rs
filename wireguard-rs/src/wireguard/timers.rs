use std::time::Duration;

use crossbeam_channel::Sender;

use crate::peer::{self, TimerControls, TimerStopControl};

use super::constants::{TIMERS_CAPACITY, TIMERS_SLOTS, TIMERS_TICK};

pub enum TimerEvent {
    NewHandshake,
    RetransmitHandshake,
    SendKeepalive,
    SendPersistentKeepalive,
    ZeroKeyMaterial,
}

fn new_handshake(
    timer_event_sender: &Sender<TimerEvent>,
) -> Result<(), crossbeam_channel::SendError<TimerEvent>> {
    timer_event_sender.send(TimerEvent::NewHandshake)
}

fn retransmit_handshake(
    timer_event_sender: &Sender<TimerEvent>,
) -> Result<(), crossbeam_channel::SendError<TimerEvent>> {
    timer_event_sender.send(TimerEvent::RetransmitHandshake)
}

fn send_keepalive(
    timer_event_sender: &Sender<TimerEvent>,
) -> Result<(), crossbeam_channel::SendError<TimerEvent>> {
    timer_event_sender.send(TimerEvent::SendKeepalive)
}

fn send_persistent_keepalive(
    timer_event_sender: &Sender<TimerEvent>,
) -> Result<(), crossbeam_channel::SendError<TimerEvent>> {
    timer_event_sender.send(TimerEvent::SendPersistentKeepalive)
}

fn zero_key_material(
    timer_event_sender: &Sender<TimerEvent>,
) -> Result<(), crossbeam_channel::SendError<TimerEvent>> {
    timer_event_sender.send(TimerEvent::ZeroKeyMaterial)
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
    retransmit_handshake: Timer,
    send_keepalive: Timer,
    send_persistent_keepalive: Timer,
    zero_key_material: Timer,
    new_handshake: Timer,
}

impl PeerTimers {
    fn new(runner: &hjul::Runner, timer_event_sender: Sender<TimerEvent>) -> Self {
        let spawn_timer = |callback: fn(
            &Sender<TimerEvent>,
        )
            -> Result<(), crossbeam_channel::SendError<TimerEvent>>| {
            let timer_event_sender = timer_event_sender.clone();
            runner.timer(move || {
                let _ = callback(&timer_event_sender);
            })
        };

        Self {
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

    pub fn create_peer_timers(&self, timer_event_sender: Sender<TimerEvent>) -> PeerTimers {
        PeerTimers::new(&self.runner, timer_event_sender)
    }
}
