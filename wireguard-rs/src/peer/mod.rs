pub mod constants;
mod peer_state;

use std::sync::Arc;
use std::time::Duration;

use crate::wireguard::TimerCallbacks;

pub use peer_state::PeerState;

pub trait TimerStopControl {
    fn stop(&self);
}

pub trait TimerControls: TimerStopControl {
    fn start(&self, duration: Duration) -> bool;
    fn reset(&self, duration: Duration);
}

pub trait PeerTimers: Send + Sync {
    fn set_timer_callbacks(&self, timer_callbacks: Arc<dyn TimerCallbacks>);

    fn all(&self) -> &dyn TimerStopControl;

    fn retransmit_handshake(&self) -> &dyn TimerControls;
    fn send_keepalive(&self) -> &dyn TimerControls;
    fn new_handshake(&self) -> &dyn TimerControls;
    fn zero_key_material(&self) -> &dyn TimerControls;
    fn send_persistent_keepalive(&self) -> &dyn TimerControls;
}
