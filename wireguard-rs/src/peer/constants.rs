use std::time::Duration;

pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub const MAX_TIMER_HANDSHAKES: usize =
    (REKEY_ATTEMPT_TIME.as_secs() / REKEY_TIMEOUT.as_secs()) as usize;

// Semantics:
// Longest possible duration of any WireGuard timer
pub const TIMER_MAX_DURATION: Duration = Duration::from_secs(200);

// Semantics:
// Resolution of the timer-wheel
pub const TIMERS_TICK: Duration = Duration::from_millis(100);

// Semantics:
// Resulting number of slots in the wheel
pub const TIMERS_SLOTS: usize = (TIMER_MAX_DURATION.as_micros() / TIMERS_TICK.as_micros()) as usize;

// Performance:
// Initial capacity of timer-wheel (grows to accommodate more timers).
pub const TIMERS_CAPACITY: usize = 16;

/* A long duration (compared to the WireGuard time constants),
 * used in places to avoid Option<Instant> by instead using a long "expired" Instant:
 * (Instant::now() - TIME_HORIZON)
 *
 * Note, this duration need not fit inside the timer wheel.
 */
pub const TIME_HORIZON: Duration = Duration::from_secs(TIMER_MAX_DURATION.as_secs() * 2);
