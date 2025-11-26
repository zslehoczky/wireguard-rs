use std::time::Duration;

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
