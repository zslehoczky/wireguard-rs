use core::{fmt::Debug, time::Duration};

pub trait Instant: Debug + Copy + Clone {
    fn since(&self, other: &Self) -> Duration;
}

impl Instant for std::time::Instant {
    fn since(&self, other: &Self) -> Duration {
        self.duration_since(*other)
    }
}
