use std::time::{Instant, SystemTime};

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;

    fn monotonic_now(&self) -> Instant;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    now: SystemTime,
    monotonic_now: Instant,
}

impl FixedClock {
    pub fn new(now: SystemTime) -> Self {
        Self::from_parts(now, Instant::now())
    }

    pub fn from_parts(now: SystemTime, monotonic_now: Instant) -> Self {
        Self { now, monotonic_now }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.now
    }

    fn monotonic_now(&self) -> Instant {
        self.monotonic_now
    }
}
