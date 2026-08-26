use std::time::SystemTime;

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    now: SystemTime,
}

impl FixedClock {
    pub fn new(now: SystemTime) -> Self {
        Self { now }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.now
    }
}
