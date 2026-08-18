use jiff::Timestamp;

pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    timestamp: Timestamp,
}

impl FixedClock {
    pub fn new(timestamp: Timestamp) -> Self {
        Self { timestamp }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.timestamp
    }
}
