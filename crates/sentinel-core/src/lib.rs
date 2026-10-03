#![forbid(unsafe_code)]

pub mod analysis;
pub mod clock;
pub mod config;
pub mod hex;
pub mod model;

pub use analysis::{
    AggregateEvaluation, RateWindow, UPSTREAM_HISTORY_SECONDS, advance_condition,
    evaluate_aggregate, evaluate_target, evaluate_target_behavior, evaluate_target_failure,
    evaluate_upstream_latency, local_time_bucket, robust_bounds,
};
pub use clock::{Clock, FixedClock, SystemClock};
pub use config::{
    ConditionProfile, Config, ConfigError, NotificationProvider, PolicyConfig, TargetAuth,
    TargetConfig,
};
pub use model::*;
