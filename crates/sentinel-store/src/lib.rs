#![forbid(unsafe_code)]

mod store;

pub use store::{NotificationAttemptOutcome, StateStore, StoreError, canonical_state_schema};
