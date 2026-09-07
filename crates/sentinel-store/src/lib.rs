#![forbid(unsafe_code)]

mod store;

pub use store::{
    NotificationAttempt, NotificationAttemptOutcome, StateStore, StoreError, canonical_state_schema,
};
