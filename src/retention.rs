//! retention.

use std::time::Duration;

// ---------------------------------------------------------------------------
// RetentionPolicy
// ---------------------------------------------------------------------------

/// Policy controlling how long audit events are retained.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Maximum age of events. Events older than this are eligible for purge.
    pub max_age: Option<Duration>,
    /// Maximum number of events to keep. Oldest are purged first.
    pub max_count: Option<usize>,
}

impl RetentionPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_age: None,
            max_count: None,
        }
    }

    #[must_use]
    pub const fn with_max_age(mut self, age: Duration) -> Self {
        self.max_age = Some(age);
        self
    }

    #[must_use]
    pub const fn with_max_count(mut self, count: usize) -> Self {
        self.max_count = Some(count);
        self
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self::new()
    }
}
