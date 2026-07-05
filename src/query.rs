//! query.

use crate::event::AuditEvent;
use crate::severity::Severity;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// QueryFilter
// ---------------------------------------------------------------------------

/// Filter criteria for querying audit events.
#[derive(Debug, Clone, Default)]
pub struct QueryFilter {
    pub start_time: Option<SystemTime>,
    pub end_time: Option<SystemTime>,
    pub actor_id: Option<String>,
    pub resource_id: Option<String>,
    pub resource_kind: Option<String>,
    pub severity: Option<Severity>,
    pub min_severity: Option<Severity>,
    pub action: Option<String>,
}

impl QueryFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_time_range(mut self, start: SystemTime, end: SystemTime) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    #[must_use]
    pub fn with_actor_id(mut self, id: &str) -> Self {
        self.actor_id = Some(id.to_owned());
        self
    }

    #[must_use]
    pub fn with_resource_id(mut self, id: &str) -> Self {
        self.resource_id = Some(id.to_owned());
        self
    }

    #[must_use]
    pub fn with_resource_kind(mut self, kind: &str) -> Self {
        self.resource_kind = Some(kind.to_owned());
        self
    }

    #[must_use]
    pub const fn with_severity(mut self, s: Severity) -> Self {
        self.severity = Some(s);
        self
    }

    #[must_use]
    pub const fn with_min_severity(mut self, s: Severity) -> Self {
        self.min_severity = Some(s);
        self
    }

    #[must_use]
    pub fn with_action(mut self, action: &str) -> Self {
        self.action = Some(action.to_owned());
        self
    }

    pub(crate) fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(start) = self.start_time {
            if event.timestamp < start {
                return false;
            }
        }
        if let Some(end) = self.end_time {
            if event.timestamp > end {
                return false;
            }
        }
        if let Some(ref id) = self.actor_id {
            if event.actor.id != *id {
                return false;
            }
        }
        if let Some(ref id) = self.resource_id {
            if event.resource.id != *id {
                return false;
            }
        }
        if let Some(ref kind) = self.resource_kind {
            if event.resource.kind != *kind {
                return false;
            }
        }
        if let Some(s) = self.severity {
            if event.severity != s {
                return false;
            }
        }
        if let Some(min) = self.min_severity {
            if event.severity < min {
                return false;
            }
        }
        if let Some(ref action) = self.action {
            if event.action != *action {
                return false;
            }
        }
        true
    }
}
