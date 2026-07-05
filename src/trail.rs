//! trail.

use crate::actor::*;
use crate::event::compute_event_hash;
use crate::event::AuditEvent;
use crate::query::QueryFilter;
use crate::report::ComplianceReport;
use crate::retention::RetentionPolicy;
use crate::severity::Severity;
use std::collections::HashMap;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// AuditTrail
// ---------------------------------------------------------------------------

/// The main audit trail containing all events with hash-chain integrity.
#[derive(Debug)]
pub struct AuditTrail {
    pub(crate) events: Vec<AuditEvent>,
    next_sequence: u64,
    retention: RetentionPolicy,
}

impl AuditTrail {
    /// Create a new empty audit trail.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: Vec::new(),
            next_sequence: 1,
            retention: RetentionPolicy::new(),
        }
    }

    /// Create an audit trail with a retention policy.
    #[must_use]
    pub const fn with_retention(policy: RetentionPolicy) -> Self {
        Self {
            events: Vec::new(),
            next_sequence: 1,
            retention: policy,
        }
    }

    /// Set the retention policy.
    pub const fn set_retention(&mut self, policy: RetentionPolicy) {
        self.retention = policy;
    }

    /// Get the current retention policy.
    #[must_use]
    pub const fn retention(&self) -> &RetentionPolicy {
        &self.retention
    }

    /// Log a new audit event. Returns the sequence number of the event.
    pub fn log_event(
        &mut self,
        severity: Severity,
        actor: Actor,
        resource: Resource,
        action: &str,
        detail: &str,
        metadata: HashMap<String, String>,
    ) -> u64 {
        self.log_event_at(
            severity,
            actor,
            resource,
            action,
            detail,
            metadata,
            SystemTime::now(),
        )
    }

    /// Log a new audit event with a specific timestamp.
    pub fn log_event_at(
        &mut self,
        severity: Severity,
        actor: Actor,
        resource: Resource,
        action: &str,
        detail: &str,
        metadata: HashMap<String, String>,
        timestamp: SystemTime,
    ) -> u64 {
        let seq = self.next_sequence;
        let prev_hash = self.events.last().map_or(0, |e| e.hash);

        let hash = compute_event_hash(
            seq, timestamp, severity, &actor, &resource, action, detail, &metadata, prev_hash,
        );

        self.events.push(AuditEvent {
            sequence: seq,
            timestamp,
            severity,
            actor,
            resource,
            action: action.to_owned(),
            detail: detail.to_owned(),
            metadata,
            hash,
            prev_hash,
        });

        self.next_sequence += 1;
        seq
    }

    /// Convenience method to log an info event.
    pub fn log_info(
        &mut self,
        actor: Actor,
        resource: Resource,
        action: &str,
        detail: &str,
    ) -> u64 {
        self.log_event(
            Severity::Info,
            actor,
            resource,
            action,
            detail,
            HashMap::new(),
        )
    }

    /// Convenience method to log a warning event.
    pub fn log_warning(
        &mut self,
        actor: Actor,
        resource: Resource,
        action: &str,
        detail: &str,
    ) -> u64 {
        self.log_event(
            Severity::Warning,
            actor,
            resource,
            action,
            detail,
            HashMap::new(),
        )
    }

    /// Convenience method to log an error event.
    pub fn log_error(
        &mut self,
        actor: Actor,
        resource: Resource,
        action: &str,
        detail: &str,
    ) -> u64 {
        self.log_event(
            Severity::Error,
            actor,
            resource,
            action,
            detail,
            HashMap::new(),
        )
    }

    /// Convenience method to log a critical event.
    pub fn log_critical(
        &mut self,
        actor: Actor,
        resource: Resource,
        action: &str,
        detail: &str,
    ) -> u64 {
        self.log_event(
            Severity::Critical,
            actor,
            resource,
            action,
            detail,
            HashMap::new(),
        )
    }

    /// Return the number of events in the trail.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Check whether the trail is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get all events as a slice.
    #[must_use]
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Get an event by sequence number.
    #[must_use]
    pub fn get_by_sequence(&self, seq: u64) -> Option<&AuditEvent> {
        self.events.iter().find(|e| e.sequence == seq)
    }

    /// Verify the entire hash chain. Returns `true` if the chain is valid.
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        let mut prev_hash: u64 = 0;
        for event in &self.events {
            if event.prev_hash != prev_hash {
                return false;
            }
            if !event.verify() {
                return false;
            }
            prev_hash = event.hash;
        }
        true
    }

    /// Detect tampered events. Returns indices of events whose hash is invalid.
    #[must_use]
    pub fn detect_tampering(&self) -> Vec<usize> {
        let mut tampered = Vec::new();
        let mut prev_hash: u64 = 0;
        for (i, event) in self.events.iter().enumerate() {
            if event.prev_hash != prev_hash || !event.verify() {
                tampered.push(i);
            }
            prev_hash = event.hash;
        }
        tampered
    }

    /// Query events using a filter.
    #[must_use]
    pub fn query(&self, filter: &QueryFilter) -> Vec<&AuditEvent> {
        self.events.iter().filter(|e| filter.matches(e)).collect()
    }

    /// Get events for a specific actor.
    #[must_use]
    pub fn events_by_actor(&self, actor_id: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.actor.id == actor_id)
            .collect()
    }

    /// Get events for a specific resource.
    #[must_use]
    pub fn events_by_resource(&self, resource_id: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.resource.id == resource_id)
            .collect()
    }

    /// Get events by severity level.
    #[must_use]
    pub fn events_by_severity(&self, severity: Severity) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == severity)
            .collect()
    }

    /// Get events at or above a minimum severity.
    #[must_use]
    pub fn events_at_or_above(&self, min_severity: Severity) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.severity >= min_severity)
            .collect()
    }

    /// Get all unique actor IDs.
    #[must_use]
    pub fn unique_actors(&self) -> Vec<String> {
        let mut seen = Vec::new();
        for event in &self.events {
            if !seen.contains(&event.actor.id) {
                seen.push(event.actor.id.clone());
            }
        }
        seen
    }

    /// Get all unique resource IDs.
    #[must_use]
    pub fn unique_resources(&self) -> Vec<String> {
        let mut seen = Vec::new();
        for event in &self.events {
            if !seen.contains(&event.resource.id) {
                seen.push(event.resource.id.clone());
            }
        }
        seen
    }

    /// Get all unique actions.
    #[must_use]
    pub fn unique_actions(&self) -> Vec<String> {
        let mut seen = Vec::new();
        for event in &self.events {
            if !seen.contains(&event.action) {
                seen.push(event.action.clone());
            }
        }
        seen
    }

    /// Apply the retention policy, removing expired events.
    /// Returns the number of events removed.
    pub fn apply_retention(&mut self) -> usize {
        let now = SystemTime::now();
        let original_len = self.events.len();

        // Apply max_age
        if let Some(max_age) = self.retention.max_age {
            self.events.retain(|e| {
                now.duration_since(e.timestamp)
                    .map_or(true, |age| age <= max_age)
            });
        }

        // Apply max_count
        if let Some(max_count) = self.retention.max_count {
            if self.events.len() > max_count {
                let drain_count = self.events.len() - max_count;
                self.events.drain(..drain_count);
            }
        }

        original_len - self.events.len()
    }

    /// Apply retention based on a specific reference time (for testing).
    pub fn apply_retention_at(&mut self, now: SystemTime) -> usize {
        let original_len = self.events.len();

        if let Some(max_age) = self.retention.max_age {
            self.events.retain(|e| {
                now.duration_since(e.timestamp)
                    .map_or(true, |age| age <= max_age)
            });
        }

        if let Some(max_count) = self.retention.max_count {
            if self.events.len() > max_count {
                let drain_count = self.events.len() - max_count;
                self.events.drain(..drain_count);
            }
        }

        original_len - self.events.len()
    }

    /// Generate a compliance report.
    #[must_use]
    pub fn compliance_report(&self) -> ComplianceReport {
        let mut by_severity = HashMap::new();
        let mut by_actor = HashMap::new();
        let mut by_resource_kind = HashMap::new();
        let mut by_action = HashMap::new();
        let mut critical = 0usize;
        let mut errors = 0usize;
        let mut earliest: Option<SystemTime> = None;
        let mut latest: Option<SystemTime> = None;

        for event in &self.events {
            *by_severity.entry(event.severity.to_string()).or_insert(0) += 1;
            *by_actor.entry(event.actor.id.clone()).or_insert(0) += 1;
            *by_resource_kind
                .entry(event.resource.kind.clone())
                .or_insert(0) += 1;
            *by_action.entry(event.action.clone()).or_insert(0) += 1;

            if event.severity == Severity::Critical {
                critical += 1;
            }
            if event.severity == Severity::Error {
                errors += 1;
            }

            match earliest {
                None => earliest = Some(event.timestamp),
                Some(e) if event.timestamp < e => earliest = Some(event.timestamp),
                _ => {}
            }
            match latest {
                None => latest = Some(event.timestamp),
                Some(l) if event.timestamp > l => latest = Some(event.timestamp),
                _ => {}
            }
        }

        ComplianceReport {
            total_events: self.events.len(),
            events_by_severity: by_severity,
            events_by_actor: by_actor,
            events_by_resource_kind: by_resource_kind,
            events_by_action: by_action,
            chain_valid: self.verify_chain(),
            earliest_event: earliest,
            latest_event: latest,
            critical_events: critical,
            error_events: errors,
        }
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
        self.next_sequence = 1;
    }
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}
