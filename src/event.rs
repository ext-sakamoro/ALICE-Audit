//! event.

use crate::actor::*;
use crate::severity::Severity;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/// A single audit event in the trail.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub sequence: u64,
    pub timestamp: SystemTime,
    pub severity: Severity,
    pub actor: Actor,
    pub resource: Resource,
    pub action: String,
    pub detail: String,
    pub metadata: HashMap<String, String>,
    /// Hash of this event (including the previous hash to form a chain).
    pub hash: u64,
    /// Hash of the previous event (0 for the first event).
    pub prev_hash: u64,
}

impl AuditEvent {
    /// Recompute the hash of this event for verification.
    #[must_use]
    pub fn compute_hash(&self) -> u64 {
        compute_event_hash(
            self.sequence,
            self.timestamp,
            self.severity,
            &self.actor,
            &self.resource,
            &self.action,
            &self.detail,
            &self.metadata,
            self.prev_hash,
        )
    }

    /// Check whether this event's stored hash matches the recomputed hash.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.hash == self.compute_hash()
    }
}

pub(crate) fn compute_event_hash(
    sequence: u64,
    timestamp: SystemTime,
    severity: Severity,
    actor: &Actor,
    resource: &Resource,
    action: &str,
    detail: &str,
    metadata: &HashMap<String, String>,
    prev_hash: u64,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    sequence.hash(&mut hasher);
    timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    severity.hash(&mut hasher);
    actor.id.hash(&mut hasher);
    actor.name.hash(&mut hasher);
    actor.role.hash(&mut hasher);
    resource.kind.hash(&mut hasher);
    resource.id.hash(&mut hasher);
    resource.name.hash(&mut hasher);
    action.hash(&mut hasher);
    detail.hash(&mut hasher);
    // Sort metadata keys for deterministic hashing
    let mut keys: Vec<&String> = metadata.keys().collect();
    keys.sort();
    for k in keys {
        k.hash(&mut hasher);
        if let Some(v) = metadata.get(k) {
            v.hash(&mut hasher);
        }
    }
    prev_hash.hash(&mut hasher);
    hasher.finish()
}
