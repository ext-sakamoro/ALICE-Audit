//! report.

use std::collections::HashMap;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// ComplianceReport
// ---------------------------------------------------------------------------

/// A compliance report summarising the audit trail.
#[derive(Debug, Clone)]
pub struct ComplianceReport {
    pub total_events: usize,
    pub events_by_severity: HashMap<String, usize>,
    pub events_by_actor: HashMap<String, usize>,
    pub events_by_resource_kind: HashMap<String, usize>,
    pub events_by_action: HashMap<String, usize>,
    pub chain_valid: bool,
    pub earliest_event: Option<SystemTime>,
    pub latest_event: Option<SystemTime>,
    pub critical_events: usize,
    pub error_events: usize,
}
