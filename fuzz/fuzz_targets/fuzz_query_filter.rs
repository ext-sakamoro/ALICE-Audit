#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use alice_audit::{Actor, AuditTrail, QueryFilter, Resource, Severity};

// Fuzz QueryFilter application against a pre-populated AuditTrail.
// Must never panic; returned event count must be <= trail length.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Populate trail with a small deterministic set of events
    let mut trail = AuditTrail::new();
    for i in 0..8 {
        let actor = Actor::new(&format!("actor-{i}"), "n", "user");
        let resource = Resource::new("doc", &format!("res-{i}"), "n");
        let sev = match i % 4 {
            0 => Severity::Info,
            1 => Severity::Warning,
            2 => Severity::Error,
            _ => Severity::Critical,
        };
        trail.log_event(sev, actor, resource, "action", "detail", HashMap::new());
    }

    // Build filter from arbitrary input bytes
    let actor_id = String::from_utf8_lossy(&data[..data.len() / 4]).into_owned();
    let resource_id = String::from_utf8_lossy(&data[data.len() / 4..data.len() / 2]).into_owned();
    let action = String::from_utf8_lossy(&data[data.len() / 2..3 * data.len() / 4]).into_owned();
    let severity = match data[0] & 0b11 {
        0 => Severity::Info,
        1 => Severity::Warning,
        2 => Severity::Error,
        _ => Severity::Critical,
    };

    let filter = QueryFilter::new()
        .with_actor_id(&actor_id)
        .with_resource_id(&resource_id)
        .with_action(&action);

    let results = trail.query(&filter);
    assert!(results.len() <= trail.events().len(), "query exceeded trail size");

    // Also fuzz severity-scoped helpers (must not panic)
    let _ = trail.events_by_severity(severity);
    let _ = trail.events_at_or_above(severity);
    let _ = trail.events_by_actor(&actor_id);
    let _ = trail.events_by_resource(&resource_id);
});
