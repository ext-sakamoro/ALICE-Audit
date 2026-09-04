#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use alice_audit::{Actor, AuditTrail, Resource, Severity};

// Fuzz AuditTrail::log_event with arbitrary UTF-8-cleansed input strings.
// Must never panic; hash chain invariants must hold after each append.
fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Slice arbitrary bytes into 4 utf-8 lossy strings + severity picker
    let sev = match data[0] & 0b11 {
        0 => Severity::Info,
        1 => Severity::Warning,
        2 => Severity::Error,
        _ => Severity::Critical,
    };
    let rest = &data[1..];
    let chunk = rest.len() / 4;
    if chunk == 0 {
        return;
    }
    let s0 = String::from_utf8_lossy(&rest[..chunk]).into_owned();
    let s1 = String::from_utf8_lossy(&rest[chunk..2 * chunk]).into_owned();
    let s2 = String::from_utf8_lossy(&rest[2 * chunk..3 * chunk]).into_owned();
    let s3 = String::from_utf8_lossy(&rest[3 * chunk..]).into_owned();

    let actor = Actor::new(&s0, &s1, "user");
    let resource = Resource::new("doc", &s2, "resource");
    let mut trail = AuditTrail::new();
    let seq = trail.log_event(sev, actor, resource, &s3, &s0, HashMap::new());
    // Sequence must be non-zero (AuditTrail starts at 1)
    assert!(seq >= 1, "sequence must be positive");
    // Chain must verify after any single append
    assert!(trail.verify_chain(), "hash chain broken after single append");
});
