#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use alice_audit::{Actor, AuditTrail, Resource, Severity};

// Fuzz hash-chain integrity across many appends with arbitrary payloads.
// Invariants:
//   1. verify_chain() must be true after any pure append sequence
//   2. detect_tampering() must return an empty vec on untampered trail
//   3. Sequence numbers must be strictly increasing
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut trail = AuditTrail::new();
    let mut last_seq: u64 = 0;

    // Split into slices of at most 32 bytes each, one event per slice
    for (idx, chunk) in data.chunks(32).enumerate().take(64) {
        let sev = match chunk.first().copied().unwrap_or(0) & 0b11 {
            0 => Severity::Info,
            1 => Severity::Warning,
            2 => Severity::Error,
            _ => Severity::Critical,
        };
        let s = String::from_utf8_lossy(chunk).into_owned();
        let actor = Actor::new(&format!("a-{idx}"), &s, "user");
        let resource = Resource::new("doc", &format!("r-{idx}"), &s);
        let seq = trail.log_event(sev, actor, resource, "act", &s, HashMap::new());

        assert!(seq > last_seq, "sequence must be strictly increasing");
        last_seq = seq;
    }

    // Chain integrity holds after every batch
    assert!(trail.verify_chain(), "hash chain broken after batch append");
    assert!(
        trail.detect_tampering().is_empty(),
        "detect_tampering must be empty on untampered trail"
    );

    // Read-only queries must not panic on any trail state
    let _ = trail.unique_actors();
    let _ = trail.unique_resources();
    let _ = trail.unique_actions();
});
