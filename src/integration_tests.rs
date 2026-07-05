//! Integration tests.

#![allow(
    clippy::wildcard_imports,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use crate::actor::*;
use crate::event::*;
use crate::query::*;
use crate::report::*;
use crate::retention::*;
use crate::severity::*;
use crate::trail::*;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;

fn make_actor(id: &str) -> Actor {
    Actor::new(id, &format!("Actor {id}"), "user")
}

fn make_resource(id: &str) -> Resource {
    Resource::new("file", id, &format!("Resource {id}"))
}

fn base_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn log_n_events(trail: &mut AuditTrail, n: usize) {
    let t = base_time();
    for i in 0..n {
        trail.log_event_at(
            Severity::Info,
            make_actor("a1"),
            make_resource("r1"),
            "read",
            &format!("event {i}"),
            HashMap::new(),
            t + Duration::from_secs(u64::try_from(i).unwrap()),
        );
    }
}

// --- Construction ---

#[test]
fn new_trail_is_empty() {
    let trail = AuditTrail::new();
    assert!(trail.is_empty());
    assert_eq!(trail.len(), 0);
}

#[test]
fn default_trail_is_empty() {
    let trail = AuditTrail::default();
    assert!(trail.is_empty());
}

#[test]
fn trail_with_retention_is_empty() {
    let trail = AuditTrail::with_retention(RetentionPolicy::new().with_max_count(10));
    assert!(trail.is_empty());
}

// --- Logging ---

#[test]
fn log_single_event() {
    let mut trail = AuditTrail::new();
    let seq = trail.log_info(make_actor("a1"), make_resource("r1"), "read", "detail");
    assert_eq!(seq, 1);
    assert_eq!(trail.len(), 1);
}

#[test]
fn log_multiple_events_increments_sequence() {
    let mut trail = AuditTrail::new();
    let s1 = trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d1");
    let s2 = trail.log_warning(make_actor("a2"), make_resource("r2"), "write", "d2");
    let s3 = trail.log_error(make_actor("a3"), make_resource("r3"), "delete", "d3");
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(s3, 3);
    assert_eq!(trail.len(), 3);
}

#[test]
fn log_info_sets_severity() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    assert_eq!(trail.events()[0].severity, Severity::Info);
}

#[test]
fn log_warning_sets_severity() {
    let mut trail = AuditTrail::new();
    trail.log_warning(make_actor("a1"), make_resource("r1"), "read", "d");
    assert_eq!(trail.events()[0].severity, Severity::Warning);
}

#[test]
fn log_error_sets_severity() {
    let mut trail = AuditTrail::new();
    trail.log_error(make_actor("a1"), make_resource("r1"), "read", "d");
    assert_eq!(trail.events()[0].severity, Severity::Error);
}

#[test]
fn log_critical_sets_severity() {
    let mut trail = AuditTrail::new();
    trail.log_critical(make_actor("a1"), make_resource("r1"), "read", "d");
    assert_eq!(trail.events()[0].severity, Severity::Critical);
}

#[test]
fn log_event_with_metadata() {
    let mut trail = AuditTrail::new();
    let mut meta = HashMap::new();
    meta.insert("ip".to_owned(), "192.168.1.1".to_owned());
    meta.insert("session".to_owned(), "abc123".to_owned());
    trail.log_event(
        Severity::Info,
        make_actor("a1"),
        make_resource("r1"),
        "login",
        "user logged in",
        meta,
    );
    assert_eq!(trail.events()[0].metadata.len(), 2);
    assert_eq!(trail.events()[0].metadata["ip"], "192.168.1.1");
}

#[test]
fn log_event_at_specific_time() {
    let mut trail = AuditTrail::new();
    let t = base_time();
    trail.log_event_at(
        Severity::Info,
        make_actor("a1"),
        make_resource("r1"),
        "read",
        "d",
        HashMap::new(),
        t,
    );
    assert_eq!(trail.events()[0].timestamp, t);
}

#[test]
fn event_stores_actor_correctly() {
    let mut trail = AuditTrail::new();
    trail.log_info(
        Actor::new("u42", "Alice", "admin"),
        make_resource("r1"),
        "read",
        "d",
    );
    let e = &trail.events()[0];
    assert_eq!(e.actor.id, "u42");
    assert_eq!(e.actor.name, "Alice");
    assert_eq!(e.actor.role, "admin");
}

#[test]
fn event_stores_resource_correctly() {
    let mut trail = AuditTrail::new();
    trail.log_info(
        make_actor("a1"),
        Resource::new("database", "db1", "MainDB"),
        "query",
        "d",
    );
    let e = &trail.events()[0];
    assert_eq!(e.resource.kind, "database");
    assert_eq!(e.resource.id, "db1");
    assert_eq!(e.resource.name, "MainDB");
}

#[test]
fn event_stores_action_and_detail() {
    let mut trail = AuditTrail::new();
    trail.log_info(
        make_actor("a1"),
        make_resource("r1"),
        "export",
        "exported CSV",
    );
    let e = &trail.events()[0];
    assert_eq!(e.action, "export");
    assert_eq!(e.detail, "exported CSV");
}

// --- Hash Chain ---

#[test]
fn first_event_prev_hash_is_zero() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    assert_eq!(trail.events()[0].prev_hash, 0);
}

#[test]
fn second_event_prev_hash_matches_first_hash() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d1");
    trail.log_info(make_actor("a2"), make_resource("r2"), "write", "d2");
    assert_eq!(trail.events()[1].prev_hash, trail.events()[0].hash);
}

#[test]
fn hash_chain_links_all_events() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 10);
    for i in 1..10 {
        assert_eq!(trail.events()[i].prev_hash, trail.events()[i - 1].hash);
    }
}

#[test]
fn each_event_has_unique_hash() {
    let mut trail = AuditTrail::new();
    let t = base_time();
    for i in 0..20 {
        trail.log_event_at(
            Severity::Info,
            make_actor(&format!("a{i}")),
            make_resource(&format!("r{i}")),
            "action",
            &format!("detail {i}"),
            HashMap::new(),
            t + Duration::from_secs(i),
        );
    }
    let hashes: Vec<u64> = trail.events().iter().map(|e| e.hash).collect();
    for (i, h) in hashes.iter().enumerate() {
        for (j, h2) in hashes.iter().enumerate() {
            if i != j {
                assert_ne!(h, h2, "hash collision at index {i} and {j}");
            }
        }
    }
}

#[test]
fn event_verify_succeeds_for_valid_event() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    assert!(trail.events()[0].verify());
}

// --- Chain Verification ---

#[test]
fn verify_chain_empty_trail() {
    let trail = AuditTrail::new();
    assert!(trail.verify_chain());
}

#[test]
fn verify_chain_single_event() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    assert!(trail.verify_chain());
}

#[test]
fn verify_chain_multiple_events() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 50);
    assert!(trail.verify_chain());
}

#[test]
fn verify_chain_detects_hash_tampering() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 5);
    // Tamper with the hash of event 2
    trail.events[2].hash = 999_999;
    assert!(!trail.verify_chain());
}

#[test]
fn verify_chain_detects_data_tampering() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 5);
    // Tamper with the action of event 1
    trail.events[1].action = "tampered".to_owned();
    assert!(!trail.verify_chain());
}

#[test]
fn verify_chain_detects_prev_hash_tampering() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 5);
    trail.events[3].prev_hash = 12345;
    assert!(!trail.verify_chain());
}

// --- Tamper Detection ---

#[test]
fn detect_tampering_empty_trail() {
    let trail = AuditTrail::new();
    assert!(trail.detect_tampering().is_empty());
}

#[test]
fn detect_tampering_valid_trail() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 10);
    assert!(trail.detect_tampering().is_empty());
}

#[test]
fn detect_tampering_finds_tampered_event() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 5);
    trail.events[2].detail = "tampered".to_owned();
    let tampered = trail.detect_tampering();
    assert!(tampered.contains(&2));
}

#[test]
fn detect_tampering_cascade() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 5);
    // Tamper event 1's hash -> events 1 and 2+ are flagged
    trail.events[1].hash = 42;
    let tampered = trail.detect_tampering();
    assert!(tampered.contains(&1));
    assert!(tampered.contains(&2)); // prev_hash mismatch
}

// --- Queries ---

#[test]
fn query_by_actor_id() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d1");
    trail.log_info(make_actor("a2"), make_resource("r2"), "write", "d2");
    trail.log_info(make_actor("a1"), make_resource("r3"), "delete", "d3");

    let filter = QueryFilter::new().with_actor_id("a1");
    let results = trail.query(&filter);
    assert_eq!(results.len(), 2);
}

#[test]
fn query_by_resource_id() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d1");
    trail.log_info(make_actor("a2"), make_resource("r2"), "write", "d2");

    let filter = QueryFilter::new().with_resource_id("r2");
    let results = trail.query(&filter);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].resource.id, "r2");
}

#[test]
fn query_by_resource_kind() {
    let mut trail = AuditTrail::new();
    trail.log_info(
        make_actor("a1"),
        Resource::new("file", "r1", "f"),
        "read",
        "d1",
    );
    trail.log_info(
        make_actor("a1"),
        Resource::new("database", "r2", "db"),
        "query",
        "d2",
    );

    let filter = QueryFilter::new().with_resource_kind("database");
    let results = trail.query(&filter);
    assert_eq!(results.len(), 1);
}

#[test]
fn query_by_severity() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_error(make_actor("a1"), make_resource("r1"), "fail", "d");
    trail.log_critical(make_actor("a1"), make_resource("r1"), "crash", "d");

    let filter = QueryFilter::new().with_severity(Severity::Error);
    let results = trail.query(&filter);
    assert_eq!(results.len(), 1);
}

#[test]
fn query_by_min_severity() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_warning(make_actor("a1"), make_resource("r1"), "slow", "d");
    trail.log_error(make_actor("a1"), make_resource("r1"), "fail", "d");
    trail.log_critical(make_actor("a1"), make_resource("r1"), "crash", "d");

    let filter = QueryFilter::new().with_min_severity(Severity::Error);
    let results = trail.query(&filter);
    assert_eq!(results.len(), 2);
}

#[test]
fn query_by_action() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_info(make_actor("a1"), make_resource("r1"), "write", "d");
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");

    let filter = QueryFilter::new().with_action("read");
    let results = trail.query(&filter);
    assert_eq!(results.len(), 2);
}

#[test]
fn query_by_time_range() {
    let mut trail = AuditTrail::new();
    let t = base_time();
    for i in 0..10 {
        trail.log_event_at(
            Severity::Info,
            make_actor("a1"),
            make_resource("r1"),
            "read",
            &format!("event {i}"),
            HashMap::new(),
            t + Duration::from_secs(i * 100),
        );
    }

    let filter = QueryFilter::new()
        .with_time_range(t + Duration::from_secs(200), t + Duration::from_secs(500));
    let results = trail.query(&filter);
    assert_eq!(results.len(), 4); // events at 200, 300, 400, 500
}

#[test]
fn query_combined_filters() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_error(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_error(make_actor("a2"), make_resource("r1"), "read", "d");

    let filter = QueryFilter::new()
        .with_actor_id("a1")
        .with_severity(Severity::Error);
    let results = trail.query(&filter);
    assert_eq!(results.len(), 1);
}

#[test]
fn query_no_matches() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");

    let filter = QueryFilter::new().with_actor_id("nonexistent");
    let results = trail.query(&filter);
    assert!(results.is_empty());
}

#[test]
fn query_empty_filter_returns_all() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 5);

    let filter = QueryFilter::new();
    let results = trail.query(&filter);
    assert_eq!(results.len(), 5);
}

// --- Convenience query methods ---

#[test]
fn events_by_actor_method() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_info(make_actor("a2"), make_resource("r1"), "read", "d");
    trail.log_info(make_actor("a1"), make_resource("r2"), "write", "d");
    assert_eq!(trail.events_by_actor("a1").len(), 2);
    assert_eq!(trail.events_by_actor("a2").len(), 1);
    assert_eq!(trail.events_by_actor("a3").len(), 0);
}

#[test]
fn events_by_resource_method() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_info(make_actor("a1"), make_resource("r2"), "read", "d");
    assert_eq!(trail.events_by_resource("r1").len(), 1);
    assert_eq!(trail.events_by_resource("r2").len(), 1);
}

#[test]
fn events_by_severity_method() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_error(make_actor("a1"), make_resource("r1"), "fail", "d");
    trail.log_error(make_actor("a1"), make_resource("r1"), "fail2", "d");
    assert_eq!(trail.events_by_severity(Severity::Info).len(), 1);
    assert_eq!(trail.events_by_severity(Severity::Error).len(), 2);
}

#[test]
fn events_at_or_above_method() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "r", "d");
    trail.log_warning(make_actor("a1"), make_resource("r1"), "r", "d");
    trail.log_error(make_actor("a1"), make_resource("r1"), "r", "d");
    trail.log_critical(make_actor("a1"), make_resource("r1"), "r", "d");
    assert_eq!(trail.events_at_or_above(Severity::Warning).len(), 3);
    assert_eq!(trail.events_at_or_above(Severity::Critical).len(), 1);
    assert_eq!(trail.events_at_or_above(Severity::Info).len(), 4);
}

// --- Unique tracking ---

#[test]
fn unique_actors_tracking() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_info(make_actor("a2"), make_resource("r1"), "read", "d");
    trail.log_info(make_actor("a1"), make_resource("r2"), "write", "d");
    let actors = trail.unique_actors();
    assert_eq!(actors.len(), 2);
    assert!(actors.contains(&"a1".to_owned()));
    assert!(actors.contains(&"a2".to_owned()));
}

#[test]
fn unique_resources_tracking() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_info(make_actor("a1"), make_resource("r2"), "read", "d");
    trail.log_info(make_actor("a1"), make_resource("r1"), "write", "d");
    let resources = trail.unique_resources();
    assert_eq!(resources.len(), 2);
}

#[test]
fn unique_actions_tracking() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_info(make_actor("a1"), make_resource("r1"), "write", "d");
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    let actions = trail.unique_actions();
    assert_eq!(actions.len(), 2);
}

// --- Retention Policies ---

#[test]
fn retention_policy_default() {
    let policy = RetentionPolicy::new();
    assert!(policy.max_age.is_none());
    assert!(policy.max_count.is_none());
}

#[test]
fn retention_policy_with_max_age() {
    let policy = RetentionPolicy::new().with_max_age(Duration::from_secs(3600));
    assert_eq!(policy.max_age, Some(Duration::from_secs(3600)));
}

#[test]
fn retention_policy_with_max_count() {
    let policy = RetentionPolicy::new().with_max_count(100);
    assert_eq!(policy.max_count, Some(100));
}

#[test]
fn retention_max_count_removes_oldest() {
    let mut trail = AuditTrail::with_retention(RetentionPolicy::new().with_max_count(5));
    log_n_events(&mut trail, 10);
    let removed = trail.apply_retention();
    assert_eq!(removed, 5);
    assert_eq!(trail.len(), 5);
    // Remaining events should be the last 5
    assert_eq!(trail.events()[0].sequence, 6);
}

#[test]
fn retention_max_count_no_removal_when_under_limit() {
    let mut trail = AuditTrail::with_retention(RetentionPolicy::new().with_max_count(20));
    log_n_events(&mut trail, 5);
    let removed = trail.apply_retention();
    assert_eq!(removed, 0);
    assert_eq!(trail.len(), 5);
}

#[test]
fn retention_max_age_removes_old_events() {
    let mut trail =
        AuditTrail::with_retention(RetentionPolicy::new().with_max_age(Duration::from_secs(500)));
    let t = base_time();
    for i in 0..10 {
        trail.log_event_at(
            Severity::Info,
            make_actor("a1"),
            make_resource("r1"),
            "read",
            &format!("e{i}"),
            HashMap::new(),
            t + Duration::from_secs(i * 100),
        );
    }
    // Reference time: t + 950s -> events older than 500s from ref are removed
    // Events at t+0, t+100, t+200, t+300, t+400 are older than 500s
    let removed = trail.apply_retention_at(t + Duration::from_secs(950));
    assert_eq!(removed, 5);
    assert_eq!(trail.len(), 5);
}

#[test]
fn retention_combined_age_and_count() {
    let mut trail = AuditTrail::with_retention(
        RetentionPolicy::new()
            .with_max_age(Duration::from_secs(500))
            .with_max_count(3),
    );
    let t = base_time();
    for i in 0..10 {
        trail.log_event_at(
            Severity::Info,
            make_actor("a1"),
            make_resource("r1"),
            "read",
            &format!("e{i}"),
            HashMap::new(),
            t + Duration::from_secs(i * 100),
        );
    }
    let removed = trail.apply_retention_at(t + Duration::from_secs(950));
    // First: max_age removes 5 (events at 0-400). Then max_count keeps 3 of remaining 5.
    assert_eq!(removed, 7);
    assert_eq!(trail.len(), 3);
}

#[test]
fn set_retention_changes_policy() {
    let mut trail = AuditTrail::new();
    trail.set_retention(RetentionPolicy::new().with_max_count(5));
    assert_eq!(trail.retention().max_count, Some(5));
}

// --- Compliance Report ---

#[test]
fn compliance_report_empty_trail() {
    let trail = AuditTrail::new();
    let report = trail.compliance_report();
    assert_eq!(report.total_events, 0);
    assert!(report.chain_valid);
    assert_eq!(report.critical_events, 0);
    assert_eq!(report.error_events, 0);
    assert!(report.earliest_event.is_none());
    assert!(report.latest_event.is_none());
}

#[test]
fn compliance_report_counts_severities() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "r", "d");
    trail.log_info(make_actor("a1"), make_resource("r1"), "r", "d");
    trail.log_warning(make_actor("a1"), make_resource("r1"), "r", "d");
    trail.log_error(make_actor("a1"), make_resource("r1"), "r", "d");
    trail.log_critical(make_actor("a1"), make_resource("r1"), "r", "d");

    let report = trail.compliance_report();
    assert_eq!(report.total_events, 5);
    assert_eq!(report.events_by_severity["INFO"], 2);
    assert_eq!(report.events_by_severity["WARNING"], 1);
    assert_eq!(report.events_by_severity["ERROR"], 1);
    assert_eq!(report.events_by_severity["CRITICAL"], 1);
    assert_eq!(report.error_events, 1);
    assert_eq!(report.critical_events, 1);
}

#[test]
fn compliance_report_counts_actors() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "r", "d");
    trail.log_info(make_actor("a1"), make_resource("r1"), "r", "d");
    trail.log_info(make_actor("a2"), make_resource("r1"), "r", "d");

    let report = trail.compliance_report();
    assert_eq!(report.events_by_actor["a1"], 2);
    assert_eq!(report.events_by_actor["a2"], 1);
}

#[test]
fn compliance_report_counts_resource_kinds() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), Resource::new("file", "r1", "f"), "r", "d");
    trail.log_info(
        make_actor("a1"),
        Resource::new("database", "r2", "db"),
        "r",
        "d",
    );
    trail.log_info(
        make_actor("a1"),
        Resource::new("file", "r3", "f2"),
        "r",
        "d",
    );

    let report = trail.compliance_report();
    assert_eq!(report.events_by_resource_kind["file"], 2);
    assert_eq!(report.events_by_resource_kind["database"], 1);
}

#[test]
fn compliance_report_counts_actions() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    trail.log_info(make_actor("a1"), make_resource("r1"), "write", "d");
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");

    let report = trail.compliance_report();
    assert_eq!(report.events_by_action["read"], 2);
    assert_eq!(report.events_by_action["write"], 1);
}

#[test]
fn compliance_report_chain_valid() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 10);
    let report = trail.compliance_report();
    assert!(report.chain_valid);
}

#[test]
fn compliance_report_chain_invalid_after_tampering() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 10);
    trail.events[5].action = "tampered".to_owned();
    let report = trail.compliance_report();
    assert!(!report.chain_valid);
}

#[test]
fn compliance_report_time_range() {
    let mut trail = AuditTrail::new();
    let t = base_time();
    trail.log_event_at(
        Severity::Info,
        make_actor("a1"),
        make_resource("r1"),
        "r",
        "d",
        HashMap::new(),
        t,
    );
    trail.log_event_at(
        Severity::Info,
        make_actor("a1"),
        make_resource("r1"),
        "r",
        "d",
        HashMap::new(),
        t + Duration::from_secs(1000),
    );
    let report = trail.compliance_report();
    assert_eq!(report.earliest_event, Some(t));
    assert_eq!(report.latest_event, Some(t + Duration::from_secs(1000)));
}

// --- Severity ordering ---

#[test]
fn severity_ordering() {
    assert!(Severity::Info < Severity::Warning);
    assert!(Severity::Warning < Severity::Error);
    assert!(Severity::Error < Severity::Critical);
}

#[test]
fn severity_display() {
    assert_eq!(Severity::Info.to_string(), "INFO");
    assert_eq!(Severity::Warning.to_string(), "WARNING");
    assert_eq!(Severity::Error.to_string(), "ERROR");
    assert_eq!(Severity::Critical.to_string(), "CRITICAL");
}

#[test]
fn severity_equality() {
    assert_eq!(Severity::Info, Severity::Info);
    assert_ne!(Severity::Info, Severity::Warning);
}

// --- Get by sequence ---

#[test]
fn get_by_sequence_found() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 5);
    let event = trail.get_by_sequence(3);
    assert!(event.is_some());
    assert_eq!(event.unwrap().sequence, 3);
}

#[test]
fn get_by_sequence_not_found() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 5);
    assert!(trail.get_by_sequence(99).is_none());
}

// --- Clear ---

#[test]
fn clear_removes_all_events() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 10);
    trail.clear();
    assert!(trail.is_empty());
    assert_eq!(trail.len(), 0);
}

#[test]
fn clear_resets_sequence() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 5);
    trail.clear();
    let seq = trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    assert_eq!(seq, 1);
}

// --- Actor / Resource ---

#[test]
fn actor_new() {
    let actor = Actor::new("u1", "Bob", "admin");
    assert_eq!(actor.id, "u1");
    assert_eq!(actor.name, "Bob");
    assert_eq!(actor.role, "admin");
}

#[test]
fn resource_new() {
    let res = Resource::new("bucket", "b1", "MyBucket");
    assert_eq!(res.kind, "bucket");
    assert_eq!(res.id, "b1");
    assert_eq!(res.name, "MyBucket");
}

#[test]
fn actor_clone() {
    let actor = Actor::new("u1", "Bob", "admin");
    let clone = actor.clone();
    assert_eq!(actor, clone);
}

#[test]
fn resource_clone() {
    let res = Resource::new("bucket", "b1", "B");
    let clone = res.clone();
    assert_eq!(res, clone);
}

#[test]
fn actor_hash_equality() {
    let a1 = Actor::new("u1", "Bob", "admin");
    let a2 = Actor::new("u1", "Bob", "admin");
    let mut hasher1 = DefaultHasher::new();
    let mut hasher2 = DefaultHasher::new();
    a1.hash(&mut hasher1);
    a2.hash(&mut hasher2);
    assert_eq!(hasher1.finish(), hasher2.finish());
}

// --- Edge cases ---

#[test]
fn empty_strings_in_event() {
    let mut trail = AuditTrail::new();
    trail.log_info(Actor::new("", "", ""), Resource::new("", "", ""), "", "");
    assert_eq!(trail.len(), 1);
    assert!(trail.verify_chain());
}

#[test]
fn large_metadata() {
    let mut trail = AuditTrail::new();
    let mut meta = HashMap::new();
    for i in 0..100 {
        meta.insert(format!("key_{i}"), format!("value_{i}"));
    }
    trail.log_event(
        Severity::Info,
        make_actor("a1"),
        make_resource("r1"),
        "bulk",
        "lots of metadata",
        meta,
    );
    assert!(trail.verify_chain());
    assert_eq!(trail.events()[0].metadata.len(), 100);
}

#[test]
fn many_events_chain_integrity() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 200);
    assert!(trail.verify_chain());
    assert_eq!(trail.len(), 200);
}

#[test]
fn retention_no_policy_does_nothing() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 10);
    let removed = trail.apply_retention();
    assert_eq!(removed, 0);
    assert_eq!(trail.len(), 10);
}

#[test]
fn query_filter_default_matches_all() {
    let filter = QueryFilter::default();
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 3);
    assert_eq!(trail.query(&filter).len(), 3);
}

#[test]
fn log_event_returns_sequential_ids() {
    let mut trail = AuditTrail::new();
    for expected in 1..=20 {
        let seq = trail.log_info(make_actor("a"), make_resource("r"), "a", "d");
        assert_eq!(seq, expected);
    }
}

#[test]
fn metadata_deterministic_hashing() {
    let mut trail1 = AuditTrail::new();
    let mut trail2 = AuditTrail::new();
    let t = base_time();
    let mut meta1 = HashMap::new();
    meta1.insert("a".to_owned(), "1".to_owned());
    meta1.insert("b".to_owned(), "2".to_owned());
    let mut meta2 = HashMap::new();
    meta2.insert("b".to_owned(), "2".to_owned());
    meta2.insert("a".to_owned(), "1".to_owned());

    trail1.log_event_at(
        Severity::Info,
        make_actor("a1"),
        make_resource("r1"),
        "read",
        "d",
        meta1,
        t,
    );
    trail2.log_event_at(
        Severity::Info,
        make_actor("a1"),
        make_resource("r1"),
        "read",
        "d",
        meta2,
        t,
    );
    assert_eq!(trail1.events()[0].hash, trail2.events()[0].hash);
}

#[test]
fn different_actions_produce_different_hashes() {
    let mut trail = AuditTrail::new();
    let t = base_time();
    trail.log_event_at(
        Severity::Info,
        make_actor("a1"),
        make_resource("r1"),
        "read",
        "d",
        HashMap::new(),
        t,
    );
    let h1 = trail.events()[0].hash;
    trail.clear();

    trail.log_event_at(
        Severity::Info,
        make_actor("a1"),
        make_resource("r1"),
        "write",
        "d",
        HashMap::new(),
        t,
    );
    let h2 = trail.events()[0].hash;
    assert_ne!(h1, h2);
}

#[test]
fn different_severities_produce_different_hashes() {
    let mut trail = AuditTrail::new();
    let t = base_time();
    trail.log_event_at(
        Severity::Info,
        make_actor("a1"),
        make_resource("r1"),
        "r",
        "d",
        HashMap::new(),
        t,
    );
    let h1 = trail.events()[0].hash;
    trail.clear();

    trail.log_event_at(
        Severity::Critical,
        make_actor("a1"),
        make_resource("r1"),
        "r",
        "d",
        HashMap::new(),
        t,
    );
    let h2 = trail.events()[0].hash;
    assert_ne!(h1, h2);
}

#[test]
fn retention_max_count_exact_boundary() {
    let mut trail = AuditTrail::with_retention(RetentionPolicy::new().with_max_count(5));
    log_n_events(&mut trail, 5);
    let removed = trail.apply_retention();
    assert_eq!(removed, 0);
    assert_eq!(trail.len(), 5);
}

#[test]
fn retention_max_count_one_over() {
    let mut trail = AuditTrail::with_retention(RetentionPolicy::new().with_max_count(5));
    log_n_events(&mut trail, 6);
    let removed = trail.apply_retention();
    assert_eq!(removed, 1);
    assert_eq!(trail.len(), 5);
}

#[test]
fn events_slice_returns_correct_data() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d1");
    trail.log_error(make_actor("a2"), make_resource("r2"), "write", "d2");
    let events = trail.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].actor.id, "a1");
    assert_eq!(events[1].actor.id, "a2");
}

#[test]
fn unique_actors_empty_trail() {
    let trail = AuditTrail::new();
    assert!(trail.unique_actors().is_empty());
}

#[test]
fn unique_resources_empty_trail() {
    let trail = AuditTrail::new();
    assert!(trail.unique_resources().is_empty());
}

#[test]
fn unique_actions_empty_trail() {
    let trail = AuditTrail::new();
    assert!(trail.unique_actions().is_empty());
}

#[test]
fn query_start_time_only() {
    let mut trail = AuditTrail::new();
    let t = base_time();
    trail.log_event_at(
        Severity::Info,
        make_actor("a"),
        make_resource("r"),
        "a",
        "d",
        HashMap::new(),
        t,
    );
    trail.log_event_at(
        Severity::Info,
        make_actor("a"),
        make_resource("r"),
        "a",
        "d",
        HashMap::new(),
        t + Duration::from_secs(1000),
    );
    let mut filter = QueryFilter::new();
    filter.start_time = Some(t + Duration::from_secs(500));
    let results = trail.query(&filter);
    assert_eq!(results.len(), 1);
}

#[test]
fn query_end_time_only() {
    let mut trail = AuditTrail::new();
    let t = base_time();
    trail.log_event_at(
        Severity::Info,
        make_actor("a"),
        make_resource("r"),
        "a",
        "d",
        HashMap::new(),
        t,
    );
    trail.log_event_at(
        Severity::Info,
        make_actor("a"),
        make_resource("r"),
        "a",
        "d",
        HashMap::new(),
        t + Duration::from_secs(1000),
    );
    let mut filter = QueryFilter::new();
    filter.end_time = Some(t + Duration::from_secs(500));
    let results = trail.query(&filter);
    assert_eq!(results.len(), 1);
}

#[test]
fn compliance_report_single_event() {
    let mut trail = AuditTrail::new();
    trail.log_critical(
        make_actor("admin"),
        make_resource("srv"),
        "shutdown",
        "emergency",
    );
    let report = trail.compliance_report();
    assert_eq!(report.total_events, 1);
    assert_eq!(report.critical_events, 1);
    assert_eq!(report.error_events, 0);
    assert!(report.chain_valid);
    assert!(report.earliest_event.is_some());
    assert_eq!(report.earliest_event, report.latest_event);
}

#[test]
fn detect_tampering_at_first_event() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 3);
    trail.events[0].action = "tampered".to_owned();
    let tampered = trail.detect_tampering();
    assert!(tampered.contains(&0));
}

#[test]
fn detect_tampering_at_last_event() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 5);
    trail.events[4].detail = "tampered".to_owned();
    let tampered = trail.detect_tampering();
    assert!(tampered.contains(&4));
}

#[test]
fn retention_policy_default_trait() {
    let policy = RetentionPolicy::default();
    assert!(policy.max_age.is_none());
    assert!(policy.max_count.is_none());
}

#[test]
fn severity_clone() {
    let s = Severity::Critical;
    let s2 = s;
    assert_eq!(s, s2);
}

#[test]
fn severity_debug() {
    let s = Severity::Warning;
    let debug = format!("{s:?}");
    assert_eq!(debug, "Warning");
}

#[test]
fn verify_chain_100_events() {
    let mut trail = AuditTrail::new();
    log_n_events(&mut trail, 100);
    assert!(trail.verify_chain());
    assert_eq!(trail.len(), 100);
}

#[test]
fn query_action_no_match() {
    let mut trail = AuditTrail::new();
    trail.log_info(make_actor("a1"), make_resource("r1"), "read", "d");
    let filter = QueryFilter::new().with_action("nonexistent");
    assert!(trail.query(&filter).is_empty());
}

#[test]
fn retention_max_count_zero() {
    let mut trail = AuditTrail::with_retention(RetentionPolicy::new().with_max_count(0));
    log_n_events(&mut trail, 5);
    let removed = trail.apply_retention();
    assert_eq!(removed, 5);
    assert!(trail.is_empty());
}

#[test]
fn compliance_report_multiple_actions_and_actors() {
    let mut trail = AuditTrail::new();
    for i in 0..5 {
        trail.log_info(
            make_actor(&format!("actor_{i}")),
            make_resource(&format!("res_{i}")),
            &format!("action_{}", i % 3),
            "d",
        );
    }
    let report = trail.compliance_report();
    assert_eq!(report.total_events, 5);
    assert_eq!(report.events_by_actor.len(), 5);
    assert_eq!(report.events_by_action.len(), 3);
}
