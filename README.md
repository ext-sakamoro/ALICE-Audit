**English** | [日本語](README_JP.md)

# ALICE-Audit

Audit trail system for [Project A.L.I.C.E.](https://github.com/anthropics/alice)

## Overview

`alice-audit` provides a tamper-evident audit trail with hash-chain integrity verification, compliance reporting, retention policies, and structured event queries.

## Features

- **Hash-Chain Audit Trail** — each event is cryptographically chained to the previous
- **Tamper Detection** — verify the entire chain or individual events
- **Severity Levels** — Info, Warning, Error, Critical classification
- **Actor & Resource Tracking** — structured who-did-what-to-which records
- **Metadata** — arbitrary key-value pairs per event
- **Retention Policies** — time-based automatic event expiration
- **Compliance Reporting** — generate audit reports by time range, actor, or resource
- **Event Queries** — filter and search across the audit log

## Quick Start

```rust
use alice_audit::{AuditTrail, Actor, Resource, Severity};

let mut trail = AuditTrail::new();
let actor = Actor::new("u-001", "Alice", "admin");
let resource = Resource::new("document", "d-42", "report.pdf");

trail.record(Severity::Info, actor, resource, "download", "User downloaded report");
assert!(trail.verify_chain());
```

## Architecture

```
alice-audit
├── Severity       — event severity classification
├── Actor          — who performed the action
├── Resource       — what was affected
├── AuditEvent     — single event with hash chain link
├── AuditTrail     — append-only log with chain verification
├── RetentionPolicy— time-based event expiration
└── ComplianceReport— structured audit reporting
```

## License

AGPL-3.0
