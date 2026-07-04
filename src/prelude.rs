//! Convenience re-export (= `use alice_audit::prelude::*;` で主要 API 一括取得)
//!
//! Audit (event / trail / GDPR / signed trail) 主要型を提供

// crate root で公開している型
pub use crate::{
    Actor, AuditEvent, AuditTrail, ComplianceReport, QueryFilter, Resource, RetentionPolicy,
    Severity,
};

// GDPR sub-module
pub use crate::gdpr::{
    DataSubjectRequest, DataSubjectRequestKind, GdprRegister, LawfulBasis, ProcessingRecord,
    RequestStatus,
};

// Signed audit trail sub-module
pub use crate::signed_trail::{SignedAuditEvent, SignedAuditTrail};
