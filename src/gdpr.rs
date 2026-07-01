//! GDPR compliance record structures.
//!
//! Implements the minimal data required by:
//!
//! - `GDPR` Art. 30 — records of processing activities kept by controllers
//!   and processors.
//! - `GDPR` Art. 15, 16, 17, 20 — data subject access, rectification,
//!   erasure and portability requests, tracked as a `DataSubjectRequest`
//!   with a lifecycle status.
//!
//! Records are content-agnostic; sign or anchor them via
//! [`crate::SignedAuditTrail`] to prove that the log has not been
//! tampered with after the fact.

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Lawful basis
// ---------------------------------------------------------------------------

/// Lawful basis for processing enumerated in `GDPR` Art. 6 (1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LawfulBasis {
    /// Point (a): explicit consent.
    Consent,
    /// Point (b): performance of a contract.
    Contract,
    /// Point (c): legal obligation.
    LegalObligation,
    /// Point (d): vital interests.
    VitalInterests,
    /// Point (e): public interest / official authority.
    PublicInterest,
    /// Point (f): legitimate interests.
    LegitimateInterests,
}

// ---------------------------------------------------------------------------
// Processing record (Art. 30)
// ---------------------------------------------------------------------------

/// A single record of processing activity.
#[derive(Debug, Clone)]
pub struct ProcessingRecord {
    pub id: String,
    pub controller: String,
    pub purposes: Vec<String>,
    pub data_categories: Vec<String>,
    pub subject_categories: Vec<String>,
    pub recipients: Vec<String>,
    pub retention_days: Option<u32>,
    pub lawful_basis: LawfulBasis,
    pub international_transfers: bool,
}

impl ProcessingRecord {
    /// Convenience constructor for the minimum-viable Art. 30 record.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        controller: impl Into<String>,
        purpose: impl Into<String>,
        lawful_basis: LawfulBasis,
    ) -> Self {
        Self {
            id: id.into(),
            controller: controller.into(),
            purposes: vec![purpose.into()],
            data_categories: Vec::new(),
            subject_categories: Vec::new(),
            recipients: Vec::new(),
            retention_days: None,
            lawful_basis,
            international_transfers: false,
        }
    }

    /// Fluent builder helper for adding a data category.
    #[must_use]
    pub fn with_data_category(mut self, category: impl Into<String>) -> Self {
        self.data_categories.push(category.into());
        self
    }
}

// ---------------------------------------------------------------------------
// DataSubjectRequest (Arts. 15, 16, 17, 20)
// ---------------------------------------------------------------------------

/// Type of data subject request.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataSubjectRequestKind {
    /// Art. 15 — access to personal data.
    Access,
    /// Art. 16 — rectification.
    Rectification,
    /// Art. 17 — erasure ("right to be forgotten").
    Erasure,
    /// Art. 20 — data portability.
    Portability,
}

/// Lifecycle status of a `DataSubjectRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestStatus {
    /// Just received; no action taken yet.
    Received,
    /// Under review; identity verified, scope being determined.
    InReview,
    /// Fulfilled with an operator-supplied note (e.g. reference to the
    /// exported archive).
    Fulfilled(String),
    /// Refused with a reason (e.g. "manifestly unfounded").
    Refused(String),
}

impl RequestStatus {
    /// Whether the request has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Fulfilled(_) | Self::Refused(_))
    }
}

/// A request received from a data subject.
#[derive(Debug, Clone)]
pub struct DataSubjectRequest {
    pub id: String,
    pub subject_id: String,
    pub kind: DataSubjectRequestKind,
    pub received_iso: String,
    pub status: RequestStatus,
}

impl DataSubjectRequest {
    /// Convenience constructor.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        subject_id: impl Into<String>,
        kind: DataSubjectRequestKind,
        received_iso: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            subject_id: subject_id.into(),
            kind,
            received_iso: received_iso.into(),
            status: RequestStatus::Received,
        }
    }

    /// Update the status.
    pub fn set_status(&mut self, status: RequestStatus) {
        self.status = status;
    }
}

// ---------------------------------------------------------------------------
// GdprRegister
// ---------------------------------------------------------------------------

/// Aggregate of Art. 30 records + data subject requests.
#[derive(Debug, Clone, Default)]
pub struct GdprRegister {
    processing: Vec<ProcessingRecord>,
    requests: Vec<DataSubjectRequest>,
}

impl GdprRegister {
    /// Empty register.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            processing: Vec::new(),
            requests: Vec::new(),
        }
    }

    /// Add a processing record.
    pub fn add_processing(&mut self, record: ProcessingRecord) {
        self.processing.push(record);
    }

    /// Add a data subject request.
    pub fn add_request(&mut self, request: DataSubjectRequest) {
        self.requests.push(request);
    }

    /// All processing records.
    #[must_use]
    pub fn processing(&self) -> &[ProcessingRecord] {
        &self.processing
    }

    /// All requests.
    #[must_use]
    pub fn requests(&self) -> &[DataSubjectRequest] {
        &self.requests
    }

    /// Count of open (non-terminal) requests.
    #[must_use]
    pub fn open_request_count(&self) -> usize {
        self.requests
            .iter()
            .filter(|r| !r.status.is_terminal())
            .count()
    }

    /// Distinct data categories referenced across all processing records.
    #[must_use]
    pub fn distinct_data_categories(&self) -> Vec<String> {
        let mut set: HashSet<&str> = HashSet::new();
        for p in &self.processing {
            for c in &p.data_categories {
                set.insert(c);
            }
        }
        let mut out: Vec<String> = set.into_iter().map(str::to_owned).collect();
        out.sort_unstable();
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processing_record_defaults_are_conservative() {
        let r = ProcessingRecord::new(
            "PR-001",
            "Acme Ltd",
            "Employee payroll",
            LawfulBasis::Contract,
        );
        assert!(r.retention_days.is_none());
        assert!(!r.international_transfers);
        assert_eq!(r.purposes.len(), 1);
    }

    #[test]
    fn processing_record_builder_appends_data_category() {
        let r = ProcessingRecord::new(
            "PR-001",
            "Acme Ltd",
            "Employee payroll",
            LawfulBasis::Contract,
        )
        .with_data_category("name")
        .with_data_category("bank account");
        assert_eq!(r.data_categories.len(), 2);
    }

    #[test]
    fn new_request_starts_in_received_status() {
        let r = DataSubjectRequest::new(
            "REQ-1",
            "subject-1",
            DataSubjectRequestKind::Access,
            "2026-04-01",
        );
        assert!(matches!(r.status, RequestStatus::Received));
        assert!(!r.status.is_terminal());
    }

    #[test]
    fn set_status_advances_lifecycle() {
        let mut r = DataSubjectRequest::new(
            "REQ-1",
            "subject-1",
            DataSubjectRequestKind::Erasure,
            "2026-04-01",
        );
        r.set_status(RequestStatus::InReview);
        assert!(matches!(r.status, RequestStatus::InReview));
        r.set_status(RequestStatus::Fulfilled("purged".into()));
        assert!(r.status.is_terminal());
    }

    #[test]
    fn register_counts_open_requests() {
        let mut reg = GdprRegister::new();
        reg.add_request(DataSubjectRequest::new(
            "REQ-1",
            "s1",
            DataSubjectRequestKind::Access,
            "2026-04-01",
        ));
        let mut r2 = DataSubjectRequest::new(
            "REQ-2",
            "s2",
            DataSubjectRequestKind::Portability,
            "2026-04-02",
        );
        r2.set_status(RequestStatus::Fulfilled("archive.zip".into()));
        reg.add_request(r2);
        assert_eq!(reg.open_request_count(), 1);
    }

    #[test]
    fn register_returns_sorted_distinct_categories() {
        let mut reg = GdprRegister::new();
        reg.add_processing(
            ProcessingRecord::new("PR-1", "Acme", "sales", LawfulBasis::Contract)
                .with_data_category("email")
                .with_data_category("phone"),
        );
        reg.add_processing(
            ProcessingRecord::new("PR-2", "Acme", "support", LawfulBasis::Consent)
                .with_data_category("email"),
        );
        let cats = reg.distinct_data_categories();
        assert_eq!(cats, vec!["email".to_string(), "phone".to_string()]);
    }

    #[test]
    fn empty_register_reports_zero_open_and_no_categories() {
        let reg = GdprRegister::new();
        assert_eq!(reg.open_request_count(), 0);
        assert!(reg.distinct_data_categories().is_empty());
    }
}
