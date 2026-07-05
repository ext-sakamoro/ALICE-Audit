//! ALICE-Audit: Audit trail + GDPR compliance.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::too_many_arguments,
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::wildcard_imports,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::return_self_not_must_use
)]

pub mod actor;
pub mod event;
pub mod gdpr;
pub mod prelude;
pub mod query;
pub mod report;
pub mod retention;
pub mod severity;
pub mod signed_trail;
pub mod trail;

#[cfg(test)]
mod integration_tests;

pub use crate::actor::*;
pub use crate::event::*;
pub use crate::query::*;
pub use crate::report::*;
pub use crate::retention::*;
pub use crate::severity::*;
pub use crate::trail::*;
