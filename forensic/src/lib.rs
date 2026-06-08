//! Forensic anomaly auditor for Apple Partition Maps.
//!
//! Reads partition-map geometry via the [`apm`] parser crate and grades it into
//! severity-ranked findings on the shared [`forensicnomicon::report`] model.
//! Each finding is an *observation* ("consistent with …"); the examiner draws
//! the conclusions.
//!
//! The forensic checks (overlaps, out-of-bounds, map-count inconsistency,
//! residual/hidden entries, unmapped regions) live in [`analyse`]; the finding
//! types live in [`findings`].

// Production code is panic-free (enforced by the workspace lints); tests opt out.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod findings;

mod analyse;
pub use analyse::{analyse, analyse_reader};
pub use findings::{Anomaly, AnomalyKind, ApmAnalysis, Severity};

// Re-export the parser surface so `apm-forensic`'s public API is unchanged:
// callers keep using `apm_forensic::{Error, ApmPartition, ApplePartitionMap, parse}`.
pub use apm::{parse, ApmPartition, ApplePartitionMap, Error};
