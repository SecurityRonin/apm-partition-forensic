//! Human-readable text rendering of an [`ApmAnalysis`].
//!
//! Dependency-free `String` building so the `apm-forensic` binary needs no
//! formatting crates. Machine-readable output is available via the `serde`
//! feature (`serde_json::to_string(&analysis)`).

use core::fmt::Write as _;

use crate::findings::ApmAnalysis;

/// Render an APM forensic analysis as a multi-line text report.
#[must_use]
pub fn text_report(a: &ApmAnalysis) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "APM Forensic Analysis");
    let _ = writeln!(s, "  block size     : {} bytes", a.block_size);
    let _ = writeln!(s, "  device blocks  : {}", a.device_block_count);

    let _ = writeln!(s, "\nPartition map ({} entries):", a.partitions.len());
    if a.partitions.is_empty() {
        let _ = writeln!(s, "  (no partition entries)");
    }
    for (i, p) in a.partitions.iter().enumerate() {
        let _ = writeln!(
            s,
            "  [{}] {:<20} {:<24} blocks {:>10}..={:<10}",
            i,
            p.name,
            p.type_name,
            p.start_block,
            p.end_block(),
        );
    }

    if a.anomalies.is_empty() {
        let _ = writeln!(s, "\nAnomalies: none");
    } else {
        let _ = writeln!(s, "\nAnomalies ({}):", a.anomalies.len());
        for an in &a.anomalies {
            let _ = writeln!(s, "  {an}");
        }
    }

    match a.max_severity() {
        Some(sev) => {
            let _ = writeln!(s, "\nHighest severity: {sev}");
        }
        None => {
            let _ = writeln!(s, "\nHighest severity: none (clean)");
        }
    }
    s
}
