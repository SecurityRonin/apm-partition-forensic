//! apm-forensic anomalies normalize onto the canonical `forensicnomicon::report`
//! model via the `Observation` producer trait.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apm_partition_forensic::{Anomaly, AnomalyKind, ApmAnalysis, Severity};
use forensicnomicon::report::{Evidence, Location, Observation, Source};

#[test]
fn anomaly_converts_to_a_canonical_finding() {
    let a = Anomaly::new(AnomalyKind::NoPartitionMapEntry);
    let f = a.to_finding(Source {
        analyzer: "apm-forensic".to_string(),
        scope: "APM".to_string(),
        version: None,
    });
    assert_eq!(f.code, "APM-NO-MAP-ENTRY");
    assert!(f.severity.is_some());
    assert_eq!(f.source.analyzer, "apm-forensic");
}

#[test]
fn anomaly_evidence_carries_its_block_location() {
    let a = Anomaly::new(AnomalyKind::PartitionOutOfBounds {
        index: 1,
        last_block: 6200,
        device_last_block: 6143,
    });
    let ev = a.evidence();
    assert!(
        ev.iter()
            .any(|e| matches!(e.location, Some(Location::Lba(6200)))),
        "out-of-bounds partition should surface its last_block as an Lba location: {ev:?}"
    );
}

/// Every `AnomalyKind` must render a non-panicking `evidence()` vector; the
/// block-addressed kinds surface an `Lba` location, the summary kinds surface a
/// locationless `Evidence`, and `NoPartitionMapEntry` carries none.
#[test]
fn evidence_covers_every_anomaly_kind() {
    let lba = |ev: &[Evidence]| {
        ev.iter()
            .filter_map(|e| match e.location {
                Some(Location::Lba(b)) => Some(b),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    // Block-addressed kinds → Lba(block).
    assert_eq!(
        lba(&Anomaly::new(AnomalyKind::ResidualEntry { block: 2 }).evidence()),
        vec![2]
    );
    assert_eq!(
        lba(&Anomaly::new(AnomalyKind::UnmappedRegion {
            start_block: 10,
            end_block: 20,
        })
        .evidence()),
        vec![10]
    );

    // Summary kinds → a single locationless Evidence carrying the detail.
    for (kind, needle) in [
        (
            AnomalyKind::MapCountMismatch {
                index: 1,
                found: 9,
                expected: 2,
            },
            "found 9",
        ),
        (AnomalyKind::OverlappingPartitions { a: 0, b: 1 }, "0 & 1"),
        (AnomalyKind::ZeroLengthPartition { index: 3 }, "3"),
        (
            AnomalyKind::UnknownPartitionType {
                index: 2,
                type_name: "Sneaky".to_string(),
            },
            "Sneaky",
        ),
    ] {
        let ev = Anomaly::new(kind).evidence();
        assert_eq!(ev.len(), 1, "summary kind emits one Evidence: {ev:?}");
        assert!(ev[0].location.is_none(), "summary kind is locationless");
        assert!(
            ev.iter().any(|e| e.value.contains(needle)),
            "evidence should mention {needle:?}: {ev:?}"
        );
    }

    // The self-describing-absence kind carries no evidence.
    assert!(Anomaly::new(AnomalyKind::NoPartitionMapEntry)
        .evidence()
        .is_empty());
}

/// `Anomaly`'s `Display` renders `[severity] code: note`.
#[test]
fn anomaly_display_renders_severity_code_and_note() {
    let a = Anomaly::new(AnomalyKind::OverlappingPartitions { a: 0, b: 1 });
    let s = a.to_string();
    assert!(s.contains("APM-PART-OVERLAP"), "shows the code: {s}");
    assert!(s.contains(&a.note), "shows the note: {s}");
    assert!(s.starts_with('['), "leads with the bracketed severity: {s}");
}

/// `ApmAnalysis::max_severity` is the maximum over anomalies, `None` when clean.
#[test]
fn max_severity_is_max_of_anomalies_and_none_when_clean() {
    let clean = ApmAnalysis {
        block_size: 512,
        device_block_count: 1000,
        partitions: Vec::new(),
        anomalies: Vec::new(),
    };
    assert_eq!(clean.max_severity(), None);

    let graded = ApmAnalysis {
        block_size: 512,
        device_block_count: 1000,
        partitions: Vec::new(),
        anomalies: vec![
            Anomaly::new(AnomalyKind::UnknownPartitionType {
                index: 0,
                type_name: "x".to_string(),
            }), // Info
            Anomaly::new(AnomalyKind::OverlappingPartitions { a: 0, b: 1 }), // Critical
            Anomaly::new(AnomalyKind::ZeroLengthPartition { index: 1 }),     // Low
        ],
    };
    assert_eq!(graded.max_severity(), Some(Severity::Critical));
}
