//! apm-forensic anomalies normalize onto the canonical `forensicnomicon::report`
//! model via the `Observation` producer trait.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apm_forensic::{Anomaly, AnomalyKind};
use forensicnomicon::report::{Observation, Source};

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
    use forensicnomicon::report::Location;
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
