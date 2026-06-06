//! apm-forensic anomalies normalize onto the canonical `forensicnomicon::report`
//! model via the `Observation` producer trait.

use forensicnomicon::report::{Observation, Source};
use apm_forensic::{Anomaly, AnomalyKind};

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
