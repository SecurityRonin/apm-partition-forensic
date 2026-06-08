//! Fuzz target: full analyse pipeline on arbitrary bytes.
//!
//! Invariants: never panics; returns `Ok` or a well-typed `Err`; all fields of
//! `ApmAnalysis` are accessible without panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match apm_forensic::analyse(data) {
        Ok(a) => {
            let _ = a.block_size;
            let _ = a.device_block_count;
            let _ = a.max_severity();
            for p in &a.partitions {
                let _ = &p.name;
                let _ = &p.type_name;
                let _ = p.end_block();
            }
            for an in &a.anomalies {
                let _ = an.severity;
                let _ = &an.note;
            }
        }
        Err(apm_forensic::Error::NotApm) => {}
        Err(apm_forensic::Error::TooShort { .. }) => {}
        Err(apm_forensic::Error::Io(_)) => {}
    }
});
