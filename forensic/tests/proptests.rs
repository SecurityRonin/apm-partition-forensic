//! Property-based invariants for the APM analyser.
//!
//! Complements the `cargo fuzz` target (which only proves no-panic): these run
//! on stable CI and assert *semantic* invariants over arbitrary input.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use std::io::Cursor;

proptest! {
    /// The byte API and the `Read + Seek` API must produce identical results for
    /// any input — `analyse_reader` is only a faithful wrapper around `analyse`.
    #[test]
    fn byte_and_reader_apis_agree(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let direct = apm_partition_forensic::analyse(&data);
        let reader = apm_partition_forensic::analyse_reader(&mut Cursor::new(&data), 1 << 20);
        match (direct, reader) {
            (Ok(a), Ok(b)) => {
                prop_assert_eq!(a.block_size, b.block_size);
                prop_assert_eq!(a.device_block_count, b.device_block_count);
                prop_assert_eq!(a.partitions.len(), b.partitions.len());
                prop_assert_eq!(a.anomalies.len(), b.anomalies.len());
            }
            (Err(_), Err(_)) => {}
            (a, b) => prop_assert!(
                false,
                "API disagreement: byte={:?} reader={:?}",
                a.is_ok(),
                b.is_ok()
            ),
        }
    }

    /// No parsed partition reports an end block before its start block.
    #[test]
    fn end_block_never_precedes_start(data in proptest::collection::vec(any::<u8>(), 512..8192)) {
        if let Ok(a) = apm_partition_forensic::analyse(&data) {
            for p in &a.partitions {
                if p.block_count > 0 {
                    prop_assert!(p.end_block() >= p.start_block);
                }
            }
        }
    }
}
