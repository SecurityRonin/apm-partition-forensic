//! Fuzz target: feed arbitrary bytes to the Apple Partition Map parser.
//!
//! Invariants: never panics; returns `None` or a well-formed `ApplePartitionMap`
//! whose fields are all accessible without panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(map) = apm::parse(data) {
        let _ = map.block_size;
        let _ = map.device_block_count;
        let _ = map.hfs_partition();
        for p in &map.partitions {
            let _ = &p.name;
            let _ = &p.type_name;
            let _ = p.end_block();
        }
    }
});
