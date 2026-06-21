// Apple Partition Map reader test, validated against REAL data:
// ../../tests/data/apm_map.bin (repo-root tests/data, shared across members) is
// the first 2 KiB of an `hdiutil create -layout SPUD` image (DDM + partition
// map, block size 512, Apple_partition_map + Apple_HFS).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apm_partition_forensic as apm;

fn real_map() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/data/apm_map.bin"
    ))
    .unwrap()
}

#[test]
fn parses_real_apple_partition_map() {
    let map = apm::parse(&real_map()).expect("parse real APM");
    assert_eq!(map.block_size, 512);
    assert_eq!(map.partitions.len(), 2);
    assert_eq!(map.partitions[0].type_name, "Apple_partition_map");
    assert_eq!(map.partitions[1].type_name, "Apple_HFS");
    assert_eq!(map.partitions[1].name, "disk image");
    assert_eq!(map.partitions[1].start_block, 64);
}

#[test]
fn finds_hfs_partition() {
    let map = apm::parse(&real_map()).unwrap();
    assert_eq!(map.hfs_partition().expect("Apple_HFS").start_block, 64);
}

#[test]
fn non_apm_is_none() {
    assert!(apm::parse(&[0u8; 2048]).is_none());
    assert!(apm::parse(&[0u8; 8]).is_none());
}
