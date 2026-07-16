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

const BS: usize = 512;

/// A minimal DDM header (`ER` + block size + device block count) at block 0.
fn ddm(block_size: u16, device_blocks: u32) -> Vec<u8> {
    let mut d = vec![0u8; BS * 4];
    d[0..2].copy_from_slice(b"ER");
    d[2..4].copy_from_slice(&block_size.to_be_bytes());
    d[4..8].copy_from_slice(&device_blocks.to_be_bytes());
    d
}

/// Write a `PM` partition entry at block `block`, declaring `map_count` entries.
fn pm_entry(d: &mut [u8], block: usize, map_count: u32, start: u32, count: u32) {
    let off = BS * block;
    d[off..off + 2].copy_from_slice(b"PM");
    d[off + 4..off + 8].copy_from_slice(&map_count.to_be_bytes());
    d[off + 8..off + 12].copy_from_slice(&start.to_be_bytes());
    d[off + 12..off + 16].copy_from_slice(&count.to_be_bytes());
}

#[test]
fn zero_block_size_is_rejected() {
    // `ER` signature present but the DDM reports a 0-byte block size — dividing
    // by the block size would be meaningless, so the map is not accepted.
    let d = ddm(0, 100);
    assert!(apm::parse(&d).is_none());
}

#[test]
fn missing_first_pm_signature_is_rejected() {
    // Valid DDM, but block 1 carries no `PM` signature — not an APM.
    let d = ddm(BS as u16, 100);
    assert!(apm::parse(&d).is_none());
}

#[test]
fn parse_stops_at_a_truncated_or_missing_entry() {
    // The map declares 3 entries, but only the first two carry a `PM` signature;
    // parsing must break at the missing third rather than fabricate an entry.
    let mut d = ddm(BS as u16, 1000);
    pm_entry(&mut d, 1, 3, 1, 63);
    pm_entry(&mut d, 2, 3, 64, 100);
    // block 3 left blank → break.
    let map = apm::parse(&d).expect("parses the two well-formed entries");
    assert_eq!(
        map.partitions.len(),
        2,
        "stopped at the missing third entry"
    );
}
