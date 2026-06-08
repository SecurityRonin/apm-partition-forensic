//! Forensic analysis of the Apple Partition Map.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apm_partition_forensic::{analyse, AnomalyKind, Error};

fn real_map() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/apm_map.bin"
    ))
    .unwrap()
}

// ── Builders for synthetic APM images ────────────────────────────────────────

const BS: usize = 512;

struct Ent {
    type_name: &'static str,
    start: u32,
    count: u32,
    map_count: u32,
}

fn build(device_blocks: u32, entries: &[Ent]) -> Vec<u8> {
    let total = BS * (1 + entries.len() + 2);
    let mut d = vec![0u8; total];
    d[0..2].copy_from_slice(b"ER");
    d[2..4].copy_from_slice(&(BS as u16).to_be_bytes());
    d[4..8].copy_from_slice(&device_blocks.to_be_bytes());
    for (i, e) in entries.iter().enumerate() {
        let off = BS * (1 + i);
        d[off..off + 2].copy_from_slice(b"PM");
        d[off + 4..off + 8].copy_from_slice(&e.map_count.to_be_bytes());
        d[off + 8..off + 12].copy_from_slice(&e.start.to_be_bytes());
        d[off + 12..off + 16].copy_from_slice(&e.count.to_be_bytes());
        let ty = e.type_name.as_bytes();
        d[off + 48..off + 48 + ty.len()].copy_from_slice(ty);
    }
    d
}

fn ent(type_name: &'static str, start: u32, count: u32, n: u32) -> Ent {
    Ent {
        type_name,
        start,
        count,
        map_count: n,
    }
}

fn kinds(d: &[u8]) -> Vec<AnomalyKind> {
    analyse(d)
        .unwrap()
        .anomalies
        .into_iter()
        .map(|a| a.kind)
        .collect()
}

// ── Real data ────────────────────────────────────────────────────────────────

#[test]
fn analyse_reader_matches_byte_api() {
    use std::io::Cursor;
    let data = real_map();
    let a = apm_partition_forensic::analyse_reader(&mut Cursor::new(&data), 1 << 20).unwrap();
    assert_eq!(a.partitions.len(), 2);
    assert!(a.anomalies.is_empty());
}

#[test]
fn real_apm_is_clean() {
    let a = analyse(&real_map()).unwrap();
    assert_eq!(a.partitions.len(), 2);
    assert!(
        a.anomalies.is_empty(),
        "real APM must be clean, got: {:?}",
        a.anomalies.iter().map(|x| x.code).collect::<Vec<_>>()
    );
}

#[test]
fn non_apm_errors() {
    assert!(matches!(
        analyse(&[0u8; 8]),
        Err(Error::TooShort { need: 512, got: 8 })
    ));
    assert!(matches!(analyse(&[0u8; 1024]), Err(Error::NotApm)));
}

// ── Anomalies ────────────────────────────────────────────────────────────────

#[test]
fn well_formed_synthetic_is_clean() {
    let d = build(
        1000,
        &[
            ent("Apple_partition_map", 1, 63, 2),
            ent("Apple_HFS", 64, 900, 2),
        ],
    );
    assert!(
        analyse(&d).unwrap().anomalies.is_empty(),
        "got {:?}",
        kinds(&d)
    );
}

#[test]
fn overlapping_partitions_flagged() {
    let d = build(
        1000,
        &[ent("Apple_HFS", 64, 500, 2), ent("Apple_HFS", 300, 400, 2)],
    );
    assert!(kinds(&d)
        .iter()
        .any(|a| matches!(a, AnomalyKind::OverlappingPartitions { .. })));
}

#[test]
fn out_of_bounds_flagged() {
    // Device has 100 blocks; partition runs to block 563.
    let d = build(100, &[ent("Apple_HFS", 64, 500, 1)]);
    assert!(kinds(&d)
        .iter()
        .any(|a| matches!(a, AnomalyKind::PartitionOutOfBounds { .. })));
}

#[test]
fn map_count_mismatch_flagged() {
    // Two entries that disagree on pmMapBlkCnt.
    let d = build(
        1000,
        &[
            ent("Apple_partition_map", 1, 63, 2),
            ent("Apple_HFS", 64, 100, 9),
        ],
    );
    assert!(kinds(&d)
        .iter()
        .any(|a| matches!(a, AnomalyKind::MapCountMismatch { .. })));
}

#[test]
fn residual_entry_flagged() {
    // Map declares 1 entry, but a PM signature lurks at block 2.
    let mut d = build(1000, &[ent("Apple_HFS", 64, 100, 1)]);
    let off = BS * 2;
    d[off..off + 2].copy_from_slice(b"PM");
    assert!(kinds(&d)
        .iter()
        .any(|a| matches!(a, AnomalyKind::ResidualEntry { .. })));
}

#[test]
fn missing_partition_map_self_entry_flagged() {
    // No Apple_partition_map entry — the map must describe itself.
    let d = build(1000, &[ent("Apple_HFS", 64, 100, 1)]);
    assert!(kinds(&d)
        .iter()
        .any(|a| matches!(a, AnomalyKind::NoPartitionMapEntry)));
}

#[test]
fn unknown_partition_type_flagged() {
    let d = build(
        1000,
        &[
            ent("Apple_partition_map", 1, 63, 2),
            ent("Sneaky_Hidden_Type", 64, 100, 2),
        ],
    );
    assert!(kinds(&d)
        .iter()
        .any(|a| matches!(a, AnomalyKind::UnknownPartitionType { .. })));
}

#[test]
fn unmapped_region_between_partitions_flagged() {
    // Blocks 64..99 are described by no partition — APM covers the whole disk
    // (free space is an Apple_Free entry), so an interior gap is hidden space.
    let d = build(
        1000,
        &[
            ent("Apple_partition_map", 1, 63, 2),
            ent("Apple_HFS", 100, 100, 2),
        ],
    );
    assert!(kinds(&d)
        .iter()
        .any(|a| matches!(a, AnomalyKind::UnmappedRegion { .. })));
}

#[test]
fn zero_length_partition_flagged() {
    let d = build(1000, &[ent("Apple_Free", 64, 0, 1)]);
    assert!(kinds(&d)
        .iter()
        .any(|a| matches!(a, AnomalyKind::ZeroLengthPartition { .. })));
}
