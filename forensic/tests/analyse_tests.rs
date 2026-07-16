//! Forensic analysis of the Apple Partition Map.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apm_partition_forensic::{analyse, AnomalyKind, Error};

fn real_map() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/data/apm_map.bin"
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

#[test]
fn empty_map_analyses_without_the_first_entry_paths() {
    // A valid DDM + `PM` signature at block 1, but the entry declares a map count
    // of 0 → the parser yields zero partitions. Analysis must handle the empty
    // map: the map-count and residual passes skip (no first entry), and the only
    // anomaly is the missing self-describing Apple_partition_map entry.
    let mut d = vec![0u8; BS * 4];
    d[0..2].copy_from_slice(b"ER");
    d[2..4].copy_from_slice(&(BS as u16).to_be_bytes());
    d[4..8].copy_from_slice(&1000u32.to_be_bytes());
    d[BS..BS + 2].copy_from_slice(b"PM"); // block 1 PM signature, map_count = 0
    let a = analyse(&d).unwrap();
    assert!(a.partitions.is_empty(), "map declares zero entries");
    assert_eq!(
        a.anomalies.len(),
        1,
        "only the missing self-entry is flagged: {:?}",
        kinds(&d)
    );
    assert!(matches!(
        a.anomalies[0].kind,
        AnomalyKind::NoPartitionMapEntry
    ));
}

#[test]
fn zero_length_partition_is_skipped_by_the_overlap_check() {
    // A zero-length entry sits between two real ones; the overlap pass must
    // `continue` past it (never flag an empty partition as overlapping) and the
    // real neighbours do not overlap, so ZeroLength is the only geometry flag.
    let d = build(
        1000,
        &[
            ent("Apple_partition_map", 1, 63, 3),
            ent("Apple_Free", 100, 0, 3),
            ent("Apple_HFS", 100, 100, 3),
        ],
    );
    let ks = kinds(&d);
    assert!(
        ks.iter()
            .any(|a| matches!(a, AnomalyKind::ZeroLengthPartition { .. })),
        "the empty entry is flagged: {ks:?}"
    );
    assert!(
        !ks.iter()
            .any(|a| matches!(a, AnomalyKind::OverlappingPartitions { .. })),
        "an empty entry never counts as an overlap: {ks:?}"
    );
}

#[test]
fn zero_device_block_count_suppresses_out_of_bounds() {
    // device_block_count 0 → device_last_block None → the out-of-bounds check is
    // skipped entirely (the geometry is unknown), even for a huge partition.
    let d = build(0, &[ent("Apple_HFS", 64, 500, 1)]);
    let ks = kinds(&d);
    assert!(
        !ks.iter()
            .any(|a| matches!(a, AnomalyKind::PartitionOutOfBounds { .. })),
        "no device size means no out-of-bounds judgment: {ks:?}"
    );
}

#[test]
fn no_residual_when_declared_count_matches() {
    // Map declares 2 entries and exactly 2 exist; the block past the last entry
    // holds no PM signature, so the residual check's condition is false.
    let d = build(
        1000,
        &[
            ent("Apple_partition_map", 1, 63, 2),
            ent("Apple_HFS", 64, 900, 2),
        ],
    );
    assert!(
        !kinds(&d)
            .iter()
            .any(|a| matches!(a, AnomalyKind::ResidualEntry { .. })),
        "a well-formed map has no residual entry"
    );
}

#[test]
fn analyse_reader_surfaces_a_read_error() {
    use std::io::{self, Read, Seek, SeekFrom};

    /// A reader that seeks fine but errors on the first `read`.
    struct Boom;
    impl Read for Boom {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("boom"))
        }
    }
    impl Seek for Boom {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            Ok(0)
        }
    }

    let err = apm_partition_forensic::analyse_reader(&mut Boom, 4096).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "read failure surfaces as Io");
}

#[test]
fn analyse_reader_retries_on_interrupted() {
    use std::io::{self, Cursor, ErrorKind, Read, Seek, SeekFrom};

    /// Returns one `Interrupted` error, then serves the wrapped bytes — the
    /// read loop must retry rather than abort (POSIX `EINTR` semantics).
    struct Interruptor {
        inner: Cursor<Vec<u8>>,
        interrupted: bool,
    }
    impl Read for Interruptor {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::new(ErrorKind::Interrupted, "eintr"));
            }
            self.inner.read(buf)
        }
    }
    impl Seek for Interruptor {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    let data = real_map();
    let mut r = Interruptor {
        inner: Cursor::new(data),
        interrupted: false,
    };
    let a = apm_partition_forensic::analyse_reader(&mut r, 1 << 20).unwrap();
    assert_eq!(a.partitions.len(), 2, "retried past the EINTR and parsed");
}
