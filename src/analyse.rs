//! Orchestration: the public [`analyse`] entry point and its forensic checks.

use std::io::{ErrorKind, Read, Seek, SeekFrom};

use crate::findings::{Anomaly, AnomalyKind, ApmAnalysis};
use crate::{parse, Error};

/// Partition map entry signature (`PM`).
const SIG_PM: &[u8; 2] = b"PM";

/// Analyse an Apple Partition Map read from a seekable image.
///
/// Reads up to `max_bytes` from the start (the APM lives in the first few
/// blocks, so a small cap such as 1 MiB suffices), then delegates to [`analyse`].
/// Composes with the container crates (`ewf`, `dmg`, `vhd`, …) that expose a
/// `Read + Seek` view of a disk image.
///
/// # Errors
/// [`Error::Io`] on a read/seek failure, or the errors of [`analyse`].
pub fn analyse_reader<R: Read + Seek>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<ApmAnalysis, Error> {
    reader.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; max_bytes];
    let mut filled = 0;
    while filled < max_bytes {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    buf.truncate(filled);
    analyse(&buf)
}

/// Perform a full forensic analysis of an Apple Partition Map.
///
/// `data` must begin at the device start (block 0 = Driver Descriptor Map). The
/// device size is taken from the self-describing `sbBlkCount` field, so no
/// separate disk-size argument is needed.
///
/// # Errors
/// [`Error::TooShort`] if `data` is under one 512-byte block; [`Error::NotApm`]
/// if it lacks the `ER`/`PM` signatures.
pub fn analyse(data: &[u8]) -> Result<ApmAnalysis, Error> {
    if data.len() < 512 {
        return Err(Error::TooShort {
            need: 512,
            got: data.len(),
        });
    }
    let map = parse(data).ok_or(Error::NotApm)?;
    let mut anomalies = Vec::new();

    // ── pmMapBlkCnt consistency ─────────────────────────────────────────────
    if let Some(first) = map.partitions.first() {
        let expected = first.map_count;
        for (index, p) in map.partitions.iter().enumerate() {
            if p.map_count != expected {
                anomalies.push(Anomaly::new(AnomalyKind::MapCountMismatch {
                    index,
                    found: p.map_count,
                    expected,
                }));
            }
        }
    }

    // ── Per-partition geometry ──────────────────────────────────────────────
    let device_last_block = map.device_block_count.checked_sub(1);
    for (index, p) in map.partitions.iter().enumerate() {
        if p.block_count == 0 {
            anomalies.push(Anomaly::new(AnomalyKind::ZeroLengthPartition { index }));
        }
        if let Some(dl) = device_last_block {
            if p.end_block() > dl {
                anomalies.push(Anomaly::new(AnomalyKind::PartitionOutOfBounds {
                    index,
                    last_block: p.end_block(),
                    device_last_block: dl,
                }));
            }
        }
    }

    // ── Overlaps (non-empty partitions only) ────────────────────────────────
    for a in 0..map.partitions.len() {
        for b in (a + 1)..map.partitions.len() {
            let (pa, pb) = (&map.partitions[a], &map.partitions[b]);
            if pa.block_count == 0 || pb.block_count == 0 {
                continue;
            }
            if pa.start_block <= pb.end_block() && pb.start_block <= pa.end_block() {
                anomalies.push(Anomaly::new(AnomalyKind::OverlappingPartitions { a, b }));
            }
        }
    }

    // ── Partition types (knowledge from forensicnomicon) ────────────────────
    if !map
        .partitions
        .iter()
        .any(|p| p.type_name == forensicnomicon::apm::PARTITION_MAP_TYPE)
    {
        anomalies.push(Anomaly::new(AnomalyKind::NoPartitionMapEntry));
    }
    for (index, p) in map.partitions.iter().enumerate() {
        if !forensicnomicon::apm::is_known_type(&p.type_name) {
            anomalies.push(Anomaly::new(AnomalyKind::UnknownPartitionType {
                index,
                type_name: p.type_name.clone(),
            }));
        }
    }

    // ── Unmapped interior regions (hidden space) ────────────────────────────
    // An APM covers the whole device; a gap between adjacent partitions is
    // unaccounted space. Trailing/leading gaps are not flagged (often benign).
    let mut extents: Vec<(u32, u32)> = map
        .partitions
        .iter()
        .filter(|p| p.block_count > 0)
        .map(|p| (p.start_block, p.end_block()))
        .collect();
    extents.sort_unstable();
    for pair in extents.windows(2) {
        let (_, prev_end) = pair[0];
        let (next_start, _) = pair[1];
        if next_start > prev_end.saturating_add(1) {
            anomalies.push(Anomaly::new(AnomalyKind::UnmappedRegion {
                start_block: prev_end + 1,
                end_block: next_start - 1,
            }));
        }
    }

    // ── Residual entry: a PM signature beyond the declared map count ─────────
    if let Some(first) = map.partitions.first() {
        let declared = first.map_count as usize;
        let off = (map.block_size as usize).saturating_mul(1 + declared);
        if off + 2 <= data.len() && &data[off..off + 2] == SIG_PM {
            anomalies.push(Anomaly::new(AnomalyKind::ResidualEntry {
                block: (1 + declared) as u32,
            }));
        }
    }

    Ok(ApmAnalysis {
        block_size: map.block_size,
        device_block_count: map.device_block_count,
        partitions: map.partitions,
        anomalies,
    })
}
