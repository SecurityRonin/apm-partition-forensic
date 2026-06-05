//! Apple Partition Map (APM) detection.
//!
//! Apple hybrid optical discs carry an Apple Partition Map so a Mac sees the
//! disc's partitions (typically an `Apple_HFS` slice alongside the ISO 9660
//! filesystem).  The layout (Inside Macintosh: Devices) is big-endian, in
//! fixed-size device blocks: block 0 is the Driver Descriptor Map (signature
//! `ER`, carrying the block size), and blocks 1.. are partition entries
//! (signature `PM`), the first of which reports how many entries the map holds.
//!
//! This module reads the map for *detection and partition geometry* (name,
//! type, start block, block count).  Validated against a real `hdiutil` APM.
//!
//! For forensic anomaly detection (overlaps, out-of-bounds, map-count
//! inconsistency, residual/hidden entries) see [`analyse`] and the
//! [`findings`] module.

pub mod findings;

mod analyse;
pub use analyse::{analyse, analyse_reader};
pub use findings::{Anomaly, AnomalyKind, ApmAnalysis, Severity};

/// Crate-level error type. (Manual impl — no `thiserror` dependency.)
#[derive(Debug)]
pub enum Error {
    /// The buffer did not begin with the Driver Descriptor Map `ER` signature,
    /// or the first partition entry lacked the `PM` signature.
    NotApm,
    /// The buffer was shorter than the structure it was asked to hold.
    TooShort { need: usize, got: usize },
    /// I/O failure while reading the disk image (from [`analyse_reader`]).
    Io(std::io::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotApm => f.write_str("not an Apple Partition Map (missing ER/PM signature)"),
            Error::TooShort { need, got } => {
                write!(f, "buffer too short: need {need} bytes, got {got}")
            }
            Error::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Driver Descriptor Map signature (`ER`).
const SIG_DDM: &[u8; 2] = b"ER";
/// Partition map entry signature (`PM`).
const SIG_PM: &[u8; 2] = b"PM";
/// Cap on partition entries, guarding against a corrupt map.
const MAX_PARTITIONS: u32 = 256;

/// One Apple Partition Map entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ApmPartition {
    /// Partition name (`pmPartName`), e.g. `"disk image"`.
    pub name: String,
    /// Partition type (`pmPartType`), e.g. `"Apple_HFS"`.
    pub type_name: String,
    /// Physical start block of the partition (`pmPyPartStart`).
    pub start_block: u32,
    /// Partition length in blocks (`pmPartBlkCnt`).
    pub block_count: u32,
    /// Number of blocks in the partition map, as recorded by *this* entry
    /// (`pmMapBlkCnt`). Every entry should report the same value.
    pub map_count: u32,
    /// Partition status bits (`pmPartStatus`).
    pub status: u32,
}

impl ApmPartition {
    /// Inclusive last block of this partition, saturating on overflow.
    #[must_use]
    pub fn end_block(&self) -> u32 {
        self.start_block
            .saturating_add(self.block_count)
            .saturating_sub(1)
    }
}

/// A parsed Apple Partition Map.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ApplePartitionMap {
    /// Device block size in bytes (from the Driver Descriptor Map).
    pub block_size: u32,
    /// Number of blocks on the device (`sbBlkCount` in the Driver Descriptor Map).
    pub device_block_count: u32,
    /// Partition entries in map order.
    pub partitions: Vec<ApmPartition>,
}

impl ApplePartitionMap {
    /// The first `Apple_HFS` (or HFS+) partition, if any.
    #[must_use]
    pub fn hfs_partition(&self) -> Option<&ApmPartition> {
        self.partitions
            .iter()
            .find(|p| p.type_name.starts_with("Apple_HFS"))
    }
}

/// Parse an Apple Partition Map from a buffer beginning at the device start
/// (block 0 = Driver Descriptor Map).  Returns `None` without the `ER`/`PM`
/// signatures or if the buffer is too short.
#[must_use]
pub fn parse(data: &[u8]) -> Option<ApplePartitionMap> {
    if data.len() < 512 || &data[0..2] != SIG_DDM {
        return None;
    }
    let block_size = u32::from(be16(&data[2..4]));
    let device_block_count = be32(&data[4..8]);
    let bs = block_size as usize;
    if bs == 0 {
        return None;
    }
    // First partition entry sits at block 1 and reports the map's entry count.
    let first = bs;
    if data.len() < first + 8 || &data[first..first + 2] != SIG_PM {
        return None;
    }
    let map_count = be32(&data[first + 4..first + 8]).min(MAX_PARTITIONS);

    let mut partitions = Vec::new();
    for i in 0..map_count {
        let off = bs * (1 + i as usize);
        if data.len() < off + 92 || &data[off..off + 2] != SIG_PM {
            break;
        }
        partitions.push(ApmPartition {
            map_count: be32(&data[off + 4..off + 8]),
            start_block: be32(&data[off + 8..off + 12]),
            block_count: be32(&data[off + 12..off + 16]),
            name: cstr(&data[off + 16..off + 48]),
            type_name: cstr(&data[off + 48..off + 80]),
            status: be32(&data[off + 88..off + 92]),
        });
    }
    Some(ApplePartitionMap {
        block_size,
        device_block_count,
        partitions,
    })
}

/// Decode a fixed-width NUL-terminated ASCII field.
fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes[..end].iter().map(|&b| b as char).collect()
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
