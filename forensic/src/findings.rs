//! Forensic finding types for Apple Partition Map analysis.
//!
//! Mirrors the model in `mbr-forensic` / `gpt-forensic`: every anomaly's
//! severity, stable code, and human note are derived from its [`AnomalyKind`],
//! so they cannot drift out of sync.

use core::fmt;

use apm::ApmPartition;

/// The canonical 5-level severity scale, shared across every `SecurityRonin`
/// analyzer via [`forensicnomicon::report`].
pub use forensicnomicon::report::Severity;

impl forensicnomicon::report::Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn evidence(&self) -> Vec<forensicnomicon::report::Evidence> {
        use forensicnomicon::report::{Evidence, Location};
        // APM addresses everything in logical device blocks.
        let at = |field: String, value: String, block: u32| Evidence {
            field,
            value,
            location: Some(Location::Lba(u64::from(block))),
        };
        match &self.kind {
            AnomalyKind::PartitionOutOfBounds {
                index,
                last_block,
                device_last_block,
            } => vec![at(
                format!("partition {index} last block"),
                format!("{last_block} past device end {device_last_block}"),
                *last_block,
            )],
            AnomalyKind::ResidualEntry { block } => vec![at(
                "residual map entry".to_string(),
                format!("block {block}"),
                *block,
            )],
            AnomalyKind::UnmappedRegion {
                start_block,
                end_block,
            } => vec![at(
                "unmapped region".to_string(),
                format!("blocks {start_block}..={end_block}"),
                *start_block,
            )],
            AnomalyKind::MapCountMismatch {
                index,
                found,
                expected,
            } => vec![Evidence {
                field: format!("map entry {index} count"),
                value: format!("found {found}, expected {expected}"),
                location: None,
            }],
            AnomalyKind::OverlappingPartitions { a, b } => vec![Evidence {
                field: "partitions".to_string(),
                value: format!("{a} & {b}"),
                location: None,
            }],
            AnomalyKind::ZeroLengthPartition { index } => vec![Evidence {
                field: "partition".to_string(),
                value: index.to_string(),
                location: None,
            }],
            AnomalyKind::UnknownPartitionType { index, type_name } => vec![Evidence {
                field: format!("partition {index} type"),
                value: type_name.clone(),
                location: None,
            }],
            AnomalyKind::NoPartitionMapEntry => Vec::new(),
        }
    }
}

/// Classification of an APM anomaly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum AnomalyKind {
    /// A partition entry's `pmMapBlkCnt` disagrees with the first entry's — every
    /// entry must report the same map block count, so this is corruption/tampering.
    MapCountMismatch {
        index: usize,
        found: u32,
        expected: u32,
    },
    /// Two partitions claim overlapping block ranges.
    OverlappingPartitions { a: usize, b: usize },
    /// A partition extends beyond the device's block count.
    PartitionOutOfBounds {
        index: usize,
        last_block: u32,
        device_last_block: u32,
    },
    /// A `PM`-signature entry exists beyond the declared map count — a hidden or
    /// residual partition entry.
    ResidualEntry { block: u32 },
    /// A partition has a zero block count.
    ZeroLengthPartition { index: usize },
    /// No entry of type `Apple_partition_map` — the map must describe itself, so
    /// its absence is a structural anomaly / tampering signal.
    NoPartitionMapEntry,
    /// A partition's `pmPartType` is not a recognised APM type — possibly a
    /// custom or hidden partition.
    UnknownPartitionType { index: usize, type_name: String },
    /// A block range between two partitions is described by no entry. An APM
    /// covers the whole device (free space is an `Apple_Free` entry), so an
    /// interior gap is unaccounted/hidden space.
    UnmappedRegion { start_block: u32, end_block: u32 },
}

impl AnomalyKind {
    /// Severity assigned to this kind — the single source of truth.
    #[must_use]
    pub fn severity(&self) -> Severity {
        use AnomalyKind as K;
        match self {
            K::OverlappingPartitions { .. } => Severity::Critical,
            K::PartitionOutOfBounds { .. } | K::ResidualEntry { .. } | K::NoPartitionMapEntry => {
                Severity::High
            }
            K::MapCountMismatch { .. } | K::UnmappedRegion { .. } => Severity::Medium,
            K::ZeroLengthPartition { .. } => Severity::Low,
            K::UnknownPartitionType { .. } => Severity::Info,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        use AnomalyKind as K;
        match self {
            K::MapCountMismatch { .. } => "APM-MAP-COUNT",
            K::OverlappingPartitions { .. } => "APM-PART-OVERLAP",
            K::PartitionOutOfBounds { .. } => "APM-PART-OOB",
            K::ResidualEntry { .. } => "APM-PART-RESIDUAL",
            K::ZeroLengthPartition { .. } => "APM-PART-ZEROLEN",
            K::NoPartitionMapEntry => "APM-NO-MAP-ENTRY",
            K::UnknownPartitionType { .. } => "APM-PART-UNKNOWN",
            K::UnmappedRegion { .. } => "APM-UNMAPPED",
        }
    }

    /// Human-readable description.
    #[must_use]
    pub fn note(&self) -> String {
        use AnomalyKind as K;
        match self {
            K::MapCountMismatch {
                index,
                found,
                expected,
            } => format!(
                "Entry {index}: pmMapBlkCnt {found} disagrees with the map's {expected} \
                 — corruption or tampering"
            ),
            K::OverlappingPartitions { a, b } => {
                format!("Partitions {a} and {b} claim overlapping block ranges")
            }
            K::PartitionOutOfBounds {
                index,
                last_block,
                device_last_block,
            } => format!(
                "Partition {index} ends at block {last_block}, beyond the device's last block \
                 {device_last_block}"
            ),
            K::ResidualEntry { block } => format!(
                "A PM partition entry exists at block {block}, beyond the declared map count \
                 — hidden or residual entry"
            ),
            K::ZeroLengthPartition { index } => format!("Partition {index} has a zero block count"),
            K::NoPartitionMapEntry => {
                "No Apple_partition_map entry — the map does not describe itself".to_string()
            }
            K::UnknownPartitionType { index, type_name } => {
                format!("Partition {index}: unrecognised type \"{type_name}\" — possibly custom or hidden")
            }
            K::UnmappedRegion {
                start_block,
                end_block,
            } => format!(
                "Blocks {start_block}–{end_block} are described by no partition entry — \
                 unaccounted/hidden space"
            ),
        }
    }
}

/// A single APM anomaly with derived severity/code/note.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Anomaly {
    pub severity: Severity,
    pub code: &'static str,
    pub kind: AnomalyKind,
    pub note: String,
}

impl Anomaly {
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.code, self.note)
    }
}

/// Result of a full APM forensic analysis.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ApmAnalysis {
    /// Device block size in bytes.
    pub block_size: u32,
    /// Device block count (from the Driver Descriptor Map).
    pub device_block_count: u32,
    /// Partition entries in map order.
    pub partitions: Vec<ApmPartition>,
    /// All detected anomalies, in discovery order.
    pub anomalies: Vec<Anomaly>,
}

impl ApmAnalysis {
    /// The highest severity among all anomalies, or `None` when clean.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.anomalies.iter().map(|a| a.severity).max()
    }
}
