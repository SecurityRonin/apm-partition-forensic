//! `forensic-vfs` [`VolumeSystem`] adapter for the Apple Partition Map, behind
//! the `vfs` feature.
//!
//! Wraps a parent [`ImageSource`](forensic_vfs::ImageSource) and exposes the
//! disk's APM partitions as [`VolumeDesc`]s, each openable as a [`SubRange`]
//! byte window. Partition geometry is in the map's own block units
//! ([`ApplePartitionMap::block_size`](crate::ApplePartitionMap), from the Driver
//! Descriptor Map — typically 512).

use std::sync::Arc;

use forensic_vfs::adapters::SubRange;
use forensic_vfs::{DynSource, VfsError, VfsResult, VolumeDesc, VolumeScheme, VolumeSystem};

/// An APM partition scheme over one parent byte source.
pub struct ApmVolumes {
    parent: DynSource,
    volumes: Vec<VolumeDesc>,
}

impl ApmVolumes {
    /// Parse the APM at the head of `parent` and build the volume table.
    pub fn open(parent: DynSource) -> VfsResult<Self> {
        // RED: not implemented yet — no partitions parsed.
        Ok(Self {
            parent,
            volumes: Vec::new(),
        })
    }
}

impl VolumeSystem for ApmVolumes {
    fn scheme(&self) -> VolumeScheme {
        VolumeScheme::Apm
    }

    fn volumes(&self) -> &[VolumeDesc] {
        &self.volumes
    }

    fn open_volume(&self, index: usize) -> VfsResult<DynSource> {
        let v = self.volumes.get(index).ok_or(VfsError::OutOfRange {
            what: "apm volume index",
            offset: index as u64,
            len: 1,
            bound: self.volumes.len() as u64,
        })?;
        Ok(Arc::new(SubRange::new(self.parent.clone(), v.start, v.len)))
    }
}

#[cfg(test)]
mod tests {
    use super::ApmVolumes;
    use forensic_vfs::adapters::FileSource;
    use forensic_vfs::{DynSource, VolumeKind, VolumeScheme, VolumeSystem};
    use std::sync::Arc;

    /// The real Apple `hdiutil`-authored APM head (32 KiB), whose table `mmls -t
    /// mac` 4.12.1 and `pdisk -dump` independently re-decoded (Tier-1 oracle; see
    /// `tests/data/README.md`).
    fn real_apm() -> DynSource {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/apm_map_32k.bin");
        Arc::new(FileSource::open(path).expect("open real APM fixture"))
    }

    #[test]
    fn apm_volumes_match_mmls_pdisk_oracle() {
        let vs = ApmVolumes::open(real_apm()).expect("real APM must parse");
        assert_eq!(vs.scheme(), VolumeScheme::Apm);

        let vols = vs.volumes();
        assert_eq!(vols.len(), 2, "map + HFS partitions");

        // Oracle answer key (block size 512): start = start_block*512.
        // 0: Apple_partition_map  start_block 1,  63 blocks
        assert_eq!(vols[0].kind, VolumeKind::Partition);
        assert_eq!(vols[0].start, 512);
        assert_eq!(vols[0].len, 63 * 512);
        assert_eq!(vols[0].type_hint.as_deref(), Some("Apple_partition_map"));
        // 1: Apple_HFS  name "disk image"  start_block 64,  16320 blocks
        assert_eq!(vols[1].start, 64 * 512);
        assert_eq!(vols[1].len, 16320 * 512);
        assert_eq!(vols[1].type_hint.as_deref(), Some("Apple_HFS"));
        assert_eq!(vols[1].label.as_deref(), Some("disk image"));
    }

    #[test]
    fn open_volume_windows_the_map_partition() {
        let parent = real_apm();
        let vs = ApmVolumes::open(parent.clone()).expect("parse");
        // The map partition [512, 32768) lies entirely within the 32 KiB head.
        let map = vs.open_volume(0).expect("open map volume");
        assert_eq!(map.len(), 63 * 512);
        let mut win = [0u8; 16];
        assert_eq!(map.read_at(0, &mut win).expect("read window"), 16);
        let mut par = [0u8; 16];
        parent.read_at(512, &mut par).expect("read parent");
        assert_eq!(win, par);
    }

    #[test]
    fn open_volume_out_of_range_errors_not_panics() {
        let vs = ApmVolumes::open(real_apm()).expect("parse");
        assert!(vs.open_volume(99).is_err());
    }
}
