//! Text report rendering (backs the `apm-forensic` CLI binary).

use apm_forensic::{analyse, report::text_report};

/// Build a minimal valid APM: DDR ("ER") + one "PM" entry.
fn build_apm() -> Vec<u8> {
    let bs = 512usize;
    let mut disk = vec![0u8; bs * 8];
    // Driver Descriptor Record.
    disk[0..2].copy_from_slice(b"ER");
    disk[2..4].copy_from_slice(&(bs as u16).to_be_bytes());
    disk[4..8].copy_from_slice(&8u32.to_be_bytes());
    // Partition map entry at block 1.
    let p = bs;
    disk[p..p + 2].copy_from_slice(b"PM");
    disk[p + 4..p + 8].copy_from_slice(&1u32.to_be_bytes()); // map count
    disk[p + 8..p + 12].copy_from_slice(&1u32.to_be_bytes()); // start block
    disk[p + 12..p + 16].copy_from_slice(&7u32.to_be_bytes()); // block count
    let name = b"Macintosh";
    disk[p + 16..p + 16 + name.len()].copy_from_slice(name);
    let ty = b"Apple_partition_map";
    disk[p + 48..p + 48 + ty.len()].copy_from_slice(ty);
    disk
}

#[test]
fn report_includes_header_and_partitions() {
    let a = analyse(&build_apm()).unwrap();
    let r = text_report(&a);
    assert!(r.contains("APM Forensic Analysis"), "{r}");
    assert!(r.contains("Macintosh"), "partition name should appear:\n{r}");
    assert!(r.contains("Apple_partition_map"), "type should appear:\n{r}");
    assert!(r.contains("block size"), "{r}");
}

#[test]
fn report_renders_anomaly_codes() {
    // Force an out-of-bounds partition: device is 8 blocks but the entry claims
    // 100 blocks starting at block 1 → end block 100 > 8 → APM-PART-OOB.
    let mut disk = build_apm();
    disk[512 + 12..512 + 16].copy_from_slice(&100u32.to_be_bytes());
    let a = analyse(&disk).unwrap();
    let r = text_report(&a);
    assert!(r.contains("APM-"), "anomaly codes should appear:\n{r}");
}
