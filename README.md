[![Crates.io](https://img.shields.io/crates/v/apm-partition-forensic.svg)](https://crates.io/crates/apm-partition-forensic)
[![docs.rs](https://img.shields.io/docsrs/apm-partition-forensic)](https://docs.rs/apm-partition-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/apm-partition-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/apm-partition-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust forensic Apple Partition Map (APM) reader — Driver Descriptor Map and partition entries from a byte buffer.**

Reads the partition scheme on Apple hybrid optical discs and APM-formatted media, with no `unsafe` — and goes beyond enumeration to flag the structural anomalies a forensic examiner cares about: map-count mismatches, overlapping or out-of-bounds partitions, residual (deleted) entries, and unmapped regions that could hide data.

```text
APM Forensic Analysis
  block size     : 512 bytes
  device blocks  : 6144

Partition map (2 entries):
  [0] Apple                Apple_partition_map      blocks          1..=63
  [1] disk image           Apple_HFS                blocks         64..=6143

Anomalies: none

Highest severity: none (clean)
```

`apm-partition-forensic` is a **library**. For a ready-made command line that
auto-detects the scheme and prints this for *any* disk, install the unified
[`disk4n6`](https://github.com/SecurityRonin/disk-forensic) tool
(`cargo install disk-forensic`).

The workspace ships two crates: the pure parser
[`apm-partition-core`](https://crates.io/crates/apm-partition-core) (imported as
`apm`) and the forensic analyzer `apm-partition-forensic` (imported as
`apm_forensic`) built on top of it.

## Install

```toml
[dependencies]
apm-partition-forensic = "0.4"
```

## Quick start

```rust
// `data` begins at the device's first byte (block 0 = Driver Descriptor Map).
let data: Vec<u8> = std::fs::read("disk.img")?;

if let Some(map) = apm_forensic::parse(&data) {
    println!("{}-byte blocks, {} partitions", map.block_size, map.partitions.len());
    for p in &map.partitions {
        println!("  {:<24} {}  start {} ({} blocks)", p.type_name, p.name, p.start_block, p.block_count);
    }
    if let Some(hfs) = map.hfs_partition() {
        println!("Apple_HFS at block {}", hfs.start_block);
    }
}
```

## What it parses

| Capability | Notes |
|---|---|
| Driver Descriptor Map | `ER` signature, device block size |
| Partition entries | `PM` entries: name, type, start block, block count |
| HFS lookup | `hfs_partition()` finds the first `Apple_HFS` slice |

## Forensic anomaly detection

`parse()` gives you the layout; `analyse()` (byte slice) and `analyse_reader()`
(any `Read + Seek`, for composing with container crates) add a severity-ranked
anomaly pass:

```rust
let report = apm_forensic::analyse(&std::fs::read("disk.img")?)?;
for a in &report.anomalies {
    println!("[{}] {}: {}", a.severity, a.code, a.note);
}
# Ok::<(), apm_forensic::Error>(())
```

| Anomaly | Code | Severity |
|---|---|---|
| Overlapping partitions | `APM-PART-OVERLAP` | Critical |
| Partition out of bounds | `APM-PART-OOB` | High |
| Residual (deleted) entry | `APM-PART-RESIDUAL` | High |
| Missing `Apple_partition_map` self-entry | `APM-NO-MAP-ENTRY` | High |
| `pmMapBlkCnt` disagreement | `APM-MAP-COUNT` | Medium |
| Unmapped region (possible hidden data) | `APM-UNMAPPED` | Medium |
| Zero-length partition | `APM-PART-ZEROLEN` | Low |
| Unknown partition type | `APM-PART-UNKNOWN` | Info |

Partition-type strings are validated against the
[`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon) knowledge
base. The reader is fuzz-tested (`cargo fuzz`) to never panic on malformed input.

## Validation

Tested against a **real `hdiutil`-created APM** (`Apple_partition_map` + `Apple_HFS` entries), so the layout is checked against genuine Apple output.

## Related

Part of the [Security Ronin](https://github.com/SecurityRonin) forensic toolkit. Sibling partition readers: [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic), [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic). The [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) orchestrator auto-detects the scheme and dispatches to whichever of the three fits. Filesystems: [`hfsplus-forensic`](https://github.com/SecurityRonin/hfsplus-forensic), [`udf-forensic`](https://github.com/SecurityRonin/udf-forensic). Consumed by [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) for Apple hybrid discs.

---

[Privacy Policy](https://securityronin.github.io/apm-partition-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/apm-partition-forensic/terms/) · © 2026 Security Ronin Ltd
