# apm-partition-forensic

[![Crates.io: core](https://img.shields.io/crates/v/apm-partition-core.svg?label=apm-partition-core)](https://crates.io/crates/apm-partition-core)
[![Crates.io: forensic](https://img.shields.io/crates/v/apm-partition-forensic.svg?label=apm-partition-forensic)](https://crates.io/crates/apm-partition-forensic)
[![docs.rs](https://img.shields.io/docsrs/apm-partition-forensic)](https://docs.rs/apm-partition-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/apm-partition-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/apm-partition-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Read an Apple Partition Map — then grade its structural anomalies into severity-ranked forensic findings.**

A read-only APM reader (Driver Descriptor Map + partition entries: name, type, bounds) paired with an anomaly auditor that flags exactly what a forensic examiner looks for: map-count disagreement, overlapping or out-of-bounds partitions, residual (hidden) entries, and unmapped interior regions that could conceal data. Pure Rust, no `unsafe`.

```rust
use apm_forensic::analyse;

let report = analyse(&std::fs::read("disk.img")?)?;
for a in &report.anomalies {
    println!("[{}] {}: {}", a.severity, a.code, a.note);
}
# Ok::<(), apm_forensic::Error>(())
```

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

## Two crates

| Crate | Import as | Role |
|---|---|---|
| [`apm-partition-core`](https://crates.io/crates/apm-partition-core) | `apm` | Read-only reader: Driver Descriptor Map + partition entries (`parse`, `ApplePartitionMap`, `ApmPartition`) |
| [`apm-partition-forensic`](https://crates.io/crates/apm-partition-forensic) | `apm_forensic` | Anomaly auditor: `analyse` / `analyse_reader` → graded `Anomaly` findings, built on the reader |

The forensic crate re-exports the reader's `parse`, `ApplePartitionMap`, `ApmPartition`, and `Error`, so depending on it alone gives you both layers.

## Install

```toml
[dependencies]
apm-partition-forensic = "0.4"   # analyzer + re-exported reader
# or, reader only:
apm-partition-core = "0.4"
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

Partition-type strings are graded against the
[`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon) knowledge
base. Each anomaly is an *observation* ("consistent with …"), never a verdict —
the examiner draws the conclusion.

## Trust, but verify

These crates parse untrusted, attacker-controllable disk images, so the bar is
*never panic, never read out of bounds, never trust a length field*:

- **Panic-free** — production code carries no `unwrap`/`expect`/`panic!`, enforced as a hard `deny` by the workspace lints; integers are read through bounds-checked helpers that return `0` rather than panicking on a short slice, and the entry count is capped (`MAX_PARTITIONS`) against a corrupt map.
- **Fuzzed** — `cargo fuzz` targets drive the `parse` reader and the full `analyse` audit pipeline; the invariant is "must not panic" on any input.
- **Real-artifact validated** — tested against a real `hdiutil`-created APM (`Apple_partition_map` + `Apple_HFS` entries), so the layout is checked against genuine Apple output, not only synthetic fixtures.
- **No `unsafe`** — `unsafe_code = "forbid"` across the workspace.

## Related

Part of the [Security Ronin](https://github.com/SecurityRonin) forensic toolkit. Sibling partition readers: [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic), [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic). The [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) orchestrator auto-detects the scheme and dispatches to whichever of the three fits. Filesystems: [`hfsplus-forensic`](https://github.com/SecurityRonin/hfsplus-forensic), [`udf-forensic`](https://github.com/SecurityRonin/udf-forensic). Consumed by [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) for Apple hybrid discs.

---

[Privacy Policy](https://securityronin.github.io/apm-partition-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/apm-partition-forensic/terms/) · © 2026 Security Ronin Ltd
