# apm-partition-forensic

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

## Forensic anomaly detection

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

Each anomaly is an *observation* ("consistent with …"), never a verdict — the examiner draws the conclusion.

## Trust, but verify

These crates parse untrusted, attacker-controllable disk images, so the bar is *never panic, never read out of bounds, never trust a length field*: panic-free production code (hard `deny` workspace lints, bounds-checked integer reads, capped entry counts), `cargo fuzz` targets over both the `parse` reader and the full `analyse` pipeline, validation against a real `hdiutil`-created APM, and `unsafe_code = "forbid"` across the workspace.

See the project [README](https://github.com/SecurityRonin/apm-partition-forensic) for the full quick start and capability tables.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
