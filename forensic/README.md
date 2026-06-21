# apm-partition-forensic

[![Crates.io](https://img.shields.io/crates/v/apm-partition-forensic.svg)](https://crates.io/crates/apm-partition-forensic)
[![Crates.io: core](https://img.shields.io/crates/v/apm-partition-core.svg?label=apm-partition-core)](https://crates.io/crates/apm-partition-core)
[![docs.rs](https://img.shields.io/docsrs/apm-partition-forensic)](https://docs.rs/apm-partition-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/apm-partition-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/apm-partition-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Audit an Apple Partition Map and get back severity-ranked forensic findings — overlaps, out-of-bounds slices, residual entries, hidden gaps.**

Reads APM geometry via the [`apm-partition-core`](https://crates.io/crates/apm-partition-core) reader, then grades the layout against the structural invariants of a valid map. Each anomaly carries a stable code, a 5-level severity, and a human note on the shared [`forensicnomicon::report`](https://crates.io/crates/forensicnomicon) model — an *observation* ("consistent with …"), never a verdict. The examiner draws the conclusion.

```bash
cargo add apm-partition-forensic
```

```rust
use apm_forensic::analyse;

// `data` begins at the device start (block 0 = Driver Descriptor Map);
// the device size comes from the map's own sbBlkCount, so no size argument.
let report = analyse(&std::fs::read("disk.img")?)?;

println!("highest severity: {:?}", report.max_severity());
for a in &report.anomalies {
    println!("[{}] {}: {}", a.severity, a.code, a.note);
}
# Ok::<(), apm_forensic::Error>(())
```

For a disk image behind a container, `analyse_reader(&mut reader, max_bytes)` takes any `Read + Seek` (the APM lives in the first few blocks, so a small cap such as 1 MiB suffices) and composes directly with the `ewf`/`dmg`/`vhd` reader crates.

## Anomaly codes

| Anomaly | Code | Severity |
|---|---|---|
| Overlapping partitions | `APM-PART-OVERLAP` | Critical |
| Partition out of bounds | `APM-PART-OOB` | High |
| Residual (hidden) entry past the declared map count | `APM-PART-RESIDUAL` | High |
| Missing `Apple_partition_map` self-entry | `APM-NO-MAP-ENTRY` | High |
| `pmMapBlkCnt` disagreement between entries | `APM-MAP-COUNT` | Medium |
| Unmapped interior region (possible hidden data) | `APM-UNMAPPED` | Medium |
| Zero-length partition | `APM-PART-ZEROLEN` | Low |
| Unknown partition type | `APM-PART-UNKNOWN` | Info |

Codes are a published contract: a shipped code never changes meaning. Partition-type strings are graded against the [`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon) knowledge base.

## Two crates

This analyzer depends on the [`apm-partition-core`](https://crates.io/crates/apm-partition-core) reader and re-exports its `parse`, `ApplePartitionMap`, `ApmPartition`, and `Error`, so adding `apm-partition-forensic` alone gives you both the reader and the audit layer. An optional `serde` feature derives `Serialize` on the analysis types for JSON output.

## Trust, but verify

These crates parse untrusted, attacker-controllable disk images:

- **Panic-free** — no `unwrap`/`expect`/`panic!` in production code (hard `deny` via the workspace lints).
- **Fuzzed** — `cargo fuzz` targets drive both `parse` and the full `analyse` audit pipeline with a "must not panic" invariant.
- **Real-artifact tested** — the reader is checked against a real `hdiutil`-created APM (`Apple_partition_map` + `Apple_HFS`), genuine Apple output rather than a hand-built byte pattern. It is graded by our own assertions (a Tier-2 check); the anomaly detectors are exercised by hand-built fixtures (Tier 3). No independent decoder (`pdisk` / `mmls` / `mac-fdisk`) cross-validates yet — the full state and the oracle gap are in [`docs/validation.md`](https://securityronin.github.io/apm-partition-forensic/validation/).
- **No `unsafe`** — `unsafe_code = "forbid"`.

## Related

Part of the [Security Ronin](https://github.com/SecurityRonin) forensic toolkit. Reader: [`apm-partition-core`](https://crates.io/crates/apm-partition-core). Sibling analyzers: [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic), [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic). The [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) orchestrator auto-detects the scheme and dispatches to whichever fits.

---

[Privacy Policy](https://securityronin.github.io/apm-partition-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/apm-partition-forensic/terms/) · © 2026 Security Ronin Ltd
