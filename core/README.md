# apm-partition-core

[![Crates.io](https://img.shields.io/crates/v/apm-partition-core.svg)](https://crates.io/crates/apm-partition-core)
[![Crates.io: forensic](https://img.shields.io/crates/v/apm-partition-forensic.svg?label=apm-partition-forensic)](https://crates.io/crates/apm-partition-forensic)
[![docs.rs](https://img.shields.io/docsrs/apm-partition-core)](https://docs.rs/apm-partition-core)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/apm-partition-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/apm-partition-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**A read-only, no-`unsafe` Apple Partition Map reader — Driver Descriptor Map and partition entries from a byte buffer.**

Decodes the big-endian APM that lets a Mac see the slices on hybrid optical discs and APM-formatted media: block 0's Driver Descriptor Map (`ER`, carrying the block size) and the `PM` partition entries (name, type, start block, block count). One `parse` call over a byte slice; no I/O of its own, no allocations beyond the partition vector.

```bash
cargo add apm-partition-core
```

```rust
// `data` begins at the device's first byte (block 0 = Driver Descriptor Map).
let data: Vec<u8> = std::fs::read("disk.img")?;

if let Some(map) = apm::parse(&data) {
    println!("{}-byte blocks, {} partitions", map.block_size, map.partitions.len());
    for p in &map.partitions {
        println!("  {:<24} {}  start {} ({} blocks)", p.type_name, p.name, p.start_block, p.block_count);
    }
    if let Some(hfs) = map.hfs_partition() {
        println!("Apple_HFS at block {}", hfs.start_block);
    }
}
# Ok::<(), std::io::Error>(())
```

> The crate is published as `apm-partition-core` (the bare `apm-core` name is taken on crates.io) but imports as `apm` via `[lib] name = "apm"` — so you write `use apm::…`.

## What it reads

| Capability | Notes |
|---|---|
| Driver Descriptor Map | `ER` signature → device block size, `sbBlkCount` device block count |
| Partition entries | `PM` entries → name, type, start block, block count, map count, status |
| HFS lookup | `hfs_partition()` returns the first `Apple_HFS`/`Apple_HFS+` slice |

`parse(&[u8]) -> Option<ApplePartitionMap>` returns `None` (rather than erroring or panicking) when the `ER`/`PM` signatures are absent or the buffer is too short. The richer `Error` type and the forensic anomaly pass live in the sibling [`apm-partition-forensic`](https://crates.io/crates/apm-partition-forensic) crate.

An optional `serde` feature derives `Serialize` on `ApplePartitionMap` and `ApmPartition` for JSON output.

## Trust, but verify

This crate parses untrusted, attacker-controllable disk images:

- **Panic-free** — no `unwrap`/`expect`/`panic!` in production code (hard `deny` via the workspace lints); integers are read through bounds-checked helpers that yield `0` on a short slice, and the entry count is capped (`MAX_PARTITIONS`) against a corrupt map.
- **Fuzzed** — a `cargo fuzz` target feeds arbitrary bytes to `parse` with a "must not panic" invariant.
- **Real-artifact tested** — checked against a real `hdiutil`-created APM, genuine Apple output rather than a hand-built byte pattern. Graded by our own assertions (a Tier-2 check); no independent decoder cross-validates yet — see [`docs/validation.md`](https://securityronin.github.io/apm-partition-forensic/validation/).
- **No `unsafe`** — `unsafe_code = "forbid"`.

## Related

Part of the [Security Ronin](https://github.com/SecurityRonin) forensic toolkit. The analyzer built on this reader is [`apm-partition-forensic`](https://crates.io/crates/apm-partition-forensic). Sibling partition readers: [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic), [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic). The [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) orchestrator auto-detects the scheme and dispatches to whichever fits.

---

[Privacy Policy](https://securityronin.github.io/apm-partition-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/apm-partition-forensic/terms/) · © 2026 Security Ronin Ltd
