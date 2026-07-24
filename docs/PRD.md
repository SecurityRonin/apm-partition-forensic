# apm-partition-forensic — Purpose & Scope

**Problem.** Apple hybrid optical discs and Mac disk images carry an Apple
Partition Map (APM). An examiner needs two things from it: the partition
geometry (what slices exist, where, and of what type) and an honest read on
whether that geometry is *structurally sound* or has been tampered with —
overlaps, out-of-bounds slices, residual/hidden entries, unmapped interior
regions that could conceal data.

**Users.** This is a **library**, consumed by fleet tooling — `disk-forensic`
(whose `disk4n6` orchestrator auto-detects MBR/GPT/APM and renders the CLI)
depends on `apm-partition-forensic`, and the `forensic-vfs-engine` stack
(mounts an APM partition as a byte window) depends on `apm-partition-core`.
Examiners run `disk4n6`, not this crate directly.

**What it does.**
- `apm-partition-core` (`use apm`): read-only parse of the Driver Descriptor Map
  + partition entries → `ApplePartitionMap` / `ApmPartition` (name, type, start
  block, block count), `hfs_partition()` lookup, and an optional
  `forensic-vfs::VolumeSystem` adapter behind the `vfs` feature.
- `apm-partition-forensic` (`use apm_partition_forensic`): grades the parsed map into
  severity-ranked `forensicnomicon::report` findings via `analyse` (byte slice)
  and `analyse_reader` (any `Read + Seek`, for composing with container crates).

**Scope.** Reading and auditing the APM structure itself, big-endian per *Inside
Macintosh: Devices* (see [ADR 0007](decisions/0007-big-endian-fixed-block-decoding.md)).
The eight anomaly codes (`APM-PART-OVERLAP` … `APM-PART-UNKNOWN`) are the audit
surface.

**Non-goals.** No filesystem parsing (HFS/HFS+/ISO 9660 live in their own
readers), no container decoding (E01/DMG/VHD — those feed `analyse_reader`), no
CLI or report renderer ([ADR 0003](decisions/0003-pure-library-no-cli.md) — that
is `disk4n6`), and read-only always (no map repair or writes).

**Validation.** The reader is cross-checked Tier-1 against two independent
oracles — The Sleuth Kit `mmls -t mac` and Apple `pdisk -dump` — on a real
`hdiutil`-created APM; the auditor's detectors are exercised by hand-built
fixtures (Tier-3). The honest per-capability state is in
[`docs/validation.md`](docs/validation.md).

The load-bearing design decisions are recorded as ADRs under
[`docs/decisions/`](decisions/).
