# 1. Reader/analyzer split across a two-member workspace

Date: 2026-07-24
Status: Accepted

## Context

The crate began as a single library that both *read* the Apple Partition Map
and *graded* its anomalies (`git log`: `4b1642d feat: extract Apple Partition
Map reader into a standalone crate`, then `a27b09d feat: add forensic analysis
layer`). Commit `8659281 refactor!: split into a Cargo workspace
(apm-partition-core + apm-partition-forensic)` divided the two roles.

The fleet constitution (`ronin-issen/CLAUDE.md` → "Crate-structure standard —
reader/analyzer split") mandates this shape for every single-format repo: a
`<x>-core` reader that reads *valid* data robustly, and a `<x>-forensic`
analyzer that emits graded findings. The two audiences differ — a downstream
consumer that only needs partition geometry should not inherit the analyzer's
knowledge-base and reporting dependencies, and the analyzer's low-level needs
should not distort the reader's clean API.

## Decision

Ship two members from one repo named `apm-partition-forensic` (the analyzer is
the headline):

- **`core/` → crate `apm-partition-core`** — the read-only reader
  (`parse`, `ApplePartitionMap`, `ApmPartition`, `Error`). No findings. Depends
  only on `std` (+ optional `serde`, + optional `forensic-vfs` behind a
  feature).
- **`forensic/` → crate `apm-partition-forensic`** — the anomaly auditor
  (`analyse`, `analyse_reader`, `Anomaly`, `AnomalyKind`, `ApmAnalysis`),
  built on `apm-partition-core` (declared once in `[workspace.dependencies]` as
  `apm = { path = "core", ... }`) and depending down on `forensicnomicon`.

The analyzer re-exports the reader's public surface (`forensic/src/lib.rs`:
`pub use apm::{parse, ApmPartition, ApplePartitionMap, Error}`) so a consumer
depending on the analyzer alone gets both layers.

## Consequences

- Matches the fleet reference implementation (`ntfs-forensic`, `mbr-forensic`,
  `gpt-forensic`) — one mental model across every partition/container repo.
- The APM format is simple enough that the analyzer builds cleanly on the
  reader's `parse()` API; it does not (yet) need to drop below `-core` to raw
  bytes the way `ntfs-forensic` does. The constitution permits either; the
  reader's output exposes every field the current detectors need.
- Two publishable crates, two version lines to keep moving together — handled
  by workspace version inheritance (ADR 0008) and release-plz.
