# 4. `forensic-vfs` VolumeSystem adapter behind an optional `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet's format-agnostic image access (`ronin-issen/CLAUDE.md` → "VFS &
Universal Container Abstraction") composes container → volume-system →
filesystem layers as one `Arc<dyn ImageSource>`, so a consumer reads an
`E01 → APM → HFS+` stack without knowing one scheme from another. For APM to
participate it must implement `forensic-vfs::VolumeSystem`, exposing each
partition as an openable byte window.

`git log`: `7e27266 test(vfs): RED — ApmVolumes VolumeSystem against
mmls/pdisk oracle` → `d589808 feat(vfs): GREEN — ApmVolumes implements
forensic-vfs VolumeSystem`. But `forensic-vfs` pulls a non-trivial dependency
graph; a consumer that only wants partition geometry from the bare parser
should not inherit it.

## Decision

Implement the VolumeSystem adapter (`core/src/vfs.rs`, `ApmVolumes`) **in the
reader crate, gated behind an optional `vfs` feature** (`core/Cargo.toml`:
`forensic-vfs = { version = "0.3", optional = true }`, `vfs = ["dep:forensic-vfs"]`).
`ApmVolumes::open(parent)` reads a bounded head (`APM_MAP_CAP = 1 MiB` — the
DDM + map is a handful of blocks, and the cap bounds a hostile parent), parses
the map, and presents each partition as a `SubRange` window in the map's own
block units.

The `vfs` feature is off by default; the constitution's "batteries-included"
rule keeps *capability* deps always-on in the shipping binary, but a VFS
*integration seam* on an optional protocol crate is legitimately feature-gated
so the bare parser stays lightweight for third-party reuse.

## Consequences

- APM slots into the universal `disk-forensic` / `forensic-vfs` stack;
  `disk4n6` can mount an APM partition through the same abstraction as MBR/GPT.
- The default parser has no `forensic-vfs` in its graph; consumers opt in with
  `features = ["vfs"]`.
- The adapter reads through the parent `ImageSource` positioned-read edge
  (`fill` tolerates short reads / EOF), never a raw `mmap` or its own file
  handle — consistent with the read-only, no-`unsafe` posture (ADR 0006).
- Validated against the `mmls`/`pdisk` oracle in the same differential test the
  reader uses (see `docs/validation.md`).
