# 7. Decode APM as big-endian, fixed device-block structures

Date: 2026-07-24
Status: Accepted

## Context

The Apple Partition Map is defined in *Inside Macintosh: Devices*
(`core/src/lib.rs` module docs). Its on-disk layout is fixed and big-endian
because it originates on Motorola 68k / PowerPC Macs. A reader that guessed the
byte order or offsets from a sample would ship inverted fields on the first real
disk — the exact failure the fleet's "Research-First" discipline exists to
prevent. The offsets and signatures are spec facts, not choices.

## Decision

Decode strictly per the documented layout (`core/src/lib.rs::parse`):

- **All multi-byte integers big-endian** (`be16`/`be32`).
- **Block 0 = Driver Descriptor Map**, signature `ER` (`SIG_DDM`); read the
  device block size at offset 2 (`u16`) and `sbBlkCount` at offset 4 (`u32`).
- **Blocks 1.. = partition entries**, signature `PM` (`SIG_PM`), located at
  `block_size * (1 + i)`; the first entry's `pmMapBlkCnt` (offset 4) reports the
  entry count. Each 92-byte entry decodes at fixed offsets: `pmMapBlkCnt` @4,
  `pmPyPartStart` @8, `pmPartBlkCnt` @12, `pmPartName` @16 (32-byte
  NUL-terminated ASCII), `pmPartType` @48 (32-byte), `pmPartStatus` @88.
- **Reject non-APM loudly** — `parse` returns `None` (no `Error`) without the
  `ER`/`PM` signatures, on a buffer shorter than one block (512 bytes), or on a
  zero block size (`core/src/lib.rs::parse`). The forensic entry points
  `analyse` / `analyse_reader` surface this as a typed error —
  `Error::TooShort { need, got }` for an under-512-byte buffer and
  `Error::NotApm` for a missing signature (`forensic/src/analyse.rs`) — naming
  the failure (the constitution's "show the unrecognized value").
- **Names decoded as fixed-width NUL-terminated fields** (`cstr`), not
  length-prefixed.

## Consequences

- Field decoding is a transcription of the published spec; correctness is
  cross-checked against two independent oracles that re-decode the same bytes —
  The Sleuth Kit `mmls -t mac` and Apple `pdisk -dump` — reconciling entry
  count, type, start block, and block count (`docs/validation.md`, `git log`:
  `e77c2cc test: Tier-1 mmls/pdisk oracle differential`).
- The 92-byte entry read and every offset are length-checked (ADR 0006), so a
  malformed map truncates the entry list rather than panicking.
- `hfs_partition()` finds the first `Apple_HFS*` slice by type string — the
  common lookup for Apple hybrid optical discs the reader targets.
