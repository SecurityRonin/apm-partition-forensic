# Test Data — `apm-partition-forensic`

Single repo-root `tests/data/` per the fleet "one repo-root tests/data" standard.
Workspace members reach these fixtures from `<member>/tests/<file>.rs` via a
relative path two levels up:
`concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/<file>")`.

The fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen); this
file is the co-located human-facing provenance detail — cross-reference, never
duplicate.

---

#### apm_map.bin

- **Source / Identity:** First 2 KiB (2048 bytes) of an Apple Partition Map
  image created with `hdiutil create -layout SPUD` on macOS. This is **REAL
  Apple `hdiutil` output** (the DDM + partition map produced by the OS), but it
  was **self-minted** on the author's machine — so the ground truth is
  self-graded (the OS authored the bytes; the author chose the scenario and
  asserts the expected partition table), not an independent third-party corpus.
- **Generator concept** (per `forensic/tests/map.rs:1-4` inline notes): an
  `hdiutil create -layout SPUD` disk image whose first 2 KiB carries the Driver
  Descriptor Map plus the partition map — block size 512, two partitions
  `Apple_partition_map` and `Apple_HFS` (name "disk image", HFS start block 64).
  The 2 KiB head was sliced from that image and committed as the fixture.
- **MD5:** `5d87d4730a865a763f49180a7949b8e2`
- **Size:** 2048 bytes
- **License / redistribution:** Self-minted, committed to the repo. No
  third-party redistribution constraint.
- **Consumed by:**
  - `forensic/tests/map.rs` — reader parse assertions (block size, partition
    count, type names, HFS start block).
  - `forensic/tests/analyse_tests.rs` — forensic analyser real-data check.
