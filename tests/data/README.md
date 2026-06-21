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

#### apm_map_32k.bin

- **Source / Identity:** First 32 KiB (32768 bytes) of a real Apple Partition
  Map image created by Apple's `hdiutil` on macOS. Genuine OS-authored bytes
  (DDM + partition map), sliced from an 8 MiB disc image. 32 KiB is the smallest
  head that BOTH independent oracles fully decode: `mmls -t mac` probes the
  `Apple_HFS` partition's start area at sector 64 (= byte 32768), while
  `pdisk -dump` decodes the map from the first 2 KiB. The 8 MiB source image is
  too large to commit; the entire partition map lives in this head.
- **Verbatim generator command (macOS):**
  ```sh
  hdiutil create -size 8m -layout SPUD -fs HFS+ -volname OracleTest /tmp/apm_oracle
  dd if=/tmp/apm_oracle.dmg of=tests/data/apm_map_32k.bin bs=1024 count=32
  ```
- **MD5:** `cf93a0aa136bd22b36b5f397dca942a2`
- **SHA256:** `d44333ae49e6c6a8dfb0abca71a9ea7b950d2481e330927731153a8b38e1b8c9`
- **Size:** 32768 bytes
- **Independent ground truth (the answer key for the differential):** both
  `mmls -t mac` (The Sleuth Kit 4.12.1) and `pdisk -dump` (macOS, v0.9a2)
  independently report block size 512 and two entries —
  `Apple_partition_map` (start block 1, 63 blocks) and `Apple_HFS`
  (name "disk image", start block 64, 16320 blocks). These tools, not this
  crate, supply the expected values.
- **License / redistribution:** Self-minted, committed to the repo. No
  third-party redistribution constraint.
- **Consumed by:**
  - `forensic/tests/real_apm_oracle.rs` — **Tier-1 differential**: re-decodes
    these same bytes with `mmls -t mac` and `pdisk -dump` at test time
    (env-gated; skips cleanly if the tool is absent) and asserts the crate's
    parse matches each oracle's actual reported entry count, type names, start
    blocks, and block counts.
