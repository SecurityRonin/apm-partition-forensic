# Validation

`apm-partition-forensic` parses untrusted Apple Partition Map structures from
potentially compromised disk images. Correctness for forensic tooling is
established against **independent oracles** (a different tool, or a different code
path, that already decodes the same bytes correctly) on **real corpora** with
known ground truth — never against fixtures we hand-encoded and then graded
ourselves.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. The **partition-map reader is now
Tier 1**: two independent decoders (`mmls -t mac` and `pdisk -dump`) re-decode the
same committed bytes and the test reconciles our parse against their actual output.
The **anomaly auditor remains Tier 3** — its detectors are still exercised only by
hand-built fixtures, and this page says so plainly rather than implying a stronger
guarantee.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

The partition-map reader is cross-checked by **two independent decoders**, each a
separate codebase that re-decodes the *same committed bytes* the crate parses.
`forensic/tests/real_apm_oracle.rs` runs them at test time (env-gated: a missing
binary skips that oracle cleanly) and asserts our parse matches their actual
reported entry count, type, start block, and block count.

| Oracle | Independent of us? | Validates | Tier | Status |
|---|---|---|---|---|
| **`mmls -t mac`** (The Sleuth Kit 4.12.1) | Yes — independent C codebase | entry count, type, start block, block count over `apm_map_32k.bin` | 1 | **Wired in** (`crate_matches_mmls_oracle`) |
| **`pdisk -dump`** (Apple, v0.9a2) | Yes — Apple's canonical APM editor | entry count, type, name, start block, block count over `apm_map_32k.bin` | 1 | **Wired in** (`crate_matches_pdisk_oracle`) |

The two oracles are additionally asserted to agree with **each other** on geometry
(`oracles_agree_on_geometry`), so the differential compares like with like
independent of this crate.

- **`mmls`** (`mmls -t mac <image>`) — emits the APM partition table (slot, start,
  length, description) from an independent C codebase; the natural differential for
  partition bounds, overlap, and unmapped-gap findings.
- **`pdisk`** (`pdisk -dump <image>`) — prints DDM block size, every `pmPartName` /
  `pmPartType`, and `pmPyPartStart` / `pmPartBlkCnt`. The canonical APM reference
  tool. (It warns on stderr about unreadable *data* blocks beyond the 32 KiB head;
  the partition-*map* decode on stdout is unaffected.)

Still-available oracles not yet wired in: **`mac-fdisk -l`** (Linux util-mac) and
**`hdiutil pmap`** (macOS, reads back an existing image — distinct from using
`hdiutil create` to *produce* the fixture). Either would add a third independent
cross-check.

## Independent test corpora

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| **`apm_map_32k.bin`** (first 32 KiB of an 8 MiB `hdiutil create -size 8m -layout SPUD -fs HFS+` image) | Real Apple `hdiutil` output on macOS (DDM + `Apple_partition_map` + `Apple_HFS`, block size 512) | **Tier-1 differential** vs `mmls -t mac` + `pdisk -dump` (entry count, type, name, start, count) | Self-minted; committed (`tests/data/apm_map_32k.bin`) |
| **`apm_map.bin`** (first 2 KiB of an `hdiutil create -layout SPUD` image) | Real Apple `hdiutil` output on macOS (DDM + `Apple_partition_map` + `Apple_HFS`, block size 512) | Reader/auditor real-data check in `map.rs` / `analyse_tests.rs` (block size, entry count, type names, HFS start block) | Self-minted; committed (`tests/data/apm_map.bin`) |

Both fixtures are **genuine Apple `hdiutil` output**, so the on-disk layout is real
(not a byte-pattern we invented). The `apm_map_32k.bin` parse is now graded by two
**independent** decoders re-reading the same bytes (Tier 1) — 32 KiB is the
smallest head both `mmls` and `pdisk` fully decode (mmls probes the HFS partition's
start area at sector 64; pdisk decodes the map from the first 2 KiB). The older
`apm_map.bin` is still consumed by the reader/auditor real-data tests; its
*expected values* there were authored here, so on its own it is Tier 2. There is
**no third-party APM corpus** (e.g. a CTF image, a NIST CFReDS Mac image, or a
published forensic sample) in the suite yet; adding one with an externally-authored
answer key would be a further independent cross-check.

> Provenance note: per-file provenance (source, verbatim generator command, MD5/
> SHA256, consumers) lives in the repo's `tests/data/README.md`; the fleet-wide
> machine index is `issen/docs/corpus-catalog.md`.

## Per-capability validation

### Partition-map reader (DDM + entries) — Tier 1

`forensic/tests/real_apm_oracle.rs` re-decodes the committed `apm_map_32k.bin`
with **two independent tools** and asserts the crate's parse matches each oracle's
**actual reported values** (never values this crate computed):

- `crate_matches_mmls_oracle` — runs `mmls -t mac` (The Sleuth Kit), parses its
  partition rows, and reconciles entry count, type, start block, and block count
  against `apm::parse`.
- `crate_matches_pdisk_oracle` — runs `pdisk -dump` (Apple), parses its rows, and
  reconciles the same fields.
- `oracles_agree_on_geometry` — asserts `mmls` and `pdisk` agree with each other,
  guarding the differential independent of this crate.

The reconciled ground truth (both oracles concur): block size 512, two entries —
`Apple_partition_map` (start block 1, 63 blocks) and `Apple_HFS` (name
`disk image`, start block 64, 16320 blocks). Each test is **env-gated**: a host
without that oracle binary skips the test cleanly. Because an independent codebase
authored the answer key by re-decoding the same bytes, this is **Tier 1**.

The original `forensic/tests/map.rs` reader assertions over `apm_map.bin` remain as
real-data regression checks (their expected values are authored here, so on their
own those are Tier 2):

- `parses_real_apple_partition_map` — block size 512, exactly two entries,
  `Apple_partition_map` then `Apple_HFS`, HFS named `disk image` starting at
  block 64.
- `finds_hfs_partition` — `hfs_partition()` locates the `Apple_HFS` slice.
- `non_apm_is_none` — non-APM input (zeroed and too-short buffers) parses to
  `None`, never a false-positive map.

### Anomaly auditor (severity-graded findings) — Tier 3

The anomaly detectors —
`APM-MAP-COUNT`, `APM-NO-MAP-ENTRY`, `APM-PART-OVERLAP`, `APM-PART-OOB`,
`APM-PART-RESIDUAL`, `APM-UNMAPPED`, `APM-PART-ZEROLEN`, `APM-PART-UNKNOWN` —
are exercised by **hand-built** partition tables in
`forensic/tests/analyse_tests.rs` (the `ent(...)` helper constructs each scenario):

- one finding per code (`map_count_mismatch_flagged`,
  `missing_partition_map_self_entry_flagged`, `overlapping_partitions_flagged`,
  `out_of_bounds_flagged`, `residual_entry_flagged`,
  `unmapped_region_between_partitions_flagged`, `zero_length_partition_flagged`,
  `unknown_partition_type_flagged`);
- clean-input negatives (`well_formed_synthetic_is_clean`, and
  `real_apm_is_clean` over the real `apm_map.bin`);
- canonical-`Finding` conversion and block-location evidence
  (`forensic/tests/canonical_finding_tests.rs`);
- error-path coverage (`forensic/tests/error_tests.rs`).

These fixtures are authored here and graded here — **Tier 3**: they prove each
detector fires on a constructed instance and stays silent on a clean one, which is
correct per-branch coverage, **not** a correctness claim against adversarial
real-world maps. The honest gap is a real APM carrying a *naturally-occurring*
anomaly (e.g. a wiped/residual entry from a real wipe, an overlap from a real
corruption) cross-checked against `mmls`/`pdisk`. There is no such corpus today.

### Robustness — never panic, never over-read

`forensic/tests/proptests.rs` drives `parse` and `analyse` with property-based
random input (invariant: must not panic; `end_block_never_precedes_start`,
`byte_and_reader_apis_agree`). Two `cargo-fuzz` targets back this:
`fuzz/fuzz_targets/fuzz_parse.rs` (the reader) and
`fuzz/fuzz_targets/fuzz_forensic.rs` (the full `analyse` audit pipeline), each with
the "must not panic" invariant. Production code is `#![forbid(unsafe_code)]` and
denies `clippy::unwrap_used` / `clippy::expect_used`; integers are read through
bounds-checked helpers that return `0` on a short slice, and the entry count is
capped (`MAX_PARTITIONS`) against a corrupt map. This is a real robustness
guarantee (independent of the correctness tier above).

## Reproducing the validation

All tests are committed and always-on (no large external image is required):

```bash
# Tier-1 differential: crate parse vs mmls -t mac AND pdisk -dump on the same bytes
# (env-gated; skips an oracle cleanly if its binary is absent)
cargo test -p apm-partition-forensic --test real_apm_oracle -- --nocapture

# Reader vs the real hdiutil-created APM (committed fixture)
cargo test -p apm-partition-forensic --test map

# Anomaly auditor: one test per finding code + clean negatives
cargo test -p apm-partition-forensic --test analyse_tests

# Canonical Finding conversion + error paths + property tests
cargo test -p apm-partition-forensic --test canonical_finding_tests \
                                     --test error_tests \
                                     --test proptests

# Whole workspace
cargo test --workspace

# Fuzz (must-not-panic) — requires the nightly cargo-fuzz toolchain
cargo +nightly fuzz run fuzz_parse
cargo +nightly fuzz run fuzz_forensic
```

To regenerate the committed Tier-1 fixture from scratch and re-confirm the oracle
agreement on a freshly minted APM:

```bash
# Produce a real APM image (macOS) and slice the 32 KiB head both oracles decode
hdiutil create -size 8m -layout SPUD -fs HFS+ -volname OracleTest /tmp/apm_oracle
dd if=/tmp/apm_oracle.dmg of=tests/data/apm_map_32k.bin bs=1024 count=32

# Independent decode of the same bytes (the answer key the differential reconciles)
pdisk tests/data/apm_map_32k.bin -dump   # Apple partition editor
mmls  -t mac tests/data/apm_map_32k.bin  # The Sleuth Kit
```

## Coverage & fuzzing as backstops

100% line coverage is enforced in CI (`cargo llvm-cov --lib`, failing on any
zero-hit line not annotated `// cov:unreachable`). Coverage is a regression
backstop that proves behavior is exercised — it is not the correctness claim. The
oracles are; and where they are absent (above), this page says so rather than
implying a stronger guarantee than the tests deliver.
