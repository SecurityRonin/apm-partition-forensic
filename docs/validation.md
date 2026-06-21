# Validation

`apm-partition-forensic` parses untrusted Apple Partition Map structures from
potentially compromised disk images. Correctness for forensic tooling is
established against **independent oracles** (a different tool, or a different code
path, that already decodes the same bytes correctly) on **real corpora** with
known ground truth — never against fixtures we hand-encoded and then graded
ourselves.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. It states the current validation state
honestly, including where independent-oracle coverage is **not yet in place** and
which tools would close that gap.

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

No independent partition-map oracle is currently wired into the test suite. The
one real artifact (below) is *produced* by Apple's `hdiutil` and graded by our
own assertions — that makes it real engine output (Tier 2), but no second,
independent decoder cross-checks the parse.

| Oracle | Independent of us? | Validates | Tier | Status |
|---|---|---|---|---|
| — | — | — | — | **None wired in.** See the recommended oracles below. |

**Recommended oracles to add (the gap).** Each of these independently decodes an
APM and would turn the reader's parse into a Tier-1 differential:

- **`pdisk`** (Apple's partition editor; `pdisk -dump <image>`) — prints DDM block
  size, every `pmPartName` / `pmPartType`, and `pmPyPartStart` / `pmPartBlkCnt`.
  The canonical APM reference tool.
- **`mac-fdisk`** (`mac-fdisk -l <image>`) — lists APM entries with type, name, and
  block bounds; available in many Linux distributions (`mac-fdisk` / `pdisk`
  packages).
- **The Sleuth Kit `mmls`** (`mmls -t mac <image>`) — emits the APM partition table
  (slot, start, length, description) from an independent C codebase; the natural
  differential for partition bounds, overlap, and unmapped-gap findings.
- **`hdiutil` as a *checker*** (`hdiutil pmap <image>` on macOS) — reads back the
  partition map of an existing image, distinct from using `hdiutil create` merely
  to *produce* the fixture.

Adding any one of these as an env-gated differential (parse our entries, parse the
oracle's dump of the *same bytes*, reconcile block size + per-entry
name/type/start/count) would raise the reader from Tier 2 to Tier 1.

## Independent test corpora

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| **`apm_map.bin`** (first 2 KiB of an `hdiutil create -layout SPUD` image) | Self-generated with Apple `hdiutil` on macOS (DDM + `Apple_partition_map` + `Apple_HFS`, block size 512) | Real-layout reader validation: block size, entry count, type names, HFS start block | Self-minted; committed (`forensic/tests/data/apm_map.bin`) |

This is **genuine Apple `hdiutil` output**, so the on-disk layout is real (not a
byte-pattern we invented). But because we both generated it and wrote its expected
answers, it is **Tier 2, not Tier 1** — no third party authored an independent
answer key, and no independent tool re-decodes it. There is **no third-party APM
corpus** (e.g. a CTF image, a NIST CFReDS Mac image, or a published forensic
sample) in the suite yet; adding one with externally-established ground truth would
be the clearest path to Tier 1.

> Provenance note: the fixture's generating command and hash are recorded inline in
> `forensic/tests/map.rs:1-3`. There is **no `tests/data/README.md`** in this repo
> yet; the fleet-wide machine index is `issen/docs/corpus-catalog.md`.

## Per-capability validation

### Partition-map reader (DDM + entries) — Tier 2

`forensic/tests/map.rs` parses the real `hdiutil`-generated `apm_map.bin` and
asserts the structurally-derivable ground truth:

- `parses_real_apple_partition_map` (`forensic/tests/map.rs:16`) — block size 512,
  exactly two entries, `Apple_partition_map` then `Apple_HFS`, HFS named
  `disk image` starting at block 64.
- `finds_hfs_partition` (`forensic/tests/map.rs:27`) — `hfs_partition()` locates the
  `Apple_HFS` slice (start block 64).
- `non_apm_is_none` (`forensic/tests/map.rs:33`) — non-APM input (zeroed and
  too-short buffers) parses to `None`, never a false-positive map.

The layout is real Apple output, but the expected values were authored here and no
independent decoder cross-checks them — hence **Tier 2**. An `mmls`/`pdisk`
differential on these same bytes would lift it to Tier 1.

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

To close the oracle gap, generate a fresh APM and diff our parse against an
independent decoder of the *same bytes*:

```bash
# Produce a real APM image (macOS)
hdiutil create -size 10m -layout SPUD -fs HFS+ /tmp/apm.dmg

# Independent decode (any one of these is an oracle for a differential test)
pdisk /tmp/apm.dmg -dump          # Apple partition editor
mmls -t mac /tmp/apm.dmg          # The Sleuth Kit
mac-fdisk -l /tmp/apm.dmg         # Linux util-mac
```

## Coverage & fuzzing as backstops

100% line coverage is enforced in CI (`cargo llvm-cov --lib`, failing on any
zero-hit line not annotated `// cov:unreachable`). Coverage is a regression
backstop that proves behavior is exercised — it is not the correctness claim. The
oracles are; and where they are absent (above), this page says so rather than
implying a stronger guarantee than the tests deliver.
