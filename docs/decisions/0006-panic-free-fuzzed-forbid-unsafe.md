# 6. Panic-free, fuzzed, `forbid(unsafe)` parsing posture

Date: 2026-07-24
Status: Accepted

## Context

These crates parse **untrusted, attacker-controllable disk images**. The fleet
"Paranoid Gatekeeper" standard (`ronin-issen/CLAUDE.md`) is absolute: never
panic, never read out of bounds, never trust a length field, and prove memory
safety by construction.

## Decision

Adopt the full panic-free posture, enforced statically and tested empirically:

- **`unsafe_code = "forbid"`** at the workspace root (`Cargo.toml`
  `[workspace.lints.rust]`). APM needs no `mmap` or FFI, so it takes the
  strongest tier — `forbid`, not the `deny` + bounded-allow that mmap readers
  (ewf, memf) must fall back to. This earns the `unsafe-forbidden` badge.
- **`unwrap_used` / `expect_used` = `deny`** in production
  (`[workspace.lints.clippy]`); tests opt out via
  `#![cfg_attr(test, allow(...))]` + `clippy.toml`
  (`allow-unwrap-in-tests`). `correctness`/`suspicious` are `deny`.
- **Bounds-checked reads** — the reader indexes with `.get(..)?` and reads
  integers through internal `be16`/`be32` helpers that substitute `0` for
  missing bytes (`core/src/lib.rs`), so a short/truncated slice yields a value
  rather than a panic.
- **Corrupt-map cap** — `MAX_PARTITIONS = 256`
  (`map_count.min(MAX_PARTITIONS)`) bounds the entry loop against a hostile
  `pmMapBlkCnt`, and every entry read is length-checked before use.
- **Fuzzing** — two `cargo fuzz` targets (`fuzz/fuzz_targets/fuzz_parse.rs`,
  `fuzz_forensic.rs`) drive the `parse` reader and the full `analyse` pipeline;
  the invariant is "must not panic" on any input, smoke-run by `fuzz.yml`.

## Consequences

- Memory-corruption / RCE class is deleted by construction; robustness is
  *tested*, not merely asserted (README "Trust, but verify").
- The integer readers are hand-rolled `be16`/`be32` rather than routed through
  the fleet's shared `safe-read` crate (the constitution's default single
  audited reader). This predates that policy in this repo and is a known
  divergence; the two two-line helpers are trivially auditable and return `0`
  out of range, so behavior matches `safe-read`'s contract — a future change
  can migrate them without altering observable output.
- `forbid` cannot be locally overridden, so any future need for `unsafe` would
  force an explicit, reviewed downgrade to `deny` — the desired friction.
