# 2. Crate naming under a crates.io collision — `apm-partition-*`

Date: 2026-07-24
Status: Accepted

## Context

The fleet naming grammar (`ronin-issen/CLAUDE.md` → "Crate naming grammar")
wants a single-format repo to publish `<x>-core` + `<x>-forensic` with the
ergonomic bare import path `use <x>::…`. For APM the natural names would be
`apm-core` and `apm-forensic`.

Two obstacles surfaced:

1. **`apm-core` is already taken** on crates.io by an unrelated third party
   (version 0.1.50) — recorded verbatim in `core/Cargo.toml`. The bare `apm`
   crate name is likewise not ours to claim.
2. The reader originally published as **`apm-forensic`** (`git log`:
   `9136eea release: apm-forensic 0.2.0`), which conflated "reader" and
   "analyzer" and did not match the `<x>-partition-*` family used by the
   sibling partition repos.

## Decision

- **Reader package name = `apm-partition-core`**, but keep the ergonomic import
  path via `[lib] name = "apm"` (`core/Cargo.toml`), so consumers write
  `use apm::…` unaffected by the package rename. This mirrors the constitution's
  `<x>-forensic-core` collision rule for a taken `-core` name.
- **Analyzer package name = `apm-partition-forensic`**; the old `apm-forensic`
  name is retired (`git log`: `8659281`). The import path is
  `apm_partition_forensic` — the analyzer keeps no `[lib] name` override, so it
  derives from the package name. The earlier `apm_forensic` lib alias was
  dropped in `5dea67f refactor: import as apm_partition_forensic (drop
  apm_forensic lib alias) for fleet consistency`, aligning the crate and lib
  names. The real consumer follows suit: `disk-forensic/src/layout.rs:102`
  imports `apm_partition_forensic::ApmAnalysis`.
- The repo is named `apm-partition-forensic` (the analyzer headline), holding
  both members.

## Consequences

- Both crates are self-describing on crates.io (`apm-partition-core`,
  `apm-partition-forensic`) — a reader searching bare names sees "the APM
  partition reader/auditor", not a generic `apm` blob.
- The bare import path (`apm` for the reader) is preserved, so a rename never
  touched downstream `use` statements.
- No hijack of a popular third-party name: `apm-core` stays with its owner; we
  claim only the `apm-partition-*` namespace.
