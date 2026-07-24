# 3. A pure library — no bundled CLI binary

Date: 2026-07-24
Status: Accepted

## Context

An earlier iteration shipped a command-line binary and a text-report renderer
(`git log`: `1187030 feat(cli): GREEN — apm-forensic binary + text_report
renderer`, `ff8b7ac docs: document apm-forensic CLI`). Two follow-up commits
reversed course:

- `a5377bd refactor!: drop the CLI binary — apm-forensic is now a pure library`
- `8d6d0db refactor!: remove text_report — apm-forensic is a pure data library
  (0.3.0)`

The fleet exposes one unified partition/disk front-end, **`disk4n6`** (the
`disk-forensic` orchestrator), which auto-detects MBR/GPT/APM and dispatches to
the matching reader. A per-format CLI in every reader repo would duplicate that
surface and split the examiner's entry point N ways — against the
constitution's "one concept, one name" and the `disk-forensic` VFS/abstraction
policy.

## Decision

`apm-partition-forensic` and `apm-partition-core` are **pure libraries** — no
`[[bin]]`, no text renderer. They emit typed data (`ApplePartitionMap`,
`ApmAnalysis`, graded `Anomaly`/`report::Finding`); rendering and the
user-facing CLI live in `disk-forensic` (`disk4n6`). The README points examiners
there explicitly ("For a ready-made command line … install the unified
`disk4n6` tool").

## Consequences

- **Tier = LIBRARY.** The repo is *linked*, never *run* by an examiner directly;
  this classification drives the documentation shape (a DESIGN/Purpose-&-Scope
  intent doc, not a PRD).
- A single, consistent front-end (`disk4n6`) for all three partition schemes;
  no per-format CLI drift.
- Consumers get structured data they can route into their own reports, the VFS
  layer, or the correlation engine — the "machine view" the fleet's
  human/machine-output discipline prefers for a library.
