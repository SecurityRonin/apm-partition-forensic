# 5. `forensicnomicon` as both the report model and the partition-type knowledge

Date: 2026-07-24
Status: Accepted

## Context

Every fleet analyzer must emit findings on one shared vocabulary so
orchestration (`disk-forensic`, Issen) and a future GUI render them uniformly
instead of N bespoke `XxxAnalysis` types (`ronin-issen/CLAUDE.md` → "The
Reporting Model — `forensicnomicon::report`"). Separately, deciding whether a
partition *type string* (`Apple_HFS`, `Apple_Free`, …) is known or suspicious
is format knowledge, not parsing — and format knowledge lives in the
`forensicnomicon` KNOWLEDGE leaf, never re-encoded per analyzer.

`git log`: `340215f test(apm-forensic): RED — Anomaly -> canonical
report::Finding` → `8d86979 feat(apm-forensic)!: normalize onto
forensicnomicon::report`, followed by version bumps tracking the leaf
(`a0b4da5` 0.5→0.11, `7105849` 0.11→1).

## Decision

Depend **down** on `forensicnomicon` (`forensic/Cargo.toml`:
`forensicnomicon.workspace = true`, declared once as `forensicnomicon = "1"`)
for two roles:

1. **Report model** — the native `AnomalyKind`/`Anomaly` domain type is kept
   (it holds the domain knowledge), and `Anomaly` implements
   `forensicnomicon::report::Observation` (`forensic/src/findings.rs`) so it
   converts to a canonical graded `Finding`, addressing evidence in logical
   device blocks (`Location::Lba`). `Severity` is re-exported from the leaf.
2. **Partition-type knowledge** — type strings are graded against
   `forensicnomicon`, so "unknown partition type" is defined by the shared
   knowledge base, not a literal allow-list baked into this crate.

Findings are **observations, never verdicts** ("consistent with …"); the
examiner draws the conclusion (README "Forensic anomaly detection").

## Consequences

- Anomaly `code`s are a published contract in scheme-prefixed SCREAMING-KEBAB
  (`APM-PART-OVERLAP`, `APM-PART-OOB`, `APM-MAP-COUNT`, `APM-UNMAPPED`, …,
  `forensic/src/findings.rs`) — stable, never re-spelled once shipped.
- Prefer-our-own-crates and single-KNOWLEDGE-leaf are both honored: no
  third-party partition dictionary, no duplicate reporting enum.
- The crate rides `forensicnomicon`'s major line; a leaf bump is a deliberate,
  reviewed dependency change (the 0.5→0.11→1 sweep in the log).
