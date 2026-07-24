# 8. Low declared MSRV, decoupled from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`ronin-issen/CLAUDE.md` → "Rust MSRV & Toolchain") splits
two numbers that must not be conflated: the **dev toolchain** (what the fleet
builds/fmt/clippy with — pinned in `rust-toolchain.toml`) and the **declared
MSRV** (`rust-version`, a downstream-facing compatibility promise). Published
libraries keep a low, CI-verified MSRV so a caret-pinning consumer is not forced
onto a newer compiler; apps declare MSRV = the pinned toolchain.

Both APM crates are published libraries (ADR 0003), so the low-floor rule
applies.

## Decision

- **Dev toolchain pinned to `1.96.0`** (`rust-toolchain.toml`, with `clippy` +
  `rustfmt` components declared in the toml so CI and local agree) — the fleet's
  single current-stable pin.
- **Declared `rust-version = "1.85"`** for both members, set once in
  `[workspace.package]` and inherited (`Cargo.toml`,
  `rust-version.workspace = true`). It is a real, deliberate floor *below* the
  1.96 dev pin — not a copy of it.
- Version, edition, license, and repository are likewise single-sourced in
  `[workspace.package]`; dependency versions (including the inter-crate `apm`
  path/version) in `[workspace.dependencies]` (`git log`: `54b62d0 chore:
  workspace dependency/version inheritance (DRY)`), so a bump is one edit.

## Consequences

- A downstream consumer on Rust 1.85 can use the reader; the analyzer's floor
  moves only if a dependency (e.g. `forensicnomicon`) genuinely requires newer
  Rust — treated as a near-breaking change, not a reflex bump.
- One place to bump version/MSRV/deps for the whole workspace.
- **Unrecovered rationale:** the *specific* choice of `1.85` (rather than the
  constitution's illustrative `1.75`/`1.80`) was present from the first
  extraction commit (`4b1642d`) with no recorded justification for that exact
  figure. Rationale reconstructed from structure; original intent (which
  newer-Rust feature set the floor at 1.85) not recovered in available history.
  The *policy* — a low, CI-verified floor decoupled from the dev pin — is the
  grounded decision; the exact number should be re-verified against the actual
  minimum the code compiles on before it is treated as load-bearing.
