//! INDEPENDENT cross-tool oracle differential (Tier 1).
//!
//! Re-decodes the SAME bytes this crate parses with two independent Apple
//! Partition Map readers and asserts our parse matches their ACTUAL reported
//! values — not values this crate computed:
//!
//!   * The Sleuth Kit `mmls -t mac` (independent C codebase)
//!   * Apple `pdisk -dump` (the canonical APM editor, ships with macOS)
//!
//! The fixture `tests/data/apm_map_32k.bin` is the first 32 KiB of a real
//! `hdiutil create -size 8m -layout SPUD -fs HFS+` image — 32 KiB is the
//! smallest head BOTH oracles fully decode (mmls probes the HFS partition's
//! start area at sector 64; pdisk decodes the map from the first 2 KiB). The
//! 8 MiB source image itself is too large to commit; the partition map lives
//! entirely in this head.
//!
//! Env-gated like the fleet's real-artifact tests: a missing oracle binary
//! skips that oracle cleanly (prints a notice) rather than failing CI. Run
//! `cargo test -p apm-partition-forensic --test real_apm_oracle -- --nocapture`
//! on a host with mmls/pdisk to see the reconciliation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

use apm_partition_forensic as apm;

fn fixture() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/data/apm_map_32k.bin"
    ))
    .expect("read apm_map_32k.bin fixture")
}

fn fixture_path() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/apm_map_32k.bin").to_string()
}

/// True if `tool` is runnable on this host (so we can env-gate cleanly).
fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .is_ok_and(|o| o.status.success())
}

/// One partition entry as an oracle reports it: (type, `start_block`,
/// `block_count`). `type` is omitted (`None`) when an oracle does not print it
/// for that row.
#[derive(Debug, PartialEq, Eq)]
struct OracleEntry {
    type_name: Option<String>,
    start: u32,
    count: u32,
}

// ── mmls (The Sleuth Kit) ─────────────────────────────────────────────────────

/// Parse `mmls -t mac` rows into oracle entries, skipping the synthetic
/// `Unallocated` / `Table` (Meta) rows TSK injects.
///
/// Row shape: `NNN:  SLOT  START  END  LENGTH  Description`
fn parse_mmls(out: &str) -> Vec<OracleEntry> {
    let mut v = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        // Data rows start with the zero-padded slot index then a colon.
        let Some((idx, rest)) = line.split_once(':') else {
            continue;
        };
        if idx.len() != 3 || !idx.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let cols: Vec<&str> = rest.split_whitespace().collect();
        // [slot, start, end, length, description...]
        if cols.len() < 5 {
            continue;
        }
        let desc = cols[4..].join(" ");
        if desc == "Unallocated" || desc == "Table" {
            continue;
        }
        let (Ok(start), Ok(count)) = (cols[1].parse::<u32>(), cols[3].parse::<u32>()) else {
            continue;
        };
        v.push(OracleEntry {
            type_name: Some(desc),
            start,
            count,
        });
    }
    v
}

// ── pdisk (Apple) ─────────────────────────────────────────────────────────────

/// Parse `pdisk -dump` rows. Row shape (whitespace-separated):
/// ` #:  type  name...  length @ base   ( size )`
/// Name can contain spaces, so anchor on `length @ base`.
fn parse_pdisk(out: &str) -> Vec<OracleEntry> {
    let mut v = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        let Some((idx, rest)) = line.split_once(':') else {
            continue;
        };
        if idx.trim().parse::<u32>().is_err() {
            continue;
        }
        // Find the `@` that separates length from base.
        let toks: Vec<&str> = rest.split_whitespace().collect();
        let Some(at) = toks.iter().position(|&t| t == "@") else {
            continue;
        };
        if at < 1 || at + 1 >= toks.len() {
            continue;
        }
        let ty = toks.first().map(|s| (*s).to_string());
        let (Ok(count), Ok(start)) = (toks[at - 1].parse::<u32>(), toks[at + 1].parse::<u32>())
        else {
            continue;
        };
        v.push(OracleEntry {
            type_name: ty,
            start,
            count,
        });
    }
    v
}

fn run(tool: &str, args: &[&str]) -> String {
    let out = Command::new(tool)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {tool}: {e}"));
    // pdisk exits 0 but warns on stderr about unreadable DATA blocks (beyond the
    // 32 KiB head) — that does not affect the partition-MAP decode on stdout.
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The crate parses the fixture into the entries the oracle independently reports.
fn crate_entries() -> Vec<(String, u32, u32)> {
    let map = apm::parse(&fixture()).expect("crate parses the real APM fixture");
    assert_eq!(map.block_size, 512, "block size from DDM");
    map.partitions
        .iter()
        .map(|p| (p.type_name.clone(), p.start_block, p.block_count))
        .collect()
}

#[test]
fn crate_matches_mmls_oracle() {
    if !have("mmls") {
        eprintln!("SKIP crate_matches_mmls_oracle: mmls (sleuthkit) not on PATH");
        return;
    }
    let oracle = parse_mmls(&run("mmls", &["-t", "mac", &fixture_path()]));
    assert!(
        !oracle.is_empty(),
        "mmls produced no APM rows — output shape changed?"
    );
    let ours = crate_entries();

    assert_eq!(
        ours.len(),
        oracle.len(),
        "entry count: crate {} vs mmls {}",
        ours.len(),
        oracle.len()
    );
    for (i, (oe, (ty, start, count))) in oracle.iter().zip(ours.iter()).enumerate() {
        // mmls prints the partition TYPE as the description.
        if let Some(otype) = &oe.type_name {
            assert_eq!(otype, ty, "entry {i} type: mmls {otype:?} vs crate {ty:?}");
        }
        assert_eq!(oe.start, *start, "entry {i} start block vs mmls");
        assert_eq!(oe.count, *count, "entry {i} block count vs mmls");
    }
}

#[test]
fn crate_matches_pdisk_oracle() {
    if !have("pdisk") {
        eprintln!("SKIP crate_matches_pdisk_oracle: pdisk not on PATH");
        return;
    }
    let oracle = parse_pdisk(&run("pdisk", &[&fixture_path(), "-dump"]));
    assert!(
        !oracle.is_empty(),
        "pdisk produced no APM rows — output shape changed?"
    );
    let ours = crate_entries();

    assert_eq!(
        ours.len(),
        oracle.len(),
        "entry count: crate {} vs pdisk {}",
        ours.len(),
        oracle.len()
    );
    for (i, (oe, (ty, start, count))) in oracle.iter().zip(ours.iter()).enumerate() {
        if let Some(otype) = &oe.type_name {
            assert_eq!(otype, ty, "entry {i} type: pdisk {otype:?} vs crate {ty:?}");
        }
        assert_eq!(oe.start, *start, "entry {i} start block vs pdisk");
        assert_eq!(oe.count, *count, "entry {i} block count vs pdisk");
    }
}

/// The two independent oracles must agree with EACH OTHER on geometry — a guard
/// that the differential is comparing like with like (start/count), independent
/// of this crate.
#[test]
fn oracles_agree_on_geometry() {
    if !have("mmls") || !have("pdisk") {
        eprintln!("SKIP oracles_agree_on_geometry: need both mmls and pdisk");
        return;
    }
    let m = parse_mmls(&run("mmls", &["-t", "mac", &fixture_path()]));
    let p = parse_pdisk(&run("pdisk", &[&fixture_path(), "-dump"]));
    assert_eq!(m.len(), p.len(), "mmls vs pdisk entry count");
    for (i, (me, pe)) in m.iter().zip(p.iter()).enumerate() {
        assert_eq!(me.start, pe.start, "entry {i} start: mmls vs pdisk");
        assert_eq!(me.count, pe.count, "entry {i} count: mmls vs pdisk");
    }
}
