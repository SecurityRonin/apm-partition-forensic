//! `apm-forensic` — analyse the Apple Partition Map of a disk image.
//!
//! Usage:
//!   apm-forensic <image>          # human-readable report
//!   apm-forensic --json <image>   # JSON (requires the `serde` feature)

use std::fs::File;
use std::process::ExitCode;

/// Cap on bytes read from the image: the APM lives in the first blocks.
const MAX_BYTES: usize = 1 << 20;

fn main() -> ExitCode {
    let mut json = false;
    let mut path: Option<String> = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                eprintln!("usage: apm-forensic [--json] <image>");
                return ExitCode::from(2);
            }
            _ => path = Some(arg),
        }
    }
    let Some(path) = path else {
        eprintln!("usage: apm-forensic [--json] <image>");
        return ExitCode::from(2);
    };

    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("apm-forensic: cannot open {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let analysis = match apm_forensic::analyse_reader(&mut file, MAX_BYTES) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("apm-forensic: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        #[cfg(feature = "serde")]
        {
            match serde_json::to_string_pretty(&analysis) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("apm-forensic: JSON error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        #[cfg(not(feature = "serde"))]
        {
            eprintln!("apm-forensic: --json requires the `serde` feature");
            return ExitCode::from(2);
        }
    } else {
        print!("{}", apm_forensic::report::text_report(&analysis));
    }

    if analysis.anomalies.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
