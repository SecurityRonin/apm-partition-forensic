//! Coverage for the crate `Error` type: Display, `From<io::Error>`, and source.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apm_forensic::Error;
use std::error::Error as _;

#[test]
fn display_renders_every_variant() {
    assert!(!Error::NotApm.to_string().is_empty());
    assert!(Error::TooShort { need: 512, got: 8 }
        .to_string()
        .contains("512"));
    let io: Error = std::io::Error::other("boom").into();
    assert!(io.to_string().contains("boom"));
}

#[test]
fn source_is_present_only_for_io() {
    let io: Error = std::io::Error::other("boom").into();
    assert!(io.source().is_some(), "Io wraps an underlying error");
    assert!(Error::NotApm.source().is_none());
    assert!(Error::TooShort { need: 1, got: 0 }.source().is_none());
}
