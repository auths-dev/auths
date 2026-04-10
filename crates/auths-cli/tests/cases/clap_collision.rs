//! Regression test: ensure no clap argument name collisions between
//! global flags and subcommand flags (e.g., the --format collision
//! fixed in Epic 1.1).

use assert_cmd::Command;

/// Subcommands that have their own `--format` or `--output` flags.
/// Running `--help` on each is enough to trigger clap's duplicate-argument
/// panic if a collision exists.
const SUBCOMMANDS_WITH_FORMAT: &[&[&str]] = &[
    &["key", "export", "--help"],
    &["key", "list", "--help"],
    &["key", "import", "--help"],
    &["key", "delete", "--help"],
    &["key", "copy-backend", "--help"],
];

/// All top-level subcommands — `--help` must never panic.
const ALL_SUBCOMMANDS: &[&[&str]] = &[
    &["init", "--help"],
    &["sign", "--help"],
    &["verify", "--help"],
    &["artifact", "--help"],
    &["status", "--help"],
    &["whoami", "--help"],
    &["pair", "--help"],
    &["trust", "--help"],
    &["doctor", "--help"],
    &["config", "--help"],
    &["completions", "--help"],
    &["id", "--help"],
    &["device", "--help"],
    &["key", "--help"],
    &["policy", "--help"],
    &["debug", "--help"],
];

#[test]
fn key_export_format_flag_does_not_panic() {
    for args in SUBCOMMANDS_WITH_FORMAT {
        let output = Command::cargo_bin("auths")
            .unwrap()
            .args(*args)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "`auths {}` exited with non-zero status.\nstderr: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn all_subcommand_help_pages_do_not_panic() {
    for args in ALL_SUBCOMMANDS {
        let output = Command::cargo_bin("auths")
            .unwrap()
            .args(*args)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "`auths {}` panicked or failed.\nstderr: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
