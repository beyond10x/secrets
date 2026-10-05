//! Invariant 5 of the independent security review of story:local-cli: in a build without feature
//! `test-hooks`, `SECRETSCTL_TEST_KEYCHAIN_FILE` is never read. The keychain stays unavailable,
//! nothing is stored, and the named file is neither created nor changed.
//!
//! Compiled only without `test-hooks` and without `native-keychain`, so the binary under test is
//! the default build and no run reaches the OS keychain:
//! `cargo test -p secretsctl --test review_default_build`.
#![cfg(all(unix, not(feature = "test-hooks"), not(feature = "native-keychain")))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Write as _,
    path::PathBuf,
    process::{Command, Stdio},
};

#[test]
fn the_test_keychain_variable_is_inert_in_a_default_build() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("secretsctl-review-default-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("home")).unwrap();
    let keychain = root.join("keychain.ron");
    let preexisting = root.join("preexisting.ron");
    fs::write(&preexisting, b"(not a keychain)").unwrap();

    for file in [&keychain, &preexisting] {
        let before = fs::read(file).ok();
        let mut child = Command::new(env!("CARGO_BIN_EXE_secretsctl"))
            .args(["put", "openai"])
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("HOME", root.join("home"))
            .env("SECRETSCTL_TEST_KEYCHAIN_FILE", file)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"value").unwrap();
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(6), "{stderr}");
        assert!(stderr.contains("--features native-keychain"), "{stderr}");
        assert!(!stderr.contains("test keychain"), "{stderr}");
        assert_eq!(fs::read(file).ok(), before, "{} changed", file.display());
    }
    assert!(!keychain.exists(), "the test keychain file was created");
}

/// story:readonly-test-backend: only a `test-hooks` build reads `[backends.onepassword.<label>]`
/// and mounts the recording fake for it. A default build refuses a `backends` table that names
/// the kind, so the label is no configured backend and nothing can be mounted on it.
#[test]
fn a_default_build_cannot_mount_the_read_only_fake() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("secretsctl-review-fake-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("home")).unwrap();
    let config = root.join("config/b10x-secrets/config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, b"[backends.onepassword.vault]\n").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_secretsctl"))
            .args(args)
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("HOME", root.join("home"))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    for args in [
        &[
            "--json",
            "namespace",
            "add",
            "vault",
            "--mount",
            "onepassword/vault",
        ][..],
        &["--json", "mount", "set", "default", "onepassword/vault"][..],
    ] {
        let output = run(args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // 3 is `not-found`: the mount names no configured backend.
        assert_eq!(output.status.code(), Some(3), "{args:?}: {stderr}");
        assert!(stderr.contains("\"error\":\"not-found\""), "{stderr}");
    }
    let listed = run(&["--json", "namespace", "list"]);
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(!listed.contains("onepassword"), "{listed}");
}
