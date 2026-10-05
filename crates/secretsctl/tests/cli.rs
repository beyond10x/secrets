//! The built `secretsctl` binary, run as a user would run it, for the behaviours an ESS scenario
//! cannot state (story:local-cli, Guards): no secret bytes on stdout or stderr, a value in argv
//! refused, where `put` accepts a value from, and how the configuration file is written.
//!
//! Each test gets its own directory under `CARGO_TARGET_TMPDIR`: `XDG_CONFIG_HOME` and `HOME`
//! point into it, and the keychain is the file-backed test store the `test-hooks` feature allows.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU32, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};

/// A value no output may contain, in any of the forms a leak would take.
const MARKER: &str = "sk-LEAK-MARKER-7f3a9c41";

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "secretsctl-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("home")).unwrap();
        Self { root }
    }

    fn config_file(&self) -> PathBuf {
        self.root.join("config/b10x-secrets/config.toml")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secretsctl"));
        command
            .args(args)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("HOME", self.root.join("home"))
            .env(
                "SECRETSCTL_TEST_KEYCHAIN_FILE",
                self.root.join("keychain.ron"),
            )
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    /// Runs with `input` on a pipe as stdin.
    fn piped(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn file(&self, name: &str, contents: &[u8], mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = self.root.join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn names(&self, namespace: &str) -> Vec<String> {
        let output = self.run(&["--json", "list", "--namespace", namespace]);
        assert!(output.status.success(), "{}", text(&output.stderr));
        let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        rows.as_array()
            .unwrap()
            .iter()
            .map(|row| row["name"].as_str().unwrap().to_owned())
            .collect()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Neither stream holds the marker, raw, base64-encoded or hex-encoded.
fn assert_clean(output: &Output, what: &str) {
    let forms = [
        MARKER.to_owned(),
        STANDARD.encode(MARKER),
        MARKER.bytes().map(|byte| format!("{byte:02x}")).collect(),
    ];
    for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        let shown = text(bytes);
        for form in &forms {
            assert!(
                !shown.contains(form.as_str()),
                "{what}: {stream} holds the secret: {shown}"
            );
        }
    }
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

#[test]
fn no_command_writes_secret_bytes_to_stdout_or_stderr() {
    let sandbox = Sandbox::new();
    let stored = sandbox.piped(&["put", "openai"], MARKER.as_bytes());
    assert!(stored.status.success(), "{}", text(&stored.stderr));
    assert_clean(&stored, "put");
    let exposed = sandbox.file("exposed", MARKER.as_bytes(), 0o644);
    let exposed = exposed.to_str().unwrap();
    let protected = sandbox.file("protected", MARKER.as_bytes(), 0o600);
    let protected = protected.to_str().unwrap();
    let mut runs: Vec<(Vec<&str>, Option<&[u8]>)> = vec![
        (vec!["namespace", "add", "work"], None),
        (
            vec!["put", "team/openai", "-n", "work", "--file", protected],
            None,
        ),
        (vec!["put", "openai"], Some(MARKER.as_bytes())),
        (vec!["put", "openai", "--raw"], Some(MARKER.as_bytes())),
        (vec!["put", "openai", MARKER], None),
        (vec!["put", "openai", "--value", MARKER], None),
        (vec!["put", "openai", "--file", exposed], None),
        (vec!["put", "Bad", "--file", protected], None),
        (vec!["put", "openai", "--bogus", MARKER], None),
        (vec!["put", "openai", MARKER, MARKER], None),
        (vec![MARKER], None),
        (vec!["describe", "openai", MARKER], None),
        (vec!["describe", "openai"], None),
        (vec!["describe", "missing"], None),
        (vec!["list"], None),
        (vec!["list", "--all"], None),
        (vec!["list", "-n", "work"], None),
        (vec!["namespace", "list"], None),
        (vec!["bind", "openai", "op://Work/OpenAI/credential"], None),
        (vec!["rename", "openai", "openai-work"], None),
        (vec!["unbind", "openai"], None),
        (vec!["rename", "openai", "openai-work"], None),
        (vec!["mount", "set", "work", "remote/prod"], None),
        (vec!["namespace", "remove", "work"], None),
        (vec!["delete", "openai-work"], None),
        (vec!["delete", "openai-work"], None),
    ];
    // Every run again under --json, which renders results and refusals another way.
    let json: Vec<_> = runs
        .iter()
        .map(|(args, input)| {
            let mut args = args.clone();
            args.insert(0, "--json");
            (args, *input)
        })
        .collect();
    runs.extend(json);
    for (args, input) in runs {
        let output = match input {
            Some(input) => sandbox.piped(&args, input),
            None => sandbox.run(&args),
        };
        assert_clean(&output, &args.join(" "));
    }
    let config = fs::read_to_string(sandbox.config_file()).unwrap();
    assert!(
        !config.contains(MARKER),
        "the configuration holds the secret"
    );
}

#[test]
fn put_refuses_a_value_in_argv_and_stores_nothing() {
    let sandbox = Sandbox::new();
    let attached = format!("--value={MARKER}");
    for args in [
        vec!["put", "openai", MARKER],
        vec!["put", "openai", "--value", MARKER],
        vec!["put", "openai", &attached],
        vec!["put", "openai", "--", MARKER],
        vec!["put", "openai", "-n", "default", MARKER],
    ] {
        // A pipe is offered too, so a refusal is the argv rule and not a missing value.
        let output = sandbox.piped(&args, b"from-the-pipe");
        assert_eq!(code(&output), 2, "{args:?}: {}", text(&output.stderr));
        assert!(text(&output.stderr).contains("never takes a value on the command line"));
        assert_clean(&output, &args.join(" "));
    }
    assert!(sandbox.names("default").is_empty());
}

#[test]
fn put_takes_a_value_from_a_pipe_and_drops_one_trailing_newline() {
    let sandbox = Sandbox::new();
    let output = sandbox.piped(&["--json", "put", "openai"], b"first\n");
    assert!(output.status.success(), "{}", text(&output.stderr));
    let created: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(created["outcome"], "created");
    assert_eq!(created["scope"]["tenant"], "default");
    assert_eq!(created["scope"]["user"], "default");
    assert_eq!(created["backend"]["kind"], "keychain");
    let output = sandbox.piped(&["--json", "put", "openai", "--raw"], b"second\n");
    let replaced: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(replaced["outcome"], "replaced");
    assert_ne!(created["version"], replaced["version"]);
}

#[test]
fn put_refuses_a_file_its_group_or_others_can_access_and_takes_a_protected_one() {
    let sandbox = Sandbox::new();
    for mode in [0o644, 0o640, 0o604, 0o660, 0o606, 0o620, 0o602] {
        let path = sandbox.file(&format!("value-{mode:o}"), MARKER.as_bytes(), mode);
        let output = sandbox.run(&["put", "openai", "--file", path.to_str().unwrap()]);
        assert_eq!(code(&output), 2, "mode {mode:o}");
        assert!(text(&output.stderr).contains("chmod 600"), "mode {mode:o}");
        assert_clean(&output, &format!("mode {mode:o}"));
    }
    assert!(sandbox.names("default").is_empty());
    for mode in [0o600, 0o400] {
        let path = sandbox.file(&format!("value-{mode:o}"), MARKER.as_bytes(), mode);
        let output = sandbox.run(&["put", "openai", "--file", path.to_str().unwrap()]);
        assert!(
            output.status.success(),
            "mode {mode:o}: {}",
            text(&output.stderr)
        );
    }
    let directory = sandbox.root.join("a-directory");
    fs::create_dir_all(&directory).unwrap();
    let output = sandbox.run(&["put", "openai", "--file", directory.to_str().unwrap()]);
    assert_eq!(code(&output), 2);
    assert_eq!(sandbox.names("default"), vec!["openai".to_owned()]);
}

#[test]
fn put_refuses_stdin_that_is_neither_a_terminal_nor_a_pipe() {
    let sandbox = Sandbox::new();
    let path = sandbox.file("redirected", MARKER.as_bytes(), 0o644);
    let output = sandbox
        .command(&["put", "openai"])
        .stdin(fs::File::open(&path).unwrap())
        .output()
        .unwrap();
    assert_eq!(code(&output), 2, "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("neither a terminal nor a pipe"));
    let output = sandbox.run(&["put", "openai"]); // stdin is /dev/null, a character device
    assert_eq!(code(&output), 2);
    assert!(sandbox.names("default").is_empty());
}

#[test]
fn a_value_over_one_mib_is_too_large() {
    let sandbox = Sandbox::new();
    let output = sandbox.piped(&["put", "big", "--raw"], &vec![b'a'; 1024 * 1024 + 1]);
    assert_eq!(code(&output), 8, "{}", text(&output.stderr));
    assert!(text(&output.stderr).starts_with("secretsctl: too-large"));
    let output = sandbox.piped(&["put", "big", "--raw"], &vec![b'a'; 1024 * 1024]);
    assert!(output.status.success(), "{}", text(&output.stderr));
}

#[cfg(unix)]
#[test]
fn the_configuration_is_written_atomically_with_mode_0600_and_holds_no_secret() {
    use std::os::unix::fs::PermissionsExt as _;
    let sandbox = Sandbox::new();
    assert!(sandbox.run(&["namespace", "add", "work"]).status.success());
    assert!(
        sandbox
            .piped(&["put", "openai", "-n", "work"], MARKER.as_bytes())
            .status
            .success()
    );
    assert!(
        sandbox
            .run(&[
                "bind",
                "openai",
                "op://Work/OpenAI/credential",
                "-n",
                "work"
            ])
            .status
            .success()
    );
    let path = sandbox.config_file();
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    let config = fs::read_to_string(&path).unwrap();
    assert!(!config.contains(MARKER));
    let table: toml::Table = toml::from_str(&config).unwrap();
    assert_eq!(table["namespace"].as_array().unwrap().len(), 2);
    assert_eq!(
        table["binding"][0]["locator"].as_str(),
        Some("op://Work/OpenAI/credential")
    );
    let leftovers: Vec<String> = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn without_xdg_config_home_the_configuration_lives_under_home_dot_config() {
    let sandbox = Sandbox::new();
    let output = sandbox
        .command(&["namespace", "add", "work"])
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        sandbox
            .root
            .join("home/.config/b10x-secrets/config.toml")
            .is_file()
    );
    assert!(!sandbox.config_file().exists());
}

#[test]
fn a_configuration_file_that_cannot_be_used_is_unavailable() {
    let sandbox = Sandbox::new();
    let path = sandbox.config_file();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "not toml [").unwrap();
    let output = sandbox.run(&["namespace", "list"]);
    assert_eq!(code(&output), 6, "{}", text(&output.stderr));
    assert!(text(&output.stderr).starts_with("secretsctl: unavailable"));
    assert_eq!(fs::read_to_string(&path).unwrap(), "not toml [");
}

#[test]
fn a_remote_token_comes_from_its_variable_or_a_protected_file_and_never_from_the_config() {
    let sandbox = Sandbox::new();
    let token = sandbox.file("token", b"token-from-file", 0o644);
    let path = sandbox.config_file();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        format!(
            "[backends.remote.env]\norigin = \"http://127.0.0.1:9/\"\ntoken_env = \"SECRETSCTL_TEST_TOKEN\"\n\
             [backends.remote.file]\norigin = \"http://127.0.0.1:9/\"\ntoken_file = {:?}\n\
             [backends.remote.inline]\norigin = \"http://127.0.0.1:9/\"\ntoken = \"inline\"\n",
            token.to_str().unwrap()
        ),
    )
    .unwrap();
    // An inline token is not a field the backends table has: the table is refused whole.
    let output = sandbox.run(&["namespace", "add", "a", "--mount", "remote/env"]);
    assert_eq!(code(&output), 3, "{}", text(&output.stderr));
    fs::write(
        &path,
        format!(
            "[backends.remote.env]\norigin = \"http://127.0.0.1:9/\"\ntoken_env = \"SECRETSCTL_TEST_TOKEN\"\n\
             [backends.remote.file]\norigin = \"http://127.0.0.1:9/\"\ntoken_file = {:?}\n",
            token.to_str().unwrap()
        ),
    )
    .unwrap();
    for (namespace, mount) in [("a", "remote/env"), ("b", "remote/file")] {
        let output = sandbox.run(&["namespace", "add", namespace, "--mount", mount]);
        assert!(output.status.success(), "{}", text(&output.stderr));
    }
    let output = sandbox
        .command(&["list", "-n", "a"])
        .env_remove("SECRETSCTL_TEST_TOKEN")
        .output()
        .unwrap();
    assert_eq!(code(&output), 6);
    assert!(text(&output.stderr).contains("`SECRETSCTL_TEST_TOKEN` is unset"));
    let output = sandbox.run(&["list", "-n", "b"]);
    assert_eq!(code(&output), 6);
    assert!(text(&output.stderr).contains("token file: the file is accessible"));
    assert!(!text(&output.stderr).contains("token-from-file"));
}

#[cfg(not(feature = "native-keychain"))]
#[test]
fn without_the_native_keychain_feature_the_keychain_is_unavailable_and_says_why() {
    let sandbox = Sandbox::new();
    let output = sandbox
        .command(&["put", "openai"])
        .env_remove("SECRETSCTL_TEST_KEYCHAIN_FILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(MARKER.as_bytes())?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(code(&output), 6, "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("--features native-keychain"));
    assert_clean(&output, "put without a keychain");
}

#[test]
fn each_storage_refusal_has_its_own_exit_code() {
    let sandbox = Sandbox::new();
    assert_eq!(code(&sandbox.run(&["describe", "missing"])), 3);
    assert_eq!(code(&sandbox.run(&["describe", "Bad"])), 7);
    assert_eq!(code(&sandbox.run(&["namespace", "remove", "default"])), 9);
    assert_eq!(
        code(&sandbox.run(&["mount", "set", "default", "nope/x"])),
        2
    );
    let output = sandbox.run(&["--json", "describe", &"a".repeat(129)]);
    assert_eq!(code(&output), 7);
    let refusal: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(refusal["error"], "invalid-name");
    assert_eq!(refusal["part"], "name");
    assert_eq!(refusal["reason"], "too-long");
}

/// story:readonly-test-backend: a `test-hooks` build mounts the read-only, binding-required fake
/// for `[backends.onepassword.<label>]`; writes, deletes, renames and listings on it are
/// `unsupported` (5).
#[test]
fn a_test_hooks_build_mounts_the_read_only_fake_for_the_onepassword_kind() {
    let sandbox = Sandbox::new();
    let path = sandbox.config_file();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"[backends.onepassword.vault]\n").unwrap();
    let added = sandbox.run(&["namespace", "add", "vault", "--mount", "onepassword/vault"]);
    assert!(added.status.success(), "{}", text(&added.stderr));
    let written = sandbox.piped(&["put", "openai", "-n", "vault"], MARKER.as_bytes());
    assert_eq!(code(&written), 5, "{}", text(&written.stderr));
    assert_clean(&written, "put on a read-only mount");
    for args in [
        &["delete", "openai", "-n", "vault"][..],
        &["rename", "openai", "openai-work", "-n", "vault"][..],
        &["list", "-n", "vault"][..],
    ] {
        assert_eq!(code(&sandbox.run(args)), 5, "{args:?}");
    }
}

#[test]
fn a_remote_origin_must_be_https_unless_its_host_is_loopback() {
    let sandbox = Sandbox::new();
    let origins = [
        ("plain", "http://secrets.example/", false),
        ("private", "http://10.0.0.1:9/", false),
        ("other", "ftp://127.0.0.1:9/", false),
        ("tls", "https://127.0.0.1:9/", true),
        ("loopback4", "http://127.0.0.1:9/", true),
        ("loopback6", "http://[::1]:9/", true),
        ("localhost", "http://localhost:9/", true),
    ];
    let mut config = String::new();
    for (label, origin, _) in origins {
        config.push_str(&format!(
            "[backends.remote.{label}]\norigin = {origin:?}\ntoken_env = \"SECRETSCTL_TEST_TOKEN\"\n"
        ));
    }
    let path = sandbox.config_file();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, config).unwrap();
    for (label, _, admitted) in origins {
        let mount = format!("remote/{label}");
        let output = sandbox.run(&["namespace", "add", label, "--mount", &mount]);
        assert!(output.status.success(), "{}", text(&output.stderr));
        // Nothing listens on these origins, so every listing is unavailable; what differs is
        // whether the origin was refused before any request carried the token.
        let output = sandbox
            .command(&["list", "-n", label])
            .env("SECRETSCTL_TEST_TOKEN", MARKER)
            .output()
            .unwrap();
        assert_eq!(code(&output), 6, "{label}: {}", text(&output.stderr));
        let note = format!("remote/{label}: `origin` must be https");
        assert_eq!(
            !text(&output.stderr).contains(&note),
            admitted,
            "{label}: {}",
            text(&output.stderr)
        );
        assert_clean(&output, label);
    }
}
