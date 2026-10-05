//! Invariants of the local commands from the independent security review of story:local-cli,
//! run against the built binary with feature `test-hooks`: links never redirect a write or a
//! read, a FIFO named by `--file` is refused at once, a socket on stdin is a pipe, `namespace
//! list` shows the local tenant only, and a remote token never reaches output.
#![cfg(all(unix, feature = "test-hooks"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Write as _,
    os::unix::{fs::PermissionsExt as _, net::UnixStream},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

const MARKER: &str = "sk-REVIEW-MARKER-31c0de55";

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "secretsctl-review-{}-{}",
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

    fn file(&self, name: &str, contents: &[u8], mode: u32) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn write_config(&self, text: &str) {
        let path = self.config_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn assert_clean(output: &Output, secret: &str, what: &str) {
    for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        assert!(
            !text(bytes).contains(secret),
            "{what}: {stream} holds the secret: {}",
            text(bytes)
        );
    }
}

/// Invariant 3: a symlink at `config.toml` or at its `.lock` sibling never carries a write to the
/// file it points at. The write replaces the link with a fresh mode-0600 file.
#[test]
fn a_symlinked_config_or_lock_file_never_redirects_a_write() {
    let sandbox = Sandbox::new();
    let directory = sandbox.config_file().parent().unwrap().to_owned();
    fs::create_dir_all(&directory).unwrap();
    let victim = sandbox.file("victim", b"# victim contents\n", 0o644);
    let lock_victim = sandbox.file("lock-victim", b"lock victim contents\n", 0o644);
    std::os::unix::fs::symlink(&victim, sandbox.config_file()).unwrap();
    std::os::unix::fs::symlink(&lock_victim, directory.join("config.toml.lock")).unwrap();

    let output = sandbox.run(&["namespace", "add", "work"]);
    assert!(output.status.success(), "{}", text(&output.stderr));

    assert_eq!(fs::read(&victim).unwrap(), b"# victim contents\n");
    assert_eq!(fs::read(&lock_victim).unwrap(), b"lock victim contents\n");
    let written = fs::symlink_metadata(sandbox.config_file()).unwrap();
    assert!(written.file_type().is_file(), "config.toml is still a link");
    assert_eq!(written.permissions().mode() & 0o777, 0o600);
}

/// Invariant 2: `--file` through a symlink is judged by the file it reaches, not by the link.
#[test]
fn put_file_through_a_symlink_is_judged_by_its_target() {
    let sandbox = Sandbox::new();
    let exposed = sandbox.file("exposed", MARKER.as_bytes(), 0o644);
    let protected = sandbox.file("protected", MARKER.as_bytes(), 0o600);
    let to_exposed = sandbox.root.join("to-exposed");
    let to_protected = sandbox.root.join("to-protected");
    std::os::unix::fs::symlink(&exposed, &to_exposed).unwrap();
    std::os::unix::fs::symlink(&protected, &to_protected).unwrap();

    let output = sandbox.run(&["put", "openai", "--file", to_exposed.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("chmod 600"));
    assert_clean(&output, MARKER, "link to an exposed file");

    let output = sandbox.run(&["put", "openai", "--file", to_protected.to_str().unwrap()]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_clean(&output, MARKER, "link to a protected file");
}

/// Invariant 2 / story:local-cli Scenarios: `--file` naming a FIFO is "not a regular file" and
/// is refused at once. `File::open` without `O_NONBLOCK` waits for a writer instead, before
/// the regular-file check is reached (value.rs `read_protected`).
#[test]
fn put_file_naming_a_fifo_is_refused_without_waiting_for_a_writer() {
    let sandbox = Sandbox::new();
    let fifo = sandbox.root.join("value.fifo");
    let made = Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    let mut child = sandbox
        .command(&["put", "openai", "--file", fifo.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let finished = child.try_wait().unwrap().is_some();
    if !finished {
        let _ = child.kill();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        finished,
        "put --file <fifo> was still waiting for a writer after 5s"
    );
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("not a regular file"));
}

/// Invariant 2 / story:local-cli Scenarios: put accepts a hidden prompt, a pipe, FIFO or socket on
/// stdin, or a protected file. A socket counts as a pipe because process spawners such as libuv
/// hand stdio over socketpairs; the value is stored and never printed.
#[test]
fn put_accepts_a_socket_on_stdin_as_a_pipe() {
    let sandbox = Sandbox::new();
    let (ours, theirs) = UnixStream::pair().unwrap();
    let child = sandbox
        .command(&["put", "openai"])
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(theirs)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut ours = ours;
        ours.write_all(MARKER.as_bytes()).unwrap();
        ours.shutdown(std::net::Shutdown::Both).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert_clean(&output, MARKER, "put from a socket");
    assert!(
        output.status.success(),
        "a socket on stdin was refused: {}",
        text(&output.stderr)
    );
    let listed = sandbox.run(&["--json", "list"]);
    let rows: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(rows[0]["name"], "openai");
    assert_clean(&listed, MARKER, "list after a put from a socket");
}

/// Invariant 6: the local CLI acts on tenant `default` only. `namespace list` is authorized for
/// tenant `default` (local.rs `namespace_list`) and then prints every record the configuration
/// holds, of any tenant; `list --all` filters to tenant `default`, this command does not.
#[test]
fn namespace_list_shows_tenant_default_only() {
    let sandbox = Sandbox::new();
    sandbox.write_config(
        "[[namespace]]\ntenant = \"default\"\nname = \"default\"\n\n\
         [[namespace]]\ntenant = \"acme\"\nname = \"ops\"\n",
    );
    let output = sandbox.run(&["--json", "namespace", "list"]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let tenants: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["namespace"]["tenant"].as_str().unwrap())
        .collect();
    assert!(
        tenants.iter().all(|tenant| *tenant == "default"),
        "namespace list printed another tenant's namespace: {tenants:?}"
    );
}

/// Invariant 4: a remote token from its variable or its protected file never reaches stdout or
/// stderr, on the path where the remote cannot be reached and every command fails.
#[test]
fn a_remote_token_never_reaches_output_when_the_remote_fails() {
    let sandbox = Sandbox::new();
    let token = sandbox.file("token", MARKER.as_bytes(), 0o600);
    sandbox.write_config(&format!(
        "[backends.remote.env]\norigin = \"http://127.0.0.1:9/\"\ntoken_env = \"REVIEW_TOKEN\"\n\
         [backends.remote.file]\norigin = \"http://127.0.0.1:9/\"\ntoken_file = {:?}\n",
        token.to_str().unwrap()
    ));
    for (namespace, mount) in [("a", "remote/env"), ("b", "remote/file")] {
        let output = sandbox
            .command(&["namespace", "add", namespace, "--mount", mount])
            .env("REVIEW_TOKEN", MARKER)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", text(&output.stderr));
    }
    for namespace in ["a", "b"] {
        for args in [
            vec!["list", "-n", namespace],
            vec!["describe", "x", "-n", namespace],
            vec!["delete", "x", "-n", namespace],
            vec!["rename", "x", "y", "-n", namespace],
            vec!["--json", "list", "-n", namespace],
            vec!["--json", "list", "--all"],
        ] {
            let output = sandbox
                .command(&args)
                .env("REVIEW_TOKEN", MARKER)
                .output()
                .unwrap();
            assert!(!output.status.success(), "{args:?} succeeded");
            assert_clean(&output, MARKER, &args.join(" "));
        }
        let mut child = sandbox
            .command(&["put", "x", "-n", namespace])
            .env("REVIEW_TOKEN", MARKER)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"value").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert_clean(&output, MARKER, "put on a remote that cannot be reached");
    }
}
