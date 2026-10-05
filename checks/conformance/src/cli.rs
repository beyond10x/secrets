//! `secrets.storage` through the built `secretsctl` binary (story:local-cli).
//!
//! The suite this answers is `contracts/cli-suite.json`: the library's generated scenarios and the
//! authored ones under `contracts/storage/scenarios/cli`, synthesized for `secrets-library`, since
//! the CLI is that library behind a command line. Every command is one run of the binary, built
//! with feature `test-hooks`, in a scenario directory of its own: `XDG_CONFIG_HOME` and `HOME`
//! point into it, the environment is otherwise empty, and `SECRETSCTL_TEST_KEYCHAIN_FILE` puts
//! the keychain on a file-backed test store there. A scenario that mounts the remote backend gets
//! the custody service the library scenarios use, on a loopback port, configured in the
//! scenario's `config.toml` with its token in a mode-0600 file.
//!
//! # How an outcome is reached
//!
//! The raw input becomes the binary's argv (`--json`, names after `--`) and, for `Write`, the
//! value on a pipe. The declared branch is read off what the binary answered: its exit status, the
//! closed code and name rule in its JSON refusal, the `created`/`replaced` it printed, and what
//! the world held when the command began:
//!
//! * a `not-found` from `Delete` or `Rename` is `not-found` when the namespace existed, and
//!   resolution's `unresolved` when it did not; from `Write` or `ListMetadata` it is `unresolved`;
//! * a `conflict` from `Rename` is `bound` when either name was bound, otherwise `taken`;
//! * a `conflict` from `RemoveNamespace` is `is-default` for namespace `default`, otherwise
//!   `in-use`;
//! * a `not-found` from `SetMount` is `no-backend` when the namespace existed, otherwise
//!   `no-namespace`.
//!
//! The in-process target also proves that exactly one backend was reached; from outside the
//! process that is not observable, and the library suite keeps that claim.
//!
//! # Arrangement
//!
//! As the in-process target arranges (see [`crate::storage`]), directly on the scenario's files:
//! namespaces and bindings through `secrets_federation::FileConfig` on the same `config.toml`,
//! fixture secrets through the keychain backend on the same test store file (opened, used, saved
//! and closed before the binary runs) or through the custody service. A forced `unavailable` makes
//! the configuration file, or the keychain file, unreadable for that one command, or takes the
//! custody database down; the file is restored byte for byte afterwards.
//!
//! # What stays unsupported
//!
//! * a scope other than tenant and user `default`: the CLI acts on the local scope only, so every
//!   `denied` and `denied-user` scenario;
//! * `Read`: the CLI has no command that prints a value;
//! * a read-only mount (kind `onepassword`, and so every forced `unsupported`): no 1Password backend
//!   exists this round.
//!
//! # Views
//!
//! `SecretMetadata` is `list --json` over every scope the scenario addressed, and each row is
//! checked against `describe --json` for its name: a describe that disagrees with the listing is a
//! target error, so every view read also exercises `describe`. `Namespaces` is
//! `namespace list --json`.
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ess_conformance::target::{TargetError, ViewRow};
use ess_primitives::node::Node;
use keyring_core::CredentialStore;
use secrets_core::storage::{
    Address, BackendKind, BackendRef, NameError, NamespaceKey, Scope, ScopeName, SecretName,
    SecretStorage, SecretValue, StorageError, Target,
};
use secrets_federation::{FileConfig, Namespace, NamespaceConfig};
use secrets_keychain::{DEFAULT_SERVICE, KeychainBackend};
use secrets_remote::RemoteBackend;
use serde_json::Value;

use crate::fixture::Admin;
use crate::storage::{
    ACTOR, FIXTURE_LOCATOR, FIXTURE_NAME, FIXTURE_VALUE, R, Remote, VALUE_LIMIT, cannot_arrange,
    declared, event, namespace_key, node, segmented, set, text,
};
use crate::target::{Observed, unavailable};

/// What a CLI command is handed.
pub struct CliContext<'a> {
    pub runtime: &'a tokio::runtime::Runtime,
    pub admin: &'a Admin,
    pub world: &'a mut World,
    pub forced: Option<String>,
    pub actor: Option<String>,
}

/// The `secretsctl` this run drives: built once, with feature `test-hooks`, by the cargo that runs
/// this runner.
fn binary() -> Result<PathBuf, String> {
    static BINARY: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let output = Command::new(cargo)
                .args([
                    "build",
                    "--locked",
                    "-p",
                    "secretsctl",
                    "--features",
                    "test-hooks",
                    "--message-format=json-render-diagnostics",
                ])
                .stderr(Stdio::inherit())
                .output()
                .map_err(|error| format!("running cargo: {error}"))?;
            if !output.status.success() {
                return Err("building secretsctl failed; see diagnostics above".to_owned());
            }
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|message| {
                    message["reason"] == "compiler-artifact"
                        && message["target"]["name"] == "secretsctl"
                })
                .find_map(|message| message["executable"].as_str().map(PathBuf::from))
                .ok_or_else(|| "cargo built no secretsctl executable".to_owned())
        })
        .clone()
}

/// The keychain service a keychain label's entries are kept under. Written into the scenario's
/// configuration for every label but `default`, so the binary is told it rather than trusted to
/// derive it.
fn service(label: &ScopeName) -> String {
    if label.is_default() {
        DEFAULT_SERVICE.to_owned()
    } else {
        format!("{DEFAULT_SERVICE}.{label}")
    }
}

fn kind_text(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Keychain => "keychain",
        BackendKind::Onepassword => "onepassword",
        BackendKind::Remote => "remote",
    }
}

/// A condition flipped on for exactly one command and off after it.
enum Switch {
    /// The file is unreadable as what it holds; `original` is put back afterwards.
    Corrupt {
        path: PathBuf,
        original: Option<Vec<u8>>,
    },
    RemoteDown,
}

/// One scenario's directory, the backends configured in it and what it addressed.
pub struct World {
    root: PathBuf,
    binary: PathBuf,
    configured: BTreeSet<BackendRef>,
    remote: Option<Remote>,
    scopes: BTreeSet<Scope>,
}

impl World {
    /// A fresh directory under `target/conformance/cli`, with nothing in it: local mode's
    /// starting point is the binary's own.
    pub fn open() -> Result<Self, Box<dyn Error>> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let binary = binary()?;
        let root = PathBuf::from("target/conformance/cli").join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("home"))?;
        Ok(Self {
            root: fs::canonicalize(root)?,
            binary,
            configured: BTreeSet::from([BackendRef::default_mount()]),
            remote: None,
            scopes: BTreeSet::new(),
        })
    }

    /// Stops the custody service, if one was started, and removes the scenario's directory.
    pub fn close(
        self,
        runtime: &tokio::runtime::Runtime,
        admin: &Admin,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(remote) = self.remote {
            remote.close(runtime, admin)?;
        }
        fs::remove_dir_all(&self.root)?;
        Ok(())
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("config/b10x-secrets/config.toml")
    }

    fn keychain_path(&self) -> PathBuf {
        self.root.join("keychain.ron")
    }

    fn config(&self) -> FileConfig {
        FileConfig::new(self.config_path())
    }

    /// One run of the binary, with `input` on a pipe when given and stdin empty otherwise.
    fn run(&self, args: &[String], input: Option<&[u8]>) -> R<Output> {
        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .env_clear()
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("HOME", self.root.join("home"))
            .env("SECRETSCTL_TEST_KEYCHAIN_FILE", self.keychain_path())
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| unavailable("running secretsctl", error))?;
        if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
            // A command that refuses before reading closes the pipe; that is its answer.
            let _ = stdin.write_all(input);
        }
        child
            .wait_with_output()
            .map_err(|error| unavailable("running secretsctl", error))
    }

    /// Runs the binary on its own result rows: `--json` output that must parse.
    fn rows(&self, args: &[&str]) -> R<Option<Vec<Value>>> {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        let output = self.run(&args, None)?;
        match output.status.code() {
            Some(0) => serde_json::from_slice::<Vec<Value>>(&output.stdout)
                .map(Some)
                .map_err(|error| unavailable("reading secretsctl's rows", error)),
            // not-found (the namespace is gone) and unsupported hold no row.
            Some(3 | 5) => Ok(None),
            _ => Err(unavailable(
                "reading through secretsctl",
                String::from_utf8_lossy(&output.stderr),
            )),
        }
    }

    /// Writes one backend into the configuration's `backends` table, keeping every other key.
    fn write_backend(&self, backend: &BackendRef, entry: toml::Table) -> R<()> {
        let path = self.config_path();
        let mut table: toml::Table = match fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).map_err(cannot_arrange)?,
            Err(_) => toml::Table::new(),
        };
        let backends = table
            .entry("backends")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(|| cannot_arrange("`backends` is not a table"))?;
        backends
            .entry(kind_text(backend.kind))
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(|| cannot_arrange("a backend kind is not a table"))?
            .insert(backend.label.to_string(), toml::Value::Table(entry));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(cannot_arrange)?;
        }
        fs::write(
            &path,
            toml::to_string(&table).map_err(cannot_arrange)?.as_bytes(),
        )
        .map_err(cannot_arrange)
    }

    /// Configures the backend a scenario names, as an operator would by editing `config.toml`.
    fn configure(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        admin: &Admin,
        backend: &BackendRef,
    ) -> R<()> {
        if self.configured.contains(backend) {
            return Ok(());
        }
        let mut entry = toml::Table::new();
        match backend.kind {
            BackendKind::Keychain => {
                entry.insert(
                    "service".to_owned(),
                    toml::Value::String(service(&backend.label)),
                );
            }
            BackendKind::Remote => {
                if self.remote.is_none() {
                    self.remote = Some(Remote::start(runtime, admin)?);
                }
                let remote = self
                    .remote
                    .as_ref()
                    .ok_or_else(|| cannot_arrange("no custody service"))?;
                let token = self.root.join("token");
                write_private(&token, remote.token.as_bytes())?;
                entry.insert(
                    "origin".to_owned(),
                    toml::Value::String(remote.origin.clone()),
                );
                entry.insert(
                    "token_file".to_owned(),
                    toml::Value::String(token.to_string_lossy().into_owned()),
                );
            }
            BackendKind::Onepassword => return Err(read_only_unsupported()),
        }
        self.write_backend(backend, entry)?;
        self.configured.insert(backend.clone());
        Ok(())
    }

    /// Runs `operation` on the backend `mount` names, outside the binary: a keychain over the
    /// scenario's test store file, opened, used, saved and closed here; the remote over the custody
    /// service.
    fn on_backend<T>(
        &self,
        runtime: &tokio::runtime::Runtime,
        mount: &BackendRef,
        operation: impl FnOnce(&tokio::runtime::Runtime, &dyn SecretStorage) -> R<T>,
    ) -> R<T> {
        match mount.kind {
            BackendKind::Keychain => {
                let path = self.keychain_path();
                let store = keyring_core::sample::Store::new_with_backing(
                    path.to_str()
                        .ok_or_else(|| cannot_arrange("a non-UTF-8 keychain path"))?,
                )
                .map_err(cannot_arrange)?;
                let backend = KeychainBackend::with_service(
                    store.clone() as Arc<CredentialStore>,
                    service(&mount.label),
                );
                let answer = operation(runtime, &backend);
                drop(backend);
                store.save().map_err(cannot_arrange)?;
                answer
            }
            BackendKind::Remote => {
                let remote = self
                    .remote
                    .as_ref()
                    .ok_or_else(|| cannot_arrange("no custody service is running"))?;
                let http = reqwest::Client::builder()
                    .no_proxy()
                    .build()
                    .map_err(cannot_arrange)?;
                let client =
                    secrets_client::Client::with_http(http, &remote.origin, remote.token.clone())
                        .map_err(cannot_arrange)?;
                operation(runtime, &RemoteBackend::new(client))
            }
            BackendKind::Onepassword => Err(read_only_unsupported()),
        }
    }

    fn flip(&self, runtime: &tokio::runtime::Runtime, admin: &Admin, switch: &Switch) -> R<()> {
        match switch {
            Switch::Corrupt { path, .. } => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(cannot_arrange)?;
                }
                fs::write(path, b"not a store [").map_err(cannot_arrange)
            }
            Switch::RemoteDown => {
                let remote = self
                    .remote
                    .as_ref()
                    .ok_or_else(|| cannot_arrange("no custody service is running"))?;
                runtime
                    .block_on(admin.take_down(&remote.scenario))
                    .map_err(cannot_arrange)
            }
        }
    }

    fn unflip(&self, runtime: &tokio::runtime::Runtime, admin: &Admin, switch: &Switch) -> R<()> {
        match switch {
            Switch::Corrupt { path, original } => match original {
                Some(bytes) => fs::write(path, bytes),
                None => fs::remove_file(path),
            }
            .map_err(|error| unavailable("restoring a file", error)),
            Switch::RemoteDown => match &self.remote {
                Some(remote) => runtime
                    .block_on(admin.bring_up(&remote.scenario))
                    .map_err(|error| unavailable("restoring the custody database", error)),
                None => Ok(()),
            },
        }
    }

    fn corrupt(path: PathBuf) -> Switch {
        let original = fs::read(&path).ok();
        Switch::Corrupt { path, original }
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> R<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(cannot_arrange)?;
    file.write_all(bytes).map_err(cannot_arrange)
}

fn read_only_unsupported() -> TargetError {
    TargetError::unsupported(
        "a read-only mount",
        "no 1Password backend exists this round (story:onepassword-backend is archived)",
    )
}

fn local_only() -> TargetError {
    TargetError::unsupported(
        "a scope other than tenant and user `default`",
        "secretsctl acts on the local scope only",
    )
}

// ---- input ----------------------------------------------------------------------------------

/// What the port would accept, for arrangement: metadata only.
enum Parsed {
    AddNamespace(NamespaceKey, Option<BackendRef>),
    RemoveNamespace(NamespaceKey),
    SetMount(NamespaceKey, BackendRef),
    Bind(Address),
    Unbind(Address),
    Write(Address),
    Delete(Address),
    Rename(Address, SecretName),
    ListMetadata(Scope),
}

impl Parsed {
    fn namespace(&self) -> NamespaceKey {
        match self {
            Self::AddNamespace(key, _) | Self::RemoveNamespace(key) | Self::SetMount(key, _) => {
                key.clone()
            }
            Self::Bind(address)
            | Self::Unbind(address)
            | Self::Write(address)
            | Self::Delete(address)
            | Self::Rename(address, _) => namespace_key(&address.scope),
            Self::ListMetadata(scope) => namespace_key(scope),
        }
    }
}

fn mount(input: &Value) -> Option<Option<BackendRef>> {
    match input.get("mount") {
        None | Some(Value::Null) => Some(None),
        Some(mount) => serde_json::from_value(mount.clone()).ok().map(Some),
    }
}

fn address(input: &Value) -> Option<Address> {
    Address::parse(
        text(input, &["address", "scope", "tenant"]).ok()?,
        text(input, &["address", "scope", "namespace"]).ok()?,
        text(input, &["address", "scope", "user"]).ok()?,
        text(input, &["address", "name"]).ok()?,
    )
    .ok()
}

fn namespace(input: &Value) -> Option<NamespaceKey> {
    NamespaceKey::parse(
        text(input, &["namespace", "tenant"]).ok()?,
        text(input, &["namespace", "namespace"]).ok()?,
    )
    .ok()
}

fn parse(command: &str, input: &Value) -> Option<Parsed> {
    Some(match command {
        "AddNamespace" => Parsed::AddNamespace(namespace(input)?, mount(input)?),
        "RemoveNamespace" => Parsed::RemoveNamespace(namespace(input)?),
        "SetMount" => Parsed::SetMount(namespace(input)?, mount(input)??),
        "Bind" => Parsed::Bind(address(input)?),
        "Unbind" => Parsed::Unbind(address(input)?),
        "Write" => Parsed::Write(address(input)?),
        "Delete" => Parsed::Delete(address(input)?),
        "Rename" => Parsed::Rename(
            address(input)?,
            SecretName::parse(text(input, &["new_name"]).ok()?).ok()?,
        ),
        "ListMetadata" => Parsed::ListMetadata(Scope {
            tenant: ScopeName::parse(text(input, &["scope", "tenant"]).ok()?).ok()?,
            namespace: ScopeName::parse(text(input, &["scope", "namespace"]).ok()?).ok()?,
            user: ScopeName::parse(text(input, &["scope", "user"]).ok()?).ok()?,
        }),
        _ => return None,
    })
}

/// Where the scope a command addresses lives in its input: (tenant, user).
fn scope_fields(command: &str) -> (&'static [&'static str], Option<&'static [&'static str]>) {
    match command {
        "AddNamespace" | "RemoveNamespace" | "SetMount" => (&["namespace", "tenant"], None),
        "ListMetadata" => (&["scope", "tenant"], Some(&["scope", "user"])),
        _ => (
            &["address", "scope", "tenant"],
            Some(&["address", "scope", "user"]),
        ),
    }
}

fn mount_arg(mount: &Value) -> R<String> {
    Ok(format!(
        "{}/{}",
        text(mount, &["kind"])?,
        text(mount, &["label"])?
    ))
}

/// The binary's argv for a command, from the raw input, and the value it reads from a pipe.
fn argv(command: &str, input: &Value) -> R<(Vec<String>, Option<Vec<u8>>)> {
    let ns = |path: &[&str]| -> R<String> { Ok(format!("--namespace={}", text(input, path)?)) };
    let name = || -> R<String> { Ok(text(input, &["address", "name"])?.to_owned()) };
    let address_ns = || ns(&["address", "scope", "namespace"]);
    let mut args: Vec<String> = vec!["--json".to_owned()];
    let mut value = None;
    match command {
        "Write" => {
            args.extend(["put".to_owned(), address_ns()?, "--raw".to_owned()]);
            args.extend(["--".to_owned(), name()?]);
            value = Some(
                STANDARD
                    .decode(text(input, &["value"])?)
                    .map_err(|error| unavailable("decoding the value", error))?,
            );
        }
        "Delete" => args.extend(["delete".to_owned(), address_ns()?, "--".to_owned(), name()?]),
        "Rename" => args.extend([
            "rename".to_owned(),
            address_ns()?,
            "--".to_owned(),
            name()?,
            text(input, &["new_name"])?.to_owned(),
        ]),
        "ListMetadata" => args.extend(["list".to_owned(), ns(&["scope", "namespace"])?]),
        "AddNamespace" => {
            args.extend(["namespace".to_owned(), "add".to_owned()]);
            if let Some(mount) = input.get("mount").filter(|mount| !mount.is_null()) {
                args.push(format!("--mount={}", mount_arg(mount)?));
            }
            args.extend([
                "--".to_owned(),
                text(input, &["namespace", "namespace"])?.to_owned(),
            ]);
        }
        "RemoveNamespace" => args.extend([
            "namespace".to_owned(),
            "remove".to_owned(),
            "--".to_owned(),
            text(input, &["namespace", "namespace"])?.to_owned(),
        ]),
        "SetMount" => {
            let mount = input
                .get("mount")
                .ok_or_else(|| unavailable("reading the command input", "mount"))?;
            args.extend([
                "mount".to_owned(),
                "set".to_owned(),
                "--".to_owned(),
                text(input, &["namespace", "namespace"])?.to_owned(),
                mount_arg(mount)?,
            ]);
        }
        "Bind" => args.extend([
            "bind".to_owned(),
            address_ns()?,
            "--".to_owned(),
            name()?,
            text(input, &["locator"])?.to_owned(),
        ]),
        "Unbind" => args.extend(["unbind".to_owned(), address_ns()?, "--".to_owned(), name()?]),
        _ => return Err(unavailable("building secretsctl's arguments", command)),
    }
    Ok((args, value))
}

/// Makes a forced port refusal's condition true on the input, as the in-process target does.
fn arrange_refusal(command: &str, outcome: &str, input: &mut Value, remote: bool) -> R<()> {
    let (path, value): (&[&str], Value) = match (command, outcome) {
        ("Write", "too-large") => (
            &["value"],
            Value::String(STANDARD.encode(vec![
                0_u8;
                if remote { VALUE_LIMIT } else { VALUE_LIMIT + 1 }
            ])),
        ),
        ("AddNamespace", "invalid-name") => (
            &["namespace", "namespace"],
            Value::String("-namespace".to_owned()),
        ),
        (_, "invalid-name") => (&["address", "name"], Value::String("a".repeat(65))),
        _ => return Err(cannot_arrange(outcome)),
    };
    set(input, path, value)
}

// ---- arrangement ----------------------------------------------------------------------------

struct Arranging<'a> {
    runtime: &'a tokio::runtime::Runtime,
    admin: &'a Admin,
    world: &'a mut World,
}

impl Arranging<'_> {
    fn namespace(&self, key: &NamespaceKey) -> R<Option<Namespace>> {
        self.runtime
            .block_on(self.world.config().namespace(key))
            .map_err(cannot_arrange)
    }

    fn ensure_namespace(&self, key: &NamespaceKey) -> R<Namespace> {
        if let Some(namespace) = self.namespace(key)? {
            return Ok(namespace);
        }
        let namespace = Namespace {
            key: key.clone(),
            mount: None,
        };
        self.runtime
            .block_on(self.world.config().insert_namespace(namespace.clone()))
            .map_err(cannot_arrange)?;
        Ok(namespace)
    }

    fn holds(&self, mount: &BackendRef, address: &Address) -> R<bool> {
        self.world
            .on_backend(self.runtime, mount, |runtime, backend| {
                match runtime.block_on(backend.read(&Target::unbound(address.clone()))) {
                    Ok(_) => Ok(true),
                    Err(StorageError::NotFound) => Ok(false),
                    Err(error) => Err(cannot_arrange(error)),
                }
            })
    }

    fn ensure_secret(&self, mount: &BackendRef, address: &Address) -> R<()> {
        if self.holds(mount, address)? {
            return Ok(());
        }
        self.world
            .on_backend(self.runtime, mount, |runtime, backend| {
                let value = SecretValue::new(FIXTURE_VALUE.to_vec()).map_err(cannot_arrange)?;
                runtime
                    .block_on(backend.write(&Target::unbound(address.clone()), value))
                    .map(drop)
                    .map_err(cannot_arrange)
            })
    }

    fn refuse_secret(&self, mount: &BackendRef, address: &Address) -> R<()> {
        if self.holds(mount, address)? {
            return Err(cannot_arrange("a secret is already stored at the address"));
        }
        Ok(())
    }

    fn clear_secret(&self, mount: &BackendRef, address: &Address) -> R<()> {
        if !self.holds(mount, address)? {
            return Ok(());
        }
        self.world
            .on_backend(self.runtime, mount, |runtime, backend| {
                runtime
                    .block_on(backend.delete(&Target::unbound(address.clone())))
                    .map_err(cannot_arrange)
            })
    }

    /// A secret in the namespace for local mode's one user.
    fn occupy(&self, namespace: &Namespace) -> R<()> {
        let scope = Scope {
            tenant: namespace.key.tenant.clone(),
            namespace: namespace.key.namespace.clone(),
            user: ScopeName::default_name(),
        };
        let mount = namespace.effective_mount();
        let listed = self
            .world
            .on_backend(self.runtime, &mount, |runtime, backend| {
                runtime
                    .block_on(backend.list(&scope))
                    .map_err(cannot_arrange)
            })?;
        if !listed.is_empty() {
            return Ok(());
        }
        let name = SecretName::parse(FIXTURE_NAME).map_err(cannot_arrange)?;
        self.ensure_secret(&mount, &Address { scope, name })
    }

    fn binding(&self, address: &Address) -> R<bool> {
        Ok(self
            .runtime
            .block_on(self.world.config().binding(address))
            .map_err(cannot_arrange)?
            .is_some())
    }

    fn ensure_binding(&self, address: &Address) -> R<()> {
        if self.binding(address)? {
            return Ok(());
        }
        self.runtime
            .block_on(self.world.config().insert_binding(
                address.clone(),
                secrets_core::storage::Locator::new(FIXTURE_LOCATOR),
            ))
            .map_err(cannot_arrange)
    }

    fn configure(&mut self, backend: &BackendRef) -> R<()> {
        self.world.configure(self.runtime, self.admin, backend)
    }

    fn unconfigured(&self, backend: &BackendRef) -> R<()> {
        if self.world.configured.contains(backend) {
            return Err(cannot_arrange("the named mount is already configured"));
        }
        Ok(())
    }

    fn fault(&self, namespace: &Namespace) -> R<Switch> {
        Ok(match namespace.effective_mount().kind {
            BackendKind::Keychain => World::corrupt(self.world.keychain_path()),
            BackendKind::Remote => Switch::RemoteDown,
            BackendKind::Onepassword => return Err(read_only_unsupported()),
        })
    }

    /// Arranges a secret command, as [`crate::storage`] does for the in-process stack.
    fn secret(&mut self, forced: Option<&str>, parsed: &Parsed) -> R<Vec<Switch>> {
        let key = parsed.namespace();
        match forced {
            Some("unresolved") => {
                if self.namespace(&key)?.is_some() {
                    return Err(cannot_arrange(
                        "the namespace exists and its backend needs no binding",
                    ));
                }
                return Ok(Vec::new());
            }
            Some("unsupported") => return Err(read_only_unsupported()),
            Some("unavailable") => {
                let namespace = self.ensure_namespace(&key)?;
                return Ok(vec![self.fault(&namespace)?]);
            }
            _ => {}
        }
        let namespace = self.ensure_namespace(&key)?;
        let mount = namespace.effective_mount();
        match (parsed, forced) {
            (Parsed::Write(address), Some("created")) => self.refuse_secret(&mount, address)?,
            (Parsed::Write(address) | Parsed::Delete(address), Some("not-found"))
            | (Parsed::Rename(address, _), Some("not-found")) => {
                self.refuse_secret(&mount, address)?;
            }
            (Parsed::Write(address) | Parsed::Delete(address), None) => {
                self.ensure_secret(&mount, address)?;
            }
            (Parsed::Rename(address, new_name), None | Some("taken" | "bound")) => {
                self.ensure_secret(&mount, address)?;
                let destination = Address {
                    scope: address.scope.clone(),
                    name: new_name.clone(),
                };
                match forced {
                    None => self.clear_secret(&mount, &destination)?,
                    Some("taken") => self.ensure_secret(&mount, &destination)?,
                    _ => self.ensure_binding(address)?,
                }
            }
            _ => {}
        }
        Ok(Vec::new())
    }

    /// Arranges a namespace or binding command.
    fn manage(&mut self, parsed: &Parsed, forced: Option<&str>) -> R<Vec<Switch>> {
        if forced == Some("unavailable") {
            return Ok(vec![World::corrupt(self.world.config_path())]);
        }
        match (parsed, forced) {
            (Parsed::AddNamespace(key, _), Some("exists")) => {
                self.ensure_namespace(key)?;
            }
            (Parsed::AddNamespace(_, mount), Some("no-backend")) => {
                self.unconfigured(&mount.clone().unwrap_or_else(BackendRef::default_mount))?;
            }
            (Parsed::AddNamespace(_, mount), None) => {
                self.configure(&mount.clone().unwrap_or_else(BackendRef::default_mount))?;
            }
            (Parsed::RemoveNamespace(key), None) => {
                self.ensure_namespace(key)?;
            }
            (Parsed::RemoveNamespace(key), Some("in-use")) => {
                let namespace = self.ensure_namespace(key)?;
                self.occupy(&namespace)?;
            }
            (Parsed::SetMount(key, mount), None) => {
                self.ensure_namespace(key)?;
                self.configure(mount)?;
            }
            (Parsed::SetMount(key, mount), Some("no-backend")) => {
                self.ensure_namespace(key)?;
                self.unconfigured(mount)?;
            }
            (Parsed::SetMount(key, mount), Some("in-use")) => {
                let namespace = self.ensure_namespace(key)?;
                self.configure(mount)?;
                self.occupy(&namespace)?;
            }
            (Parsed::Bind(address), None) => {
                self.ensure_namespace(&namespace_key(&address.scope))?;
            }
            (Parsed::Bind(address), Some("already-bound")) => {
                self.ensure_namespace(&namespace_key(&address.scope))?;
                self.ensure_binding(address)?;
            }
            (Parsed::Unbind(address), None) => {
                self.ensure_namespace(&namespace_key(&address.scope))?;
                self.ensure_binding(address)?;
            }
            _ => {}
        }
        Ok(Vec::new())
    }
}

// ---- the command ----------------------------------------------------------------------------

pub fn command(
    context: &mut CliContext<'_>,
    command: &str,
    input: &BTreeMap<String, Node>,
) -> Option<R<Observed>> {
    let short = command.strip_prefix("secrets.storage.")?;
    if !matches!(
        short,
        "AddNamespace"
            | "RemoveNamespace"
            | "SetMount"
            | "Bind"
            | "Unbind"
            | "Write"
            | "Read"
            | "Delete"
            | "Rename"
            | "ListMetadata"
    ) {
        return None;
    }
    Some(answer(context, short, input))
}

fn undeclared() -> Observed {
    Observed {
        outcome: None,
        error: None,
        events: Vec::new(),
    }
}

fn answer(
    context: &mut CliContext<'_>,
    command: &str,
    input: &BTreeMap<String, Node>,
) -> R<Observed> {
    if let Some(actor) = context.actor.as_deref()
        && actor != ACTOR
    {
        return Err(TargetError::unsupported(
            format!("sending a command as `{actor}`"),
            "the specification declares the local user only",
        ));
    }
    if command == "Read" {
        return Err(TargetError::unsupported(
            "reading a value",
            "secretsctl has no command that prints a secret value",
        ));
    }
    let mut input =
        serde_json::to_value(input).map_err(|error| unavailable("encoding the input", error))?;
    let (tenant, user) = scope_fields(command);
    if text(&input, tenant)? != ScopeName::DEFAULT
        || user.is_some_and(|user| text(&input, user).ok() != Some(ScopeName::DEFAULT))
    {
        return Err(local_only());
    }
    if input
        .get("mount")
        .and_then(|mount| mount.get("kind"))
        .and_then(Value::as_str)
        == Some("onepassword")
    {
        return Err(read_only_unsupported());
    }
    let forced = context.forced.clone();
    let forced = forced.as_deref();
    let refusal = forced.filter(|outcome| matches!(*outcome, "invalid-name" | "too-large"));
    if let Some(outcome) = refusal {
        let remote = command == "Write" && outcome == "too-large" && on_remote(context, &input)?;
        arrange_refusal(command, outcome, &mut input, remote)?;
    } else if forced.is_none() {
        // Unforced: the external segment rule is made false at the same length (ESS-LIMIT #1).
        for path in [&["address", "name"][..], &["new_name"][..]] {
            if let Ok(name) = text(&input, path)
                && SecretName::parse(name) == Err(NameError::SegmentTooLong)
            {
                let length = name.len();
                set(&mut input, path, Value::String(segmented(length)))?;
            }
        }
    }
    let parsed = parse(command, &input);
    if let Some(parsed) = &parsed {
        let key = parsed.namespace();
        context.world.scopes.insert(Scope {
            tenant: key.tenant,
            namespace: key.namespace,
            user: ScopeName::default_name(),
        });
    }
    let (runtime, admin) = (context.runtime, context.admin);
    let switches = match (&parsed, refusal) {
        (Some(parsed), None) => {
            let mut arranging = Arranging {
                runtime,
                admin,
                world: context.world,
            };
            match parsed {
                Parsed::Write(_)
                | Parsed::Delete(_)
                | Parsed::Rename(..)
                | Parsed::ListMetadata(_) => arranging.secret(forced, parsed)?,
                _ => arranging.manage(parsed, forced)?,
            }
        }
        _ => Vec::new(),
    };
    let world = &*context.world;
    // What the world held when the command began.
    let (existed, bound) = match &parsed {
        Some(parsed) => {
            let config = world.config();
            let existed = runtime
                .block_on(config.namespace(&parsed.namespace()))
                .map_err(|error| unavailable("reading the namespace before the command", error))?
                .is_some();
            let bound = match parsed {
                Parsed::Rename(address, new_name) => {
                    let destination = Address {
                        scope: address.scope.clone(),
                        name: new_name.clone(),
                    };
                    runtime
                        .block_on(config.binding(address))
                        .map_err(|error| unavailable("reading a binding", error))?
                        .is_some()
                        || runtime
                            .block_on(config.binding(&destination))
                            .map_err(|error| unavailable("reading a binding", error))?
                            .is_some()
                }
                _ => false,
            };
            (existed, bound)
        }
        None => (false, false),
    };
    let (args, value) = argv(command, &input)?;
    for switch in &switches {
        world.flip(runtime, admin, switch)?;
    }
    let output = world.run(&args, value.as_deref());
    for switch in &switches {
        world.unflip(runtime, admin, switch)?;
    }
    let output = output?;
    let namespace = input
        .get("namespace")
        .and_then(|key| key.get("namespace"))
        .and_then(Value::as_str);
    interpret(command, &input, &output, existed, bound, namespace)
}

/// Whether the raw input's namespace is mounted on the remote backend now.
fn on_remote(context: &CliContext<'_>, input: &Value) -> R<bool> {
    let Some(address) = address(input) else {
        return Ok(false);
    };
    Ok(context
        .runtime
        .block_on(
            context
                .world
                .config()
                .namespace(&namespace_key(&address.scope)),
        )
        .map_err(cannot_arrange)?
        .is_some_and(|namespace| namespace.effective_mount().kind == BackendKind::Remote))
}

/// The declared branch the binary's answer is.
fn interpret(
    command: &str,
    input: &Value,
    output: &Output,
    existed: bool,
    bound: bool,
    namespace: Option<&str>,
) -> R<Observed> {
    let status = output
        .status
        .code()
        .ok_or_else(|| unavailable("running secretsctl", "killed by a signal"))?;
    if status == 0 {
        return succeeded(command, input, output);
    }
    let Some(index) = status
        .checked_sub(3)
        .and_then(|index| usize::try_from(index).ok())
    else {
        // A refused command line or input names no declared branch.
        return if status == 2 {
            Ok(undeclared())
        } else {
            Err(unavailable(
                "running secretsctl",
                String::from_utf8_lossy(&output.stderr),
            ))
        };
    };
    let Some(error) = StorageError::ALL.get(index).copied() else {
        return Ok(undeclared());
    };
    let refusal: Value = serde_json::from_slice(&output.stderr)
        .map_err(|error| unavailable("reading secretsctl's refusal", error))?;
    if refusal["error"].as_str() != Some(error.code()) {
        return Ok(undeclared());
    }
    let names = matches!(command, "Bind" | "Write" | "Delete" | "Rename");
    let outcome = match (command, error) {
        (_, StorageError::InvalidName) => {
            let detail = (refusal["part"].as_str(), refusal["reason"].as_str());
            match detail {
                (Some("name"), Some("too-long")) if names => Some("name-too-long"),
                (Some("new-name"), Some("too-long")) if command == "Rename" => {
                    Some("new-name-too-long")
                }
                (Some("namespace"), Some("too-long")) if command == "AddNamespace" => {
                    Some("name-too-long")
                }
                (Some("label"), _) => None,
                (Some(_), Some(_)) if names || command == "AddNamespace" => Some("invalid-name"),
                _ => None,
            }
        }
        (_, StorageError::Unavailable) => Some("unavailable"),
        ("AddNamespace", StorageError::Conflict) => Some("exists"),
        ("AddNamespace", StorageError::NotFound) => Some("no-backend"),
        ("RemoveNamespace", StorageError::Conflict) => {
            Some(if namespace == Some(ScopeName::DEFAULT) {
                "is-default"
            } else {
                "in-use"
            })
        }
        ("RemoveNamespace" | "Unbind", StorageError::NotFound) => Some("not-found"),
        ("SetMount", StorageError::NotFound) => Some(if existed {
            "no-backend"
        } else {
            "no-namespace"
        }),
        ("SetMount", StorageError::Conflict) => Some("in-use"),
        ("Bind", StorageError::NotFound) => Some("no-namespace"),
        ("Bind", StorageError::Conflict) => Some("already-bound"),
        ("Write", StorageError::TooLarge) => Some("too-large"),
        ("Delete" | "Rename", StorageError::NotFound) => {
            Some(if existed { "not-found" } else { "unresolved" })
        }
        ("Write" | "ListMetadata", StorageError::NotFound) if !existed => Some("unresolved"),
        ("Write" | "Delete" | "Rename" | "ListMetadata", StorageError::Unsupported) => {
            Some("unsupported")
        }
        ("Rename", StorageError::Conflict) => Some(if bound { "bound" } else { "taken" }),
        _ => None,
    };
    Ok(match outcome {
        Some(outcome) => Observed {
            outcome: Some(outcome.to_owned()),
            error: declared(error),
            events: Vec::new(),
        },
        None => undeclared(),
    })
}

/// A success branch and the event the command declares for it, from the input the binary
/// accepted.
fn succeeded(command: &str, input: &Value, output: &Output) -> R<Observed> {
    let field = |name: &str| -> R<Node> {
        node(
            input
                .get(name)
                .ok_or_else(|| unavailable("reading the command input", name))?,
        )
    };
    let (outcome, event) = match command {
        "AddNamespace" => (
            "added",
            event(
                "secrets.storage.NamespaceAdded",
                vec![("namespace", field("namespace")?)],
            ),
        ),
        "RemoveNamespace" => (
            "removed",
            event(
                "secrets.storage.NamespaceRemoved",
                vec![("namespace", field("namespace")?)],
            ),
        ),
        "SetMount" => (
            "set",
            event(
                "secrets.storage.MountSet",
                vec![
                    ("namespace", field("namespace")?),
                    ("mount", field("mount")?),
                ],
            ),
        ),
        "Bind" => (
            "bound",
            event(
                "secrets.storage.NameBound",
                vec![("address", field("address")?)],
            ),
        ),
        "Unbind" => (
            "unbound",
            event(
                "secrets.storage.NameUnbound",
                vec![("address", field("address")?)],
            ),
        ),
        "Write" => {
            let printed: Value = serde_json::from_slice(&output.stdout)
                .map_err(|error| unavailable("reading secretsctl's answer", error))?;
            let outcome = match printed["outcome"].as_str() {
                Some("created") => "created",
                Some("replaced") => "replaced",
                _ => return Ok(undeclared()),
            };
            (
                outcome,
                event(
                    "secrets.storage.SecretWritten",
                    vec![("address", field("address")?)],
                ),
            )
        }
        "Delete" => (
            "deleted",
            event(
                "secrets.storage.SecretDeleted",
                vec![("address", field("address")?)],
            ),
        ),
        "Rename" => (
            "renamed",
            event(
                "secrets.storage.SecretRenamed",
                vec![
                    ("address", field("address")?),
                    ("new_name", field("new_name")?),
                ],
            ),
        ),
        "ListMetadata" => (
            "listed",
            event(
                "secrets.storage.MetadataListed",
                vec![("scope", field("scope")?)],
            ),
        ),
        _ => return Ok(undeclared()),
    };
    Ok(Observed {
        outcome: Some(outcome.to_owned()),
        error: None,
        events: vec![event],
    })
}

// ---- views ----------------------------------------------------------------------------------

pub fn view(context: &mut CliContext<'_>, view: &str) -> Option<R<Vec<ViewRow>>> {
    Some(match view {
        "secrets.storage.SecretMetadata" => secret_metadata(context.world),
        "secrets.storage.Namespaces" => namespaces(context.world),
        _ => return None,
    })
}

/// `list --json` over every scope the scenario addressed, each row checked against `describe`.
fn secret_metadata(world: &World) -> R<Vec<ViewRow>> {
    let mut rows = Vec::new();
    for scope in &world.scopes {
        let namespace = format!("--namespace={}", scope.namespace);
        let Some(listed) = world.rows(&["--json", "list", &namespace])? else {
            continue;
        };
        for row in listed {
            let name = row["name"]
                .as_str()
                .ok_or_else(|| unavailable("reading a listed row", "name"))?;
            let args: Vec<String> = ["--json", "describe", &namespace, "--", name]
                .iter()
                .map(|arg| (*arg).to_owned())
                .collect();
            let described = world.run(&args, None)?;
            let described: Value = serde_json::from_slice(&described.stdout)
                .map_err(|error| unavailable("reading secretsctl's describe", error))?;
            if described != row {
                return Err(unavailable(
                    "checking describe against list",
                    format!("describe answered {described} for listed {row}"),
                ));
            }
            let address = serde_json::json!({"scope": row["scope"], "name": row["name"]});
            rows.push(BTreeMap::from([
                ("address".to_owned(), node(&address)?),
                ("version".to_owned(), node(&row["version"])?),
                ("state".to_owned(), Node::Text("Stored".to_owned())),
            ]));
        }
    }
    Ok(rows)
}

fn namespaces(world: &World) -> R<Vec<ViewRow>> {
    world
        .rows(&["--json", "namespace", "list"])?
        .ok_or_else(|| unavailable("listing namespaces", "secretsctl refused"))?
        .iter()
        .map(|row| {
            Ok(BTreeMap::from([
                ("namespace".to_owned(), node(&row["namespace"])?),
                ("mount".to_owned(), node(&row["mount"])?),
                ("state".to_owned(), Node::Text("Present".to_owned())),
            ]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn names_go_after_a_double_dash_so_a_leading_hyphen_is_not_a_flag() {
        let input = serde_json::json!({
            "address": {"scope": {"tenant": "default", "namespace": "-ns", "user": "default"}, "name": "-x"},
        });
        let (args, _) = argv("Delete", &input).unwrap();
        assert_eq!(args, ["--json", "delete", "--namespace=-ns", "--", "-x"]);
    }
}
