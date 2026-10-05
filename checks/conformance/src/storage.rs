//! `secrets.storage` against the composed storage stack, in this process: the local authorizer
//! (`secrets_core::authorize`) in front of mount routing (`secrets_federation::FederatedStorage`)
//! over the keychain backend (`secrets_keychain`) on a mock store, the remote backend
//! (`secrets_remote`) against an in-process custody service, and recording fakes
//! (`secrets_core::storage::testing`) where the specification needs a backend the shipped ones are
//! not.
//!
//! # How an outcome is reached
//!
//! Every command's input goes through the port's own parsing — [`Address::parse`],
//! [`Address::parse_rename`], [`NamespaceKey::parse`], [`ScopeName::parse`] and
//! [`SecretValue::new`] — and an accepted input goes to the stack. The declared branch is read off
//! what the stack answered and what the world shows happened: the closed code it returned, which
//! backends the call reached, and whether the namespace configuration store was consulted. The
//! adapter never decides a branch; it arranges the world the branch is answered in.
//!
//! Several branches share a code, so the observation tells them apart:
//!
//! * a `not-found` the backend answered is `not-found`; one no backend was reached for is
//!   resolution's `unresolved`;
//! * a `conflict` from `Rename` that reached the backend is `taken`; one decided before any
//!   backend call is `bound`;
//! * a `conflict` from `RemoveNamespace` decided without consulting the configuration store is
//!   `is-default`; one decided after it is `in-use`;
//! * a `not-found` from `SetMount` on a namespace that existed when the command began is
//!   `no-backend`; otherwise `no-namespace`.
//!
//! Every backend the stack routes to is wrapped in a counter ([`Watched`]), and so is the
//! configuration store. A command that reaches more than one backend, or a backend other than the
//! one its namespace was mounted on when the command began, takes no declared branch: routing
//! promises exactly one backend and no fallback. A denial that reached a backend or the store, and
//! an `unsupported` that reached a backend, take no declared branch either: the specification
//! decides both before any backend call.
//!
//! # The authorizer comes first
//!
//! Secret commands (`Write`, `Read`, `Delete`, `Rename`, `ListMetadata`) go through
//! `Authorized<FederatedStorage>`; the authorizer it holds says which check refused a denial
//! (`Denial::outcome`). `AddNamespace`, `RemoveNamespace`, `SetMount`, `Bind` and `Unbind` are not
//! port methods, so the same authorizer decides them with action `manage-namespace` before routing
//! is called. A name the port refuses is answered by the authorizer first when it denies the scope:
//! the specification decides a denial before any name refusal.
//!
//! # Arrangement
//!
//! **Unforced**, no declared refusal's condition holds: the namespace a command addresses exists
//! (on the default keychain mount when the adapter adds it), the mount a command names is
//! configured, and a command that addresses a secret or binding finds one — the adapter stores a
//! fixture through the backend itself, or binds the address, when the world holds none. A rename's
//! destination is cleared. A name whose only fault is a segment over 64 bytes (an external
//! `invalid-name` condition, which synthesis cannot see under ESS-LIMIT #1) is rewritten to a name
//! of the same length whose segments are within the bound, so the length guard is still what is
//! probed.
//!
//! **Forced**, exactly the named condition is made true on top of that, and nothing the scenario
//! did is undone to get there:
//!
//! * `invalid-name`: a name with one 65-byte segment (a namespace starting with `-` for
//!   `AddNamespace`);
//! * `too-large`: a value one byte past 1 MiB, or, on a namespace mounted on the remote backend,
//!   exactly 1 MiB, which the port accepts and the remote refuses (the service's 1 MiB body carries
//!   the value base64-encoded);
//! * `unresolved`: the addressed namespace is left absent;
//! * `unsupported`: a new namespace is mounted on a read-only fake;
//! * `unavailable`: the configuration store's switch for a namespace command; for a secret command
//!   a new namespace on a fake switched off, or the mounted backend's own fault — a keychain entry
//!   armed to fail, or the custody service's database refusing connections;
//! * `exists`, `already-bound`, `in-use`, `taken`, `bound`: the namespace, binding, fixture secret
//!   or destination the condition names is added;
//! * `no-backend`: the named mount is left unconfigured;
//! * `not-found`, `no-namespace`, `created`: nothing is added, and a world that already holds the
//!   record cannot be arranged.
//!
//! When the port still accepts an input a forced port refusal was arranged on, the port failed to
//! refuse what the arrangement made true, and the command is reported as taking no declared
//! branch.
//!
//! # The 1Password kind
//!
//! No 1Password backend exists (story:onepassword-backend is archived). Every mount of kind
//! `onepassword` is played by the read-only, binding-required recording fake
//! (story:readonly-test-backend): a mount a scenario names, configured as an operator would, and
//! the mounts the forced `unsupported` and `unresolved` arrangements add under labels of the
//! adapter's own. The scenarios that reach it check routing's capability and binding rules, which
//! the fake declares as the kind does; they do not check 1Password itself.
//!
//! # Read's response
//!
//! `Read.read` declares `returns: true`. A read that succeeded hands ESS what the stack returned:
//! `value` as base64 text and `version` as text, or `null` when the backend returned none
//! ([`read_response`]). The scenarios under `contracts/storage/scenarios/response` assert the value
//! literally.
//!
//! # Events
//!
//! The library publishes nothing (`spec/domains/storage.yaml`, events). A success outcome's event is
//! the accepted input as the port parsed it, recorded only when the stack answered success.
//!
//! # Errors
//!
//! A refusal is reported by the text the port's error displays, looked up among the wire codes
//! the specification declares. Text that is not exactly one of those codes is no declared error.
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ess_conformance::target::{TargetError, ViewRow};
use ess_primitives::node::Node;
use keyring_core::{CredentialStore, api::CredentialStoreApi as _, mock};
use secrets_core::{
    authorize::{Authorized, Authorizer as _, Denial, LocalAuthorizer, Resource},
    storage::{
        Action, Address, AddressError, BackendKind, BackendRef, Capability, Locator, NameError,
        NamespaceKey, Part, Revealed, Scope, ScopeName, SecretMetadata, SecretName, SecretStorage,
        SecretValue, StorageError, Target, Written, testing::RecordingBackend,
    },
};
use secrets_federation::{FederatedStorage, InMemoryConfig, Namespace, NamespaceConfig};
use secrets_keychain::{DEFAULT_SERVICE, KeychainBackend, entry_user};
use secrets_remote::RemoteBackend;
use serde::Serialize;
use serde_json::Value;

use crate::fixture::{Admin, Audience, Scenario};
use crate::target::{LibraryContext, LibraryDomain, Observed, unavailable};

pub const DOMAIN: LibraryDomain = LibraryDomain { command, view };

pub(crate) const ACTOR: &str = "secrets.storage.LocalUser";
/// The value bound, restated rather than imported so a change to the port's bound is something
/// this adapter notices instead of follows.
pub(crate) const VALUE_LIMIT: usize = 1024 * 1024;
/// The specification's errors, by wire code (`naming: {wire: ...}` in `spec/domains/storage.yaml`).
const ERRORS: [(&str, &str); 7] = [
    ("not-found", "secrets.storage.NotFound"),
    ("denied", "secrets.storage.Denied"),
    ("unsupported", "secrets.storage.Unsupported"),
    ("unavailable", "secrets.storage.Unavailable"),
    ("invalid-name", "secrets.storage.InvalidName"),
    ("too-large", "secrets.storage.TooLarge"),
    ("conflict", "secrets.storage.Conflict"),
];
/// Outcomes whose condition the port itself decides, so a forced one is arranged on the input.
const PORT_REFUSALS: [&str; 2] = ["invalid-name", "too-large"];
/// The workload the remote backend's custody client authenticates as, and the one action each
/// workload route it calls authorizes (`crates/secrets-http/src/lib.rs`); nothing broader.
const REMOTE_SUBJECT: &str = "system:serviceaccount:fixture:storage-library";
const REMOTE_ACTIONS: &[&str] = &[
    "secret:write",
    "secret:read_value",
    "secret:read_metadata",
    "secret:list",
    "secret:delete",
    "secret:prepare",
    "secret:commit",
    "secret:abort",
];
/// The value a fixture secret holds, and the locator a fixture binding names.
pub(crate) const FIXTURE_VALUE: &[u8] = b"fixture";
pub(crate) const FIXTURE_LOCATOR: &str = "fixture-locator";
pub(crate) const FIXTURE_NAME: &str = "fixture";

pub(crate) type R<T> = Result<T, TargetError>;

pub(crate) fn cannot_arrange(what: impl std::fmt::Display) -> TargetError {
    unavailable("arranging the forced outcome", what)
}

// ---- the world ------------------------------------------------------------------------------

/// A backend as routing sees it: every request that reaches it is counted.
struct Watched {
    inner: Arc<dyn SecretStorage>,
    calls: AtomicU64,
}

impl Watched {
    fn hit(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl SecretStorage for Watched {
    fn capabilities(&self) -> &[Capability] {
        self.inner.capabilities()
    }
    fn requires_binding(&self) -> bool {
        self.inner.requires_binding()
    }
    async fn read(&self, target: &Target) -> Result<Revealed, StorageError> {
        self.hit();
        self.inner.read(target).await
    }
    async fn write(&self, target: &Target, value: SecretValue) -> Result<Written, StorageError> {
        self.hit();
        self.inner.write(target, value).await
    }
    async fn delete(&self, target: &Target) -> Result<(), StorageError> {
        self.hit();
        self.inner.delete(target).await
    }
    async fn rename(&self, target: &Target, new_name: &SecretName) -> Result<(), StorageError> {
        self.hit();
        self.inner.rename(target, new_name).await
    }
    async fn list(&self, scope: &Scope) -> Result<Vec<SecretMetadata>, StorageError> {
        self.hit();
        self.inner.list(scope).await
    }
}

/// The namespace configuration store as routing sees it: every call is counted.
struct WatchedConfig {
    inner: Arc<InMemoryConfig>,
    calls: AtomicU64,
}

impl WatchedConfig {
    fn hit(&self) -> &InMemoryConfig {
        self.calls.fetch_add(1, Ordering::SeqCst);
        &self.inner
    }
}

#[async_trait]
impl NamespaceConfig for WatchedConfig {
    async fn namespace(&self, key: &NamespaceKey) -> Result<Option<Namespace>, StorageError> {
        self.hit().namespace(key).await
    }
    async fn namespaces(&self) -> Result<Vec<Namespace>, StorageError> {
        self.hit().namespaces().await
    }
    async fn insert_namespace(&self, namespace: Namespace) -> Result<(), StorageError> {
        self.hit().insert_namespace(namespace).await
    }
    async fn remove_namespace(&self, key: &NamespaceKey) -> Result<(), StorageError> {
        self.hit().remove_namespace(key).await
    }
    async fn set_mount(&self, key: &NamespaceKey, mount: BackendRef) -> Result<(), StorageError> {
        self.hit().set_mount(key, mount).await
    }
    async fn binding(&self, address: &Address) -> Result<Option<Locator>, StorageError> {
        self.hit().binding(address).await
    }
    async fn has_bindings(&self, key: &NamespaceKey) -> Result<bool, StorageError> {
        self.hit().has_bindings(key).await
    }
    async fn insert_binding(&self, address: Address, locator: Locator) -> Result<(), StorageError> {
        self.hit().insert_binding(address, locator).await
    }
    async fn remove_binding(&self, address: &Address) -> Result<(), StorageError> {
        self.hit().remove_binding(address).await
    }
}

/// How a mounted backend is made to fail, as the backend itself would.
enum Fault {
    /// A recording fake: its own switch.
    Fake(Arc<RecordingBackend>),
    /// A keychain backend: the mock store's entry for an address, armed to fail its next call.
    Keychain { service: String },
    /// The remote backend: the custody service's database refusing connections.
    Remote,
}

struct Mounted {
    /// The backend itself, which the adapter arranges fixtures through without counting them.
    inner: Arc<dyn SecretStorage>,
    /// What routing is handed.
    watched: Arc<Watched>,
    fault: Fault,
}

/// The custody service a scenario mounts as the remote backend, on a loopback port.
pub(crate) struct Remote {
    pub(crate) scenario: Scenario,
    pub(crate) server: tokio::task::JoinHandle<()>,
    pub(crate) origin: String,
    pub(crate) token: String,
}

impl Remote {
    /// The shipped router and store over a scenario database, served on `127.0.0.1:0`, and a
    /// workload token of tenant `default` holding only the actions the remote backend uses.
    pub(crate) fn start(runtime: &tokio::runtime::Runtime, admin: &Admin) -> R<Self> {
        runtime
            .block_on(async {
                let mut scenario = admin.open().await?;
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let origin = format!("http://{}/", listener.local_addr()?);
                let router = scenario.router.clone();
                let server = tokio::spawn(async move {
                    let _ = axum::serve(listener, router).await;
                });
                let token = scenario.token(
                    Audience::Workload,
                    REMOTE_SUBJECT,
                    ScopeName::DEFAULT,
                    REMOTE_ACTIONS,
                )?;
                Ok::<_, Box<dyn Error>>(Self {
                    scenario,
                    server,
                    origin,
                    token,
                })
            })
            .map_err(|error| unavailable("starting the custody service", error))
    }

    /// Stops the service and drops its database.
    pub(crate) fn close(
        self,
        runtime: &tokio::runtime::Runtime,
        admin: &Admin,
    ) -> Result<(), Box<dyn Error>> {
        self.server.abort();
        runtime.block_on(admin.close(self.scenario))
    }
}

/// A condition flipped on for exactly one command and off after it.
enum Switch {
    ConfigDown,
    FakeDown(Arc<RecordingBackend>),
    KeychainEntry { service: String, address: Address },
    RemoteDown,
}

/// One scenario's storage: the configuration store, every mounted backend and what the scenario
/// addressed. Opened per scenario, so no state crosses scenarios.
pub struct World {
    config: Arc<InMemoryConfig>,
    watched_config: Arc<WatchedConfig>,
    keychain: Arc<mock::Store>,
    mounted: BTreeMap<BackendRef, Mounted>,
    remote: Option<Remote>,
    /// Every scope a command addressed, so the unparameterised SecretMetadata view is read over
    /// each of them.
    scopes: BTreeSet<Scope>,
    fakes: u64,
}

/// The call counts when a command began.
struct Mark {
    backends: BTreeMap<BackendRef, u64>,
    config: u64,
}

/// What a command reached.
struct Reached {
    backends: Vec<BackendRef>,
    config: bool,
}

impl World {
    /// Local mode's starting point: namespace `default` on the default mount, the keychain backend
    /// over a fresh mock store registered as that mount, and nothing else.
    pub fn open() -> Result<Self, Box<dyn Error>> {
        let config = Arc::new(InMemoryConfig::local());
        let mut world = Self {
            watched_config: Arc::new(WatchedConfig {
                inner: config.clone(),
                calls: AtomicU64::new(0),
            }),
            config,
            keychain: mock::Store::new()?,
            mounted: BTreeMap::new(),
            remote: None,
            scopes: BTreeSet::new(),
            fakes: 0,
        };
        world.insert_keychain(BackendRef::default_mount());
        Ok(world)
    }

    /// Stops the custody service, if one was started, and drops its database.
    pub fn close(
        self,
        runtime: &tokio::runtime::Runtime,
        admin: &Admin,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(remote) = self.remote {
            remote.close(runtime, admin)?;
        }
        Ok(())
    }

    /// The stack every command goes through, over what is mounted now.
    fn stack(&self) -> R<Authorized<FederatedStorage>> {
        let mut routing =
            FederatedStorage::new(self.watched_config.clone() as Arc<dyn NamespaceConfig>);
        for (backend, mounted) in &self.mounted {
            routing = routing
                .with_backend(
                    backend.clone(),
                    mounted.watched.clone() as Arc<dyn SecretStorage>,
                )
                .map_err(|error| unavailable("registering a backend", error))?;
        }
        Ok(Authorized::local(routing))
    }

    fn insert(&mut self, backend: BackendRef, inner: Arc<dyn SecretStorage>, fault: Fault) {
        let watched = Arc::new(Watched {
            inner: inner.clone(),
            calls: AtomicU64::new(0),
        });
        self.mounted.insert(
            backend,
            Mounted {
                inner,
                watched,
                fault,
            },
        );
    }

    /// A keychain backend over the scenario's mock store, under a service of its own label.
    fn insert_keychain(&mut self, backend: BackendRef) {
        let service = if backend.label.is_default() {
            DEFAULT_SERVICE.to_owned()
        } else {
            format!("{DEFAULT_SERVICE}.{}", backend.label)
        };
        let store = self.keychain.clone() as Arc<CredentialStore>;
        let inner = Arc::new(KeychainBackend::with_service(store, service.clone()));
        self.insert(backend, inner, Fault::Keychain { service });
    }

    /// Configures the backend a scenario names, as an operator would before mounting it.
    fn configure(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        admin: &Admin,
        backend: &BackendRef,
    ) -> R<()> {
        if self.mounted.contains_key(backend) {
            return Ok(());
        }
        match backend.kind {
            BackendKind::Keychain => self.insert_keychain(backend.clone()),
            BackendKind::Remote => {
                let (origin, token) = self.custody(runtime, admin)?;
                let http = reqwest::Client::builder()
                    .no_proxy()
                    .build()
                    .map_err(|error| unavailable("building the custody client", error))?;
                let client = secrets_client::Client::with_http(http, &origin, token)
                    .map_err(|error| unavailable("building the custody client", error))?;
                self.insert(
                    backend.clone(),
                    Arc::new(RemoteBackend::new(client)),
                    Fault::Remote,
                );
            }
            // The read-only, binding-required fake plays the kind (story:readonly-test-backend).
            BackendKind::Onepassword => {
                let fake = Arc::new(RecordingBackend::read_only_bound());
                self.insert(backend.clone(), fake.clone(), Fault::Fake(fake));
            }
        }
        Ok(())
    }

    /// The scenario's custody service, started on first use: the shipped router and store over a
    /// scenario database, served on `127.0.0.1:0`, and a workload token of tenant `default`.
    fn custody(&mut self, runtime: &tokio::runtime::Runtime, admin: &Admin) -> R<(String, String)> {
        if self.remote.is_none() {
            self.remote = Some(Remote::start(runtime, admin)?);
        }
        self.remote
            .as_ref()
            .map(|remote| (remote.origin.clone(), remote.token.clone()))
            .ok_or_else(|| unavailable("starting the custody service", "not started"))
    }

    /// A new recording fake under a label of the adapter's own: read-only and binding-required
    /// (the capability row of kind `onepassword`), or read-write (kind `keychain`'s row).
    fn insert_fake(&mut self, read_only: bool) -> R<BackendRef> {
        self.fakes += 1;
        let label = ScopeName::parse(&format!("fixture-{}", self.fakes)).map_err(cannot_arrange)?;
        let (kind, fake) = if read_only {
            (
                BackendKind::Onepassword,
                RecordingBackend::read_only_bound(),
            )
        } else {
            (BackendKind::Keychain, RecordingBackend::read_write())
        };
        let fake = Arc::new(fake);
        let backend = BackendRef { kind, label };
        self.insert(backend.clone(), fake.clone(), Fault::Fake(fake));
        Ok(backend)
    }

    fn mark(&self) -> Mark {
        Mark {
            backends: self
                .mounted
                .iter()
                .map(|(backend, mounted)| {
                    (
                        backend.clone(),
                        mounted.watched.calls.load(Ordering::SeqCst),
                    )
                })
                .collect(),
            config: self.watched_config.calls.load(Ordering::SeqCst),
        }
    }

    fn reached(&self, mark: &Mark) -> Reached {
        Reached {
            backends: self
                .mounted
                .iter()
                .filter(|(backend, mounted)| {
                    mounted.watched.calls.load(Ordering::SeqCst)
                        != mark.backends.get(*backend).copied().unwrap_or(0)
                })
                .map(|(backend, _)| backend.clone())
                .collect(),
            config: self.watched_config.calls.load(Ordering::SeqCst) != mark.config,
        }
    }

    fn flip(&self, runtime: &tokio::runtime::Runtime, admin: &Admin, switch: &Switch) -> R<()> {
        match switch {
            Switch::ConfigDown => self.config.set_unavailable(true),
            Switch::FakeDown(fake) => fake.set_unavailable(true),
            Switch::KeychainEntry { service, address } => {
                let entry = self
                    .keychain
                    .build(service, &entry_user(address), None)
                    .map_err(cannot_arrange)?;
                let credential: &mock::Cred = entry
                    .as_any()
                    .downcast_ref()
                    .ok_or_else(|| cannot_arrange("the mock store built no mock entry"))?;
                credential.set_error(keyring_core::Error::PlatformFailure(Box::new(
                    std::io::Error::other("fixture keychain fault"),
                )));
            }
            Switch::RemoteDown => {
                let remote = self
                    .remote
                    .as_ref()
                    .ok_or_else(|| cannot_arrange("no custody service is running"))?;
                runtime
                    .block_on(admin.take_down(&remote.scenario))
                    .map_err(cannot_arrange)?;
            }
        }
        Ok(())
    }

    fn unflip(&self, runtime: &tokio::runtime::Runtime, admin: &Admin, switch: &Switch) -> R<()> {
        match switch {
            Switch::ConfigDown => self.config.set_unavailable(false),
            Switch::FakeDown(fake) => fake.set_unavailable(false),
            // An armed entry fails its next call only; the command made that call.
            Switch::KeychainEntry { .. } => {}
            Switch::RemoteDown => {
                if let Some(remote) = &self.remote {
                    runtime
                        .block_on(admin.bring_up(&remote.scenario))
                        .map_err(|error| unavailable("restoring the custody database", error))?;
                }
            }
        }
        Ok(())
    }
}

// ---- arrangement ----------------------------------------------------------------------------

/// What arrangement is done with, for one command.
struct Arranging<'a> {
    runtime: &'a tokio::runtime::Runtime,
    admin: &'a Admin,
    world: &'a mut World,
}

impl Arranging<'_> {
    fn namespace(&self, key: &NamespaceKey) -> R<Option<Namespace>> {
        self.runtime
            .block_on(self.world.config.namespace(key))
            .map_err(cannot_arrange)
    }

    /// The namespace, added on `mount` (the default mount when `None`) when absent.
    fn ensure_namespace(&self, key: &NamespaceKey, mount: Option<BackendRef>) -> R<Namespace> {
        if let Some(namespace) = self.namespace(key)? {
            return Ok(namespace);
        }
        let namespace = Namespace {
            key: key.clone(),
            mount,
        };
        self.runtime
            .block_on(self.world.config.insert_namespace(namespace.clone()))
            .map_err(cannot_arrange)?;
        Ok(namespace)
    }

    fn mounted(&self, namespace: &Namespace) -> R<&Mounted> {
        self.world
            .mounted
            .get(&namespace.effective_mount())
            .ok_or_else(|| cannot_arrange("the namespace is mounted on no configured backend"))
    }

    fn backend(&self, namespace: &Namespace) -> R<Arc<dyn SecretStorage>> {
        Ok(self.mounted(namespace)?.inner.clone())
    }

    fn holds(&self, backend: &dyn SecretStorage, address: &Address) -> R<bool> {
        match self
            .runtime
            .block_on(backend.read(&Target::unbound(address.clone())))
        {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound) => Ok(false),
            Err(error) => Err(cannot_arrange(error)),
        }
    }

    /// A fixture secret at the address, stored through the backend itself, when none is there.
    fn ensure_secret(&self, backend: &dyn SecretStorage, address: &Address) -> R<()> {
        if self.holds(backend, address)? {
            return Ok(());
        }
        let value = SecretValue::new(FIXTURE_VALUE.to_vec()).map_err(cannot_arrange)?;
        self.runtime
            .block_on(backend.write(&Target::unbound(address.clone()), value))
            .map(drop)
            .map_err(cannot_arrange)
    }

    fn refuse_secret(&self, backend: &dyn SecretStorage, address: &Address) -> R<()> {
        if self.holds(backend, address)? {
            return Err(cannot_arrange("a secret is already stored at the address"));
        }
        Ok(())
    }

    /// A secret in the namespace for local mode's one user, which is what routing asks the
    /// mounted backend when it checks whether a namespace is in use.
    fn occupy(&self, namespace: &Namespace) -> R<()> {
        let scope = Scope {
            tenant: namespace.key.tenant.clone(),
            namespace: namespace.key.namespace.clone(),
            user: ScopeName::default_name(),
        };
        let backend = self.backend(namespace)?;
        let listed = self
            .runtime
            .block_on(backend.list(&scope))
            .map_err(cannot_arrange)?;
        if !listed.is_empty() {
            return Ok(());
        }
        let name = SecretName::parse(FIXTURE_NAME).map_err(cannot_arrange)?;
        self.ensure_secret(backend.as_ref(), &Address { scope, name })
    }

    fn binding(&self, address: &Address) -> R<Option<Locator>> {
        self.runtime
            .block_on(self.world.config.binding(address))
            .map_err(cannot_arrange)
    }

    fn ensure_binding(&self, address: &Address) -> R<()> {
        if self.binding(address)?.is_some() {
            return Ok(());
        }
        self.runtime
            .block_on(
                self.world
                    .config
                    .insert_binding(address.clone(), Locator::new(FIXTURE_LOCATOR)),
            )
            .map_err(cannot_arrange)
    }

    fn configure(&mut self, backend: &BackendRef) -> R<()> {
        self.world.configure(self.runtime, self.admin, backend)
    }

    fn unconfigured(&self, backend: &BackendRef) -> R<()> {
        if self.world.mounted.contains_key(backend) {
            return Err(cannot_arrange("the named mount is already configured"));
        }
        Ok(())
    }

    /// The mounted backend's own fault, for one command on `address` (a listing names none).
    fn fault(&self, namespace: &Namespace, address: Option<&Address>) -> R<Switch> {
        Ok(match &self.mounted(namespace)?.fault {
            Fault::Fake(fake) => Switch::FakeDown(fake.clone()),
            Fault::Keychain { service } => Switch::KeychainEntry {
                service: service.clone(),
                address: address
                    .ok_or_else(|| cannot_arrange("a keychain listing cannot be made to fail"))?
                    .clone(),
            },
            Fault::Remote => Switch::RemoteDown,
        })
    }

    /// Arranges a secret command (`Write`, `Read`, `Delete`, `Rename`, `ListMetadata`) on the
    /// namespace of `scope`, and on `address` when the command names one.
    fn secret(
        &mut self,
        command: &str,
        forced: Option<&str>,
        scope: &Scope,
        address: Option<&Address>,
        new_name: Option<&SecretName>,
    ) -> R<Vec<Switch>> {
        let key = namespace_key(scope);
        let needs = needs(command);
        match forced {
            Some("unresolved") => {
                if let Some(namespace) = self.namespace(&key)? {
                    let binding_missing = match address {
                        Some(address) => {
                            self.mounted(&namespace)?.inner.requires_binding()
                                && self.binding(address)?.is_none()
                        }
                        None => false,
                    };
                    if !binding_missing {
                        return Err(cannot_arrange(
                            "the namespace exists and its backend needs no binding",
                        ));
                    }
                }
                return Ok(Vec::new());
            }
            Some("unsupported") => {
                let namespace = match self.namespace(&key)? {
                    Some(namespace) => namespace,
                    None => {
                        let fake = self.world.insert_fake(true)?;
                        self.ensure_namespace(&key, Some(fake))?
                    }
                };
                let offered = self.mounted(&namespace)?.inner.capabilities();
                if needs.iter().all(|need| offered.contains(need)) {
                    return Err(cannot_arrange(
                        "the namespace is mounted on a backend with the capability",
                    ));
                }
                return Ok(Vec::new());
            }
            Some("unavailable") => {
                let namespace = match self.namespace(&key)? {
                    Some(namespace) => namespace,
                    None => {
                        let fake = self.world.insert_fake(false)?;
                        self.ensure_namespace(&key, Some(fake))?
                    }
                };
                return Ok(vec![self.fault(&namespace, address)?]);
            }
            _ => {}
        }
        let namespace = self.ensure_namespace(&key, None)?;
        let Some(address) = address else {
            return Ok(Vec::new());
        };
        let backend = self.backend(&namespace)?;
        let backend = backend.as_ref();
        match (command, forced) {
            ("Write", Some("created")) | (_, Some("not-found")) => {
                self.refuse_secret(backend, address)?;
            }
            ("Write", None) | ("Read" | "Delete", None) => self.ensure_secret(backend, address)?,
            ("Rename", None | Some("taken" | "bound")) => {
                self.ensure_secret(backend, address)?;
                let destination = Address {
                    scope: address.scope.clone(),
                    name: new_name
                        .ok_or_else(|| cannot_arrange("a rename without a new name"))?
                        .clone(),
                };
                match forced {
                    None => {
                        if self.holds(backend, &destination)? {
                            self.runtime
                                .block_on(backend.delete(&Target::unbound(destination)))
                                .map_err(cannot_arrange)?;
                        }
                    }
                    Some("taken") => self.ensure_secret(backend, &destination)?,
                    _ => self.ensure_binding(address)?,
                }
            }
            _ => {}
        }
        Ok(Vec::new())
    }

    /// Arranges a namespace or binding command.
    fn manage(&mut self, accepted: &Accepted, forced: Option<&str>) -> R<Vec<Switch>> {
        if forced == Some("unavailable") {
            return Ok(vec![Switch::ConfigDown]);
        }
        match (accepted, forced) {
            (Accepted::AddNamespace(key, _), Some("exists")) => {
                self.ensure_namespace(key, None)?;
            }
            (Accepted::AddNamespace(_, mount), Some("no-backend")) => {
                self.unconfigured(&mount.clone().unwrap_or_else(BackendRef::default_mount))?;
            }
            (Accepted::AddNamespace(_, mount), None) => {
                self.configure(&mount.clone().unwrap_or_else(BackendRef::default_mount))?;
            }
            (Accepted::RemoveNamespace(key), None) => {
                self.ensure_namespace(key, None)?;
            }
            (Accepted::RemoveNamespace(key), Some("in-use")) => {
                let namespace = self.ensure_namespace(key, None)?;
                self.occupy(&namespace)?;
            }
            (Accepted::SetMount(key, mount), None) => {
                self.ensure_namespace(key, None)?;
                self.configure(mount)?;
            }
            (Accepted::SetMount(key, mount), Some("no-backend")) => {
                self.ensure_namespace(key, None)?;
                self.unconfigured(mount)?;
            }
            (Accepted::SetMount(key, mount), Some("in-use")) => {
                let namespace = self.ensure_namespace(key, None)?;
                self.configure(mount)?;
                self.occupy(&namespace)?;
            }
            (Accepted::Bind(address, _), None) => {
                self.ensure_namespace(&namespace_key(&address.scope), None)?;
            }
            (Accepted::Bind(address, _), Some("already-bound")) => {
                self.ensure_namespace(&namespace_key(&address.scope), None)?;
                self.ensure_binding(address)?;
            }
            (Accepted::Unbind(address), None) => {
                self.ensure_namespace(&namespace_key(&address.scope), None)?;
                self.ensure_binding(address)?;
            }
            _ => {}
        }
        Ok(Vec::new())
    }
}

pub(crate) fn namespace_key(scope: &Scope) -> NamespaceKey {
    NamespaceKey {
        tenant: scope.tenant.clone(),
        namespace: scope.namespace.clone(),
    }
}

/// The capabilities a secret command needs of its backend.
pub(crate) fn needs(command: &str) -> &'static [Capability] {
    match command {
        "Write" => &[Capability::Write],
        "Read" => &[Capability::Read],
        "Delete" => &[Capability::Delete],
        "Rename" => &[Capability::Write, Capability::Delete],
        _ => &[Capability::List],
    }
}

/// The actions the authorizer decides for a command (`spec/domains/storage.yaml`, `Action`).
fn actions(command: &str) -> &'static [Action] {
    match command {
        "Write" => &[Action::Write],
        "Read" => &[Action::Read],
        "Delete" => &[Action::Delete],
        "Rename" => &[Action::Write, Action::Delete],
        "ListMetadata" => &[Action::List],
        _ => &[Action::ManageNamespace],
    }
}

fn decide(
    authorizer: &LocalAuthorizer,
    resource: Resource<'_>,
    command: &str,
) -> Result<(), Denial> {
    actions(command)
        .iter()
        .try_for_each(|action| authorizer.decide(resource, *action))
}

// ---- the port -------------------------------------------------------------------------------

/// What the port accepted, ready for the stack.
enum Accepted {
    AddNamespace(NamespaceKey, Option<BackendRef>),
    RemoveNamespace(NamespaceKey),
    SetMount(NamespaceKey, BackendRef),
    Bind(Address, Locator),
    Unbind(Address),
    Write(Address, SecretValue),
    Read(Address),
    Delete(Address),
    Rename(Address, SecretName),
    ListMetadata(Scope),
}

impl Accepted {
    /// The scope a secret command addresses; `None` for a namespace or binding command.
    fn secret_scope(&self) -> Option<&Scope> {
        match self {
            Self::Write(address, _)
            | Self::Read(address)
            | Self::Delete(address)
            | Self::Rename(address, _) => Some(&address.scope),
            Self::ListMetadata(scope) => Some(scope),
            _ => None,
        }
    }

    /// The namespace the command addresses.
    fn namespace(&self) -> NamespaceKey {
        match self {
            Self::AddNamespace(key, _) | Self::RemoveNamespace(key) | Self::SetMount(key, _) => {
                key.clone()
            }
            Self::Bind(address, _)
            | Self::Unbind(address)
            | Self::Write(address, _)
            | Self::Read(address)
            | Self::Delete(address)
            | Self::Rename(address, _) => namespace_key(&address.scope),
            Self::ListMetadata(scope) => namespace_key(scope),
        }
    }

    fn resource(&self) -> Resource<'_> {
        match self {
            Self::AddNamespace(key, _) | Self::RemoveNamespace(key) | Self::SetMount(key, _) => {
                Resource::namespace(key)
            }
            Self::Bind(address, _)
            | Self::Unbind(address)
            | Self::Write(address, _)
            | Self::Read(address)
            | Self::Delete(address)
            | Self::Rename(address, _) => Resource::address(address),
            Self::ListMetadata(scope) => Resource::scope(scope),
        }
    }
}

/// The port's refusal of an input.
enum Refusal {
    Address(AddressError),
    /// A mount label outside the ScopeName grammar.
    Label(NameError),
    Value(StorageError),
}

impl Refusal {
    fn error(&self) -> StorageError {
        match self {
            Self::Address(error) => (*error).into(),
            Self::Label(reason) => (*reason).into(),
            Self::Value(error) => *error,
        }
    }
}

fn command(
    context: &mut LibraryContext<'_>,
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
        response: None,
        outcome: None,
        error: None,
        events: Vec::new(),
    }
}

fn refused(outcome: &str, error: StorageError) -> Observed {
    Observed {
        response: None,
        outcome: Some(outcome.to_owned()),
        error: declared(error),
        events: Vec::new(),
    }
}

fn answer(
    context: &mut LibraryContext<'_>,
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
    let mut input =
        serde_json::to_value(input).map_err(|error| unavailable("encoding the input", error))?;
    let forced = context.forced.clone();
    // The authorizer the stack holds, asked on the raw scope text: the specification decides a
    // denial before any name refusal, so a refused name in a denied scope is a denial.
    let authorizer = LocalAuthorizer;
    let admitted = {
        let (tenant, user) = scope_fields(command);
        let tenant = text(&input, tenant)?;
        let resource = match user {
            None => Resource::Namespace { tenant },
            Some(user) => Resource::Scope {
                tenant,
                user: text(&input, user)?,
            },
        };
        decide(&authorizer, resource, command)
    };
    let mut parsed = parse(command, &input)?;
    if forced.is_none() && admitted.is_ok() {
        // Unforced: the external segment rule is made false at the same length (ESS-LIMIT #1).
        for _ in 0..2 {
            let Err(Refusal::Address(AddressError {
                part: part @ (Part::Name | Part::NewName),
                reason: NameError::SegmentTooLong,
            })) = &parsed
            else {
                break;
            };
            let path: &[&str] = match part {
                Part::NewName => &["new_name"],
                _ => &["address", "name"],
            };
            let length = text(&input, path)?.len();
            set(&mut input, path, Value::String(segmented(length)))?;
            parsed = parse(command, &input)?;
        }
    }
    if let (Ok(_), Some(outcome), Ok(())) = (&parsed, forced.as_deref(), admitted)
        && PORT_REFUSALS.contains(&outcome)
    {
        // A value the port accepts and the remote backend must refuse on its own.
        let remote = command == "Write" && outcome == "too-large" && on_remote(context, &input)?;
        arrange(command, outcome, &mut input, remote)?;
        parsed = parse(command, &input)?;
        if parsed.is_ok() && !remote {
            return Ok(undeclared());
        }
    }
    match parsed {
        Err(refusal) => Ok(match admitted {
            Err(denial) => refused(denial.outcome(), StorageError::Denied),
            Ok(()) => Observed {
                response: None,
                outcome: branch(command, &refusal).map(ToOwned::to_owned),
                error: declared(refusal.error()),
                events: Vec::new(),
            },
        }),
        Ok(accepted) => mounted(context, command, accepted),
    }
}

/// Whether the raw input's namespace is mounted on the remote backend now.
fn on_remote(context: &LibraryContext<'_>, input: &Value) -> R<bool> {
    let Ok(key) = NamespaceKey::parse(
        text(input, &["address", "scope", "tenant"])?,
        text(input, &["address", "scope", "namespace"])?,
    ) else {
        return Ok(false);
    };
    Ok(context
        .runtime
        .block_on(context.world.config.namespace(&key))
        .map_err(cannot_arrange)?
        .is_some_and(|namespace| namespace.effective_mount().kind == BackendKind::Remote))
}

/// A name of `length` bytes whose segments are each within 64 bytes.
pub(crate) fn segmented(length: usize) -> String {
    let first = length.saturating_sub(2).min(64);
    let second = length.saturating_sub(first + 1);
    format!("{}/{}", "a".repeat(first), "a".repeat(second))
}

/// The declared error whose wire code is exactly the text the port's error displays.
pub(crate) fn declared(error: StorageError) -> Option<&'static str> {
    let text = error.to_string();
    ERRORS
        .iter()
        .find(|(code, _)| *code == text)
        .map(|(_, name)| *name)
}

/// The declared branch a refusal is, for the command that got it; `None` for a refusal the
/// command declares no branch for.
fn branch(command: &str, refusal: &Refusal) -> Option<&'static str> {
    let names = matches!(command, "Bind" | "Write" | "Read" | "Delete" | "Rename");
    match refusal {
        Refusal::Value(StorageError::TooLarge) if command == "Write" => Some("too-large"),
        Refusal::Value(_) | Refusal::Label(_) => None,
        Refusal::Address(AddressError {
            part: Part::Name,
            reason: NameError::TooLong,
        }) if names => Some("name-too-long"),
        Refusal::Address(AddressError {
            part: Part::NewName,
            reason: NameError::TooLong,
        }) if command == "Rename" => Some("new-name-too-long"),
        Refusal::Address(AddressError {
            part: Part::Namespace,
            reason: NameError::TooLong,
        }) if command == "AddNamespace" => Some("name-too-long"),
        Refusal::Address(_) if names || command == "AddNamespace" => Some("invalid-name"),
        Refusal::Address(_) => None,
    }
}

pub(crate) fn text<'a>(input: &'a Value, path: &[&str]) -> R<&'a str> {
    path.iter()
        .try_fold(input, |value, key| value.get(key))
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable("reading the command input", path.join(".")))
}

pub(crate) fn set(input: &mut Value, path: &[&str], value: Value) -> R<()> {
    let (last, parents) = path
        .split_last()
        .ok_or_else(|| cannot_arrange("an empty input path"))?;
    let slot = parents
        .iter()
        .try_fold(&mut *input, |value, key| value.get_mut(key))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| cannot_arrange(path.join(".")))?;
    slot.insert((*last).to_owned(), value);
    Ok(())
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

fn address(input: &Value) -> R<Result<Address, AddressError>> {
    Ok(Address::parse(
        text(input, &["address", "scope", "tenant"])?,
        text(input, &["address", "scope", "namespace"])?,
        text(input, &["address", "scope", "user"])?,
        text(input, &["address", "name"])?,
    ))
}

fn namespace(input: &Value) -> R<Result<NamespaceKey, AddressError>> {
    Ok(NamespaceKey::parse(
        text(input, &["namespace", "tenant"])?,
        text(input, &["namespace", "namespace"])?,
    ))
}

/// A mount through the port. An absent optional mount is the default mount; a kind the
/// specification does not declare is not an input this adapter can send.
fn mount(input: &Value, required: bool) -> R<Result<Option<BackendRef>, Refusal>> {
    let mount = match input.get("mount") {
        None | Some(Value::Null) if !required => return Ok(Ok(None)),
        None | Some(Value::Null) => {
            return Err(unavailable("reading the command input", "mount"));
        }
        Some(mount) => mount,
    };
    let kind =
        serde_json::from_value::<BackendKind>(Value::String(text(mount, &["kind"])?.to_owned()))
            .map_err(|error| unavailable("reading the mount kind", error))?;
    Ok(ScopeName::parse(text(mount, &["label"])?)
        .map(|label| Some(BackendRef { kind, label }))
        .map_err(Refusal::Label))
}

fn scope(input: &Value) -> R<Result<Scope, Refusal>> {
    let part = |part: Part, field: &str| -> R<Result<ScopeName, Refusal>> {
        Ok(ScopeName::parse(text(input, &["scope", field])?)
            .map_err(|reason| Refusal::Address(AddressError::new(part, reason))))
    };
    let tenant = part(Part::Tenant, "tenant")?;
    let namespace = part(Part::Namespace, "namespace")?;
    let user = part(Part::User, "user")?;
    Ok((|| {
        Ok(Scope {
            tenant: tenant?,
            namespace: namespace?,
            user: user?,
        })
    })())
}

/// The input through the port, in the order the port decides it.
fn parse(command: &str, input: &Value) -> R<Result<Accepted, Refusal>> {
    let refused = Refusal::Address;
    Ok(match command {
        "AddNamespace" | "SetMount" => match namespace(input)? {
            Err(error) => Err(refused(error)),
            Ok(key) => match mount(input, command == "SetMount")? {
                Err(refusal) => Err(refusal),
                Ok(mount) => match (command, mount) {
                    ("SetMount", Some(mount)) => Ok(Accepted::SetMount(key, mount)),
                    ("SetMount", None) => {
                        return Err(unavailable("reading the command input", "mount"));
                    }
                    (_, mount) => Ok(Accepted::AddNamespace(key, mount)),
                },
            },
        },
        "RemoveNamespace" => namespace(input)?
            .map(Accepted::RemoveNamespace)
            .map_err(refused),
        "Bind" => {
            let locator = Locator::new(text(input, &["locator"])?);
            address(input)?
                .map(|address| Accepted::Bind(address, locator))
                .map_err(refused)
        }
        "Unbind" => address(input)?.map(Accepted::Unbind).map_err(refused),
        "Read" => address(input)?.map(Accepted::Read).map_err(refused),
        "Delete" => address(input)?.map(Accepted::Delete).map_err(refused),
        "Write" => match address(input)? {
            Err(error) => Err(refused(error)),
            Ok(address) => {
                let bytes = STANDARD
                    .decode(text(input, &["value"])?)
                    .map_err(|error| unavailable("decoding the value", error))?;
                SecretValue::new(bytes)
                    .map(|value| Accepted::Write(address, value))
                    .map_err(Refusal::Value)
            }
        },
        "Rename" => Address::parse_rename(
            text(input, &["address", "scope", "tenant"])?,
            text(input, &["address", "scope", "namespace"])?,
            text(input, &["address", "scope", "user"])?,
            text(input, &["address", "name"])?,
            text(input, &["new_name"])?,
        )
        .map(|(address, new_name)| Accepted::Rename(address, new_name))
        .map_err(refused),
        "ListMetadata" => scope(input)?.map(Accepted::ListMetadata),
        _ => return Err(unavailable("parsing the command input", command)),
    })
}

/// Makes the forced port refusal's condition true on the input. On a remote mount a `too-large`
/// value is exactly the port's bound, which the remote backend must refuse on its own.
fn arrange(command: &str, outcome: &str, input: &mut Value, remote: bool) -> R<()> {
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

// ---- the stack ------------------------------------------------------------------------------

/// What the stack answered on success.
enum Done {
    Unit,
    Written(Written),
    Revealed(Revealed),
}

/// `Read`'s response as the specification declares it: `value` (Bytes, as base64 text) and
/// `version` (`null` when the backend keeps none).
pub(crate) fn read_response(value: &[u8], version: Option<&str>) -> BTreeMap<String, Node> {
    BTreeMap::from([
        ("value".to_owned(), Node::Text(STANDARD.encode(value))),
        (
            "version".to_owned(),
            version.map_or(Node::Null, |version| Node::Text(version.to_owned())),
        ),
    ])
}

pub(crate) fn node(value: &impl Serialize) -> R<Node> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(|error| unavailable("encoding a node", error))
}

pub(crate) fn event(
    name: &'static str,
    fields: Vec<(&str, Node)>,
) -> (&'static str, BTreeMap<String, Node>) {
    (
        name,
        fields
            .into_iter()
            .map(|(field, value)| (field.to_owned(), value))
            .collect(),
    )
}

/// Hands an accepted command to the stack, in the world arranged for it, and reads the branch off
/// what it answered and what it reached.
fn mounted(context: &mut LibraryContext<'_>, command: &str, accepted: Accepted) -> R<Observed> {
    let forced = context.forced.clone();
    let forced = forced.as_deref();
    let stack = context.world.stack()?;
    let resource = accepted.resource();
    let admitted = decide(stack.authorizer(), resource, command);
    let key = accepted.namespace();
    if admitted.is_ok() {
        context.world.scopes.insert(match accepted.secret_scope() {
            Some(scope) => scope.clone(),
            None => Scope {
                tenant: key.tenant.clone(),
                namespace: key.namespace.clone(),
                user: match &accepted {
                    Accepted::Bind(address, _) | Accepted::Unbind(address) => {
                        address.scope.user.clone()
                    }
                    _ => ScopeName::default_name(),
                },
            },
        });
    }
    let (runtime, admin) = (context.runtime, context.admin);
    let switches = if admitted.is_err() {
        Vec::new()
    } else {
        let mut arranging = Arranging {
            runtime,
            admin,
            world: context.world,
        };
        match &accepted {
            Accepted::Write(address, _) | Accepted::Read(address) | Accepted::Delete(address) => {
                arranging.secret(command, forced, &address.scope, Some(address), None)?
            }
            Accepted::Rename(address, new_name) => arranging.secret(
                command,
                forced,
                &address.scope,
                Some(address),
                Some(new_name),
            )?,
            Accepted::ListMetadata(scope) => {
                arranging.secret(command, forced, scope, None, None)?
            }
            _ => arranging.manage(&accepted, forced)?,
        }
    };
    // The stack is rebuilt over what arrangement configured.
    let stack = context.world.stack()?;
    let world = &*context.world;
    let before = runtime
        .block_on(world.config.namespace(&key))
        .map_err(|error| unavailable("reading the namespace before the command", error))?;
    let expected = before.as_ref().map(Namespace::effective_mount);
    for switch in &switches {
        world.flip(runtime, admin, switch)?;
    }
    let mark = world.mark();
    let result = runtime.block_on(execute(&stack, &accepted));
    let reached = world.reached(&mark);
    for switch in &switches {
        world.unflip(runtime, admin, switch)?;
    }
    // Exactly one backend, the one the namespace was mounted on, and no fallback.
    if reached.backends.len() > 1
        || reached
            .backends
            .first()
            .is_some_and(|backend| Some(backend) != expected.as_ref())
    {
        return Ok(undeclared());
    }
    let backend = !reached.backends.is_empty();
    let error = match result {
        Ok(done) => return succeeded(command, &accepted, &done),
        Err(error) => error,
    };
    if error == StorageError::Denied {
        // The authorizer's denial: decided before any backend or the configuration store.
        let denial = decide(stack.authorizer(), resource, command);
        return Ok(match denial {
            Err(denial) if !backend && !reached.config => {
                refused(denial.outcome(), StorageError::Denied)
            }
            _ => undeclared(),
        });
    }
    let outcome = match (command, error) {
        (_, StorageError::Unavailable) => Some("unavailable"),
        ("AddNamespace", StorageError::Conflict) => Some("exists"),
        ("AddNamespace", StorageError::NotFound) => Some("no-backend"),
        ("RemoveNamespace", StorageError::Conflict) => Some(if reached.config {
            "in-use"
        } else {
            "is-default"
        }),
        ("RemoveNamespace" | "Unbind", StorageError::NotFound) => Some("not-found"),
        ("SetMount", StorageError::NotFound) => Some(if before.is_some() {
            "no-backend"
        } else {
            "no-namespace"
        }),
        ("SetMount", StorageError::Conflict) => Some("in-use"),
        ("Bind", StorageError::NotFound) => Some("no-namespace"),
        ("Bind", StorageError::Conflict) => Some("already-bound"),
        ("Write", StorageError::TooLarge) => Some("too-large"),
        ("Read" | "Delete" | "Rename", StorageError::NotFound) => {
            Some(if backend { "not-found" } else { "unresolved" })
        }
        ("Write" | "ListMetadata", StorageError::NotFound) if !backend => Some("unresolved"),
        ("Write" | "Delete" | "Rename" | "ListMetadata", StorageError::Unsupported) if !backend => {
            Some("unsupported")
        }
        ("Rename", StorageError::Conflict) => Some(if backend { "taken" } else { "bound" }),
        _ => None,
    };
    Ok(match outcome {
        Some(outcome) => refused(outcome, error),
        None => undeclared(),
    })
}

async fn execute(
    stack: &Authorized<FederatedStorage>,
    accepted: &Accepted,
) -> Result<Done, StorageError> {
    let routing = stack.inner();
    let authorizer = stack.authorizer();
    // Namespace and binding commands are not port methods: the same authorizer decides them
    // with `manage-namespace` before routing is called.
    let manage = |resource: Resource<'_>| authorizer.authorize(resource, Action::ManageNamespace);
    let unit = |result: Result<(), StorageError>| result.map(|()| Done::Unit);
    match accepted {
        Accepted::AddNamespace(key, mount) => {
            manage(Resource::namespace(key))?;
            unit(routing.add_namespace(key.clone(), mount.clone()).await)
        }
        Accepted::RemoveNamespace(key) => {
            manage(Resource::namespace(key))?;
            unit(routing.remove_namespace(key).await)
        }
        Accepted::SetMount(key, mount) => {
            manage(Resource::namespace(key))?;
            unit(routing.set_mount(key, mount.clone()).await)
        }
        Accepted::Bind(address, locator) => {
            manage(Resource::address(address))?;
            unit(routing.bind(address, locator.clone()).await)
        }
        Accepted::Unbind(address) => {
            manage(Resource::address(address))?;
            unit(routing.unbind(address).await)
        }
        Accepted::Write(address, value) => {
            let value = SecretValue::new(value.expose().to_vec())?;
            stack
                .write(&Target::unbound(address.clone()), value)
                .await
                .map(Done::Written)
        }
        Accepted::Read(address) => stack
            .read(&Target::unbound(address.clone()))
            .await
            .map(Done::Revealed),
        Accepted::Delete(address) => unit(stack.delete(&Target::unbound(address.clone())).await),
        Accepted::Rename(address, new_name) => unit(
            stack
                .rename(&Target::unbound(address.clone()), new_name)
                .await,
        ),
        Accepted::ListMetadata(scope) => stack.list(scope).await.map(|_| Done::Unit),
    }
}

/// A success branch and the event the command declares for it.
fn succeeded(command: &str, accepted: &Accepted, done: &Done) -> R<Observed> {
    let (outcome, event) = match (accepted, done) {
        (Accepted::AddNamespace(key, _), _) => (
            "added",
            event(
                "secrets.storage.NamespaceAdded",
                vec![("namespace", node(key)?)],
            ),
        ),
        (Accepted::RemoveNamespace(key), _) => (
            "removed",
            event(
                "secrets.storage.NamespaceRemoved",
                vec![("namespace", node(key)?)],
            ),
        ),
        (Accepted::SetMount(key, mount), _) => (
            "set",
            event(
                "secrets.storage.MountSet",
                vec![("namespace", node(key)?), ("mount", node(mount)?)],
            ),
        ),
        (Accepted::Bind(address, _), _) => (
            "bound",
            event(
                "secrets.storage.NameBound",
                vec![("address", node(address)?)],
            ),
        ),
        (Accepted::Unbind(address), _) => (
            "unbound",
            event(
                "secrets.storage.NameUnbound",
                vec![("address", node(address)?)],
            ),
        ),
        (Accepted::Write(address, _), Done::Written(written)) => (
            match written {
                Written::Created(_) => "created",
                Written::Replaced(_) => "replaced",
            },
            event(
                "secrets.storage.SecretWritten",
                vec![("address", node(address)?)],
            ),
        ),
        (Accepted::Read(_), Done::Revealed(revealed)) => {
            return Ok(Observed {
                response: Some(read_response(
                    revealed.value.expose(),
                    revealed.version.as_ref().map(|version| version.as_str()),
                )),
                outcome: Some("read".to_owned()),
                error: None,
                events: Vec::new(),
            });
        }
        (Accepted::Delete(address), _) => (
            "deleted",
            event(
                "secrets.storage.SecretDeleted",
                vec![("address", node(address)?)],
            ),
        ),
        (Accepted::Rename(address, new_name), _) => (
            "renamed",
            event(
                "secrets.storage.SecretRenamed",
                vec![("address", node(address)?), ("new_name", node(new_name)?)],
            ),
        ),
        (Accepted::ListMetadata(scope), _) => (
            "listed",
            event(
                "secrets.storage.MetadataListed",
                vec![("scope", node(scope)?)],
            ),
        ),
        (Accepted::Write(..), Done::Unit | Done::Revealed(_))
        | (Accepted::Read(_), Done::Unit | Done::Written(_)) => {
            return Err(unavailable("reading the stack's answer", command));
        }
    };
    Ok(Observed {
        response: None,
        outcome: Some(outcome.to_owned()),
        error: None,
        events: vec![event],
    })
}

// ---- views ----------------------------------------------------------------------------------

fn view(context: &mut LibraryContext<'_>, view: &str) -> Option<R<Vec<ViewRow>>> {
    Some(match view {
        "secrets.storage.SecretMetadata" => secret_metadata(context),
        "secrets.storage.Namespaces" => namespaces(context),
        _ => return None,
    })
}

/// Every secret in every scope the scenario addressed, listed through the stack. A scope whose
/// namespace is gone, whose backend cannot list or that the authorizer denies holds no row.
fn secret_metadata(context: &mut LibraryContext<'_>) -> R<Vec<ViewRow>> {
    let stack = context.world.stack()?;
    let mut rows = BTreeSet::new();
    for scope in &context.world.scopes {
        match context.runtime.block_on(stack.list(scope)) {
            Ok(listed) => rows.extend(listed),
            Err(StorageError::NotFound | StorageError::Unsupported | StorageError::Denied) => {}
            Err(error) => return Err(unavailable("listing secret metadata", error)),
        }
    }
    rows.iter()
        .map(|row| {
            Ok(BTreeMap::from([
                ("address".to_owned(), node(&row.address)?),
                ("version".to_owned(), node(&row.version)?),
                ("state".to_owned(), Node::Text("Stored".to_owned())),
            ]))
        })
        .collect()
}

fn namespaces(context: &mut LibraryContext<'_>) -> R<Vec<ViewRow>> {
    let stack = context.world.stack()?;
    context
        .runtime
        .block_on(stack.inner().namespaces())
        .map_err(|error| unavailable("listing namespaces", error))?
        .iter()
        .map(|namespace| {
            Ok(BTreeMap::from([
                ("namespace".to_owned(), node(&namespace.key)?),
                ("mount".to_owned(), node(&namespace.mount)?),
                ("state".to_owned(), Node::Text("Present".to_owned())),
            ]))
        })
        .collect()
}
