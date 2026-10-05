//! story:mount-federation, over the recording fake backends of `secrets-core`'s `testing`
//! feature. Each test names the story scenario it guards; "no backend is called" is asserted
//! here because a conformance scenario cannot assert it (ESS-LIMIT #27).
use std::sync::Arc;

use async_trait::async_trait;
use secrets_core::storage::{
    Address, BackendKind, BackendRef, Capability, Locator, NamespaceKey, Revealed, Scope,
    ScopeName, SecretMetadata, SecretName, SecretStorage, SecretValue, StorageError, Target,
    Written,
    testing::{Call, RecordingBackend},
};

use crate::{FederatedStorage, InMemoryConfig, Namespace, NamespaceConfig};

type R = Result<(), StorageError>;

const LOCATOR: &str = "op://vault/item/field";

struct Fixture {
    config: Arc<InMemoryConfig>,
    /// The default mount: keychain `default`.
    keychain: Arc<RecordingBackend>,
    /// Remote `work`, mounted to namespace `work`.
    remote: Arc<RecordingBackend>,
    /// Read-only and binding-required, as onepassword `personal`, mounted to namespace `vault`.
    vault: Arc<RecordingBackend>,
    storage: FederatedStorage,
}

fn label(label: &str) -> Result<ScopeName, StorageError> {
    Ok(ScopeName::parse(label)?)
}

fn remote_work() -> Result<BackendRef, StorageError> {
    Ok(BackendRef {
        kind: BackendKind::Remote,
        label: label("work")?,
    })
}

fn onepassword_personal() -> Result<BackendRef, StorageError> {
    Ok(BackendRef {
        kind: BackendKind::Onepassword,
        label: label("personal")?,
    })
}

fn key(namespace: &str) -> Result<NamespaceKey, StorageError> {
    Ok(NamespaceKey::parse("default", namespace)?)
}

fn address(namespace: &str, name: &str) -> Result<Address, StorageError> {
    Ok(Address::parse("default", namespace, "default", name)?)
}

fn scope(namespace: &str) -> Result<Scope, StorageError> {
    Ok(address(namespace, "x")?.scope)
}

fn target(namespace: &str, name: &str) -> Result<Target, StorageError> {
    Ok(Target::unbound(address(namespace, name)?))
}

fn value(bytes: &[u8]) -> Result<SecretValue, StorageError> {
    SecretValue::new(bytes.to_vec())
}

fn name(name: &str) -> Result<SecretName, StorageError> {
    Ok(SecretName::parse(name)?)
}

/// The refusal, if the result is one. `Revealed` has no `Debug`, so results are compared this way.
fn refusal<T>(result: Result<T, StorageError>) -> Option<StorageError> {
    result.err()
}

async fn fixture() -> Result<Fixture, StorageError> {
    let config = Arc::new(InMemoryConfig::local());
    let keychain = Arc::new(RecordingBackend::read_write());
    let remote = Arc::new(RecordingBackend::read_write());
    let vault = Arc::new(RecordingBackend::read_only_bound());
    let storage = FederatedStorage::new(config.clone())
        .with_backend(BackendRef::default_mount(), keychain.clone())?
        .with_backend(remote_work()?, remote.clone())?
        .with_backend(onepassword_personal()?, vault.clone())?;
    storage
        .add_namespace(key("work")?, Some(remote_work()?))
        .await?;
    storage
        .add_namespace(key("vault")?, Some(onepassword_personal()?))
        .await?;
    Ok(Fixture {
        config,
        keychain,
        remote,
        vault,
        storage,
    })
}

impl Fixture {
    fn calls(&self) -> [usize; 3] {
        [
            self.keychain.calls().len(),
            self.remote.calls().len(),
            self.vault.calls().len(),
        ]
    }
}

/// Every secret command on `namespace`/`name`, each answered `expected`.
async fn every_secret_command(
    storage: &FederatedStorage,
    namespace: &str,
    expected: StorageError,
) -> R {
    let at = target(namespace, "openai")?;
    assert_eq!(refusal(storage.read(&at).await), Some(expected), "read");
    assert_eq!(
        refusal(storage.write(&at, value(b"v")?).await),
        Some(expected),
        "write"
    );
    assert_eq!(refusal(storage.delete(&at).await), Some(expected), "delete");
    assert_eq!(
        refusal(storage.rename(&at, &name("openai-work")?).await),
        Some(expected),
        "rename"
    );
    assert_eq!(
        refusal(storage.list(&scope(namespace)?).await),
        Some(expected),
        "list"
    );
    Ok(())
}

// Scenario: "a name with no mount or binding is `not-found` and the fakes record no call".

#[tokio::test]
async fn a_name_in_a_namespace_that_does_not_exist_is_not_found_and_no_backend_is_called() -> R {
    let f = fixture().await?;
    every_secret_command(&f.storage, "missing", StorageError::NotFound).await?;
    assert_eq!(f.calls(), [0, 0, 0]);
    Ok(())
}

#[tokio::test]
async fn a_mount_naming_an_unregistered_backend_is_not_found_and_no_backend_is_called() -> R {
    let f = fixture().await?;
    // Written straight into the store, as a stale configuration file would hold it.
    f.config
        .insert_namespace(Namespace {
            key: key("stale")?,
            mount: Some(BackendRef {
                kind: BackendKind::Remote,
                label: label("gone")?,
            }),
        })
        .await?;
    every_secret_command(&f.storage, "stale", StorageError::NotFound).await?;
    assert_eq!(f.calls(), [0, 0, 0]);
    Ok(())
}

#[tokio::test]
async fn an_unbound_name_on_a_binding_backend_is_not_found_and_no_backend_is_called() -> R {
    let f = fixture().await?;
    f.vault.preload(Locator::new(LOCATOR), value(b"held")?)?;
    let unbound = target("vault", "openai")?;
    assert_eq!(
        refusal(f.storage.read(&unbound).await),
        Some(StorageError::NotFound)
    );
    // A locator the caller supplies is not a binding.
    let forged = Target {
        address: unbound.address.clone(),
        locator: Some(Locator::new(LOCATOR)),
    };
    assert_eq!(
        refusal(f.storage.read(&forged).await),
        Some(StorageError::NotFound)
    );
    assert_eq!(f.calls(), [0, 0, 0]);
    Ok(())
}

#[tokio::test]
async fn a_bound_name_reads_through_its_locator_and_after_unbind_is_not_found_again() -> R {
    let f = fixture().await?;
    f.vault.preload(Locator::new(LOCATOR), value(b"held")?)?;
    let at = address("vault", "openai")?;
    f.storage.bind(&at, Locator::new(LOCATOR)).await?;
    let Revealed { value, version } = f.storage.read(&Target::unbound(at.clone())).await?;
    assert_eq!(value.expose(), b"held");
    assert!(version.is_some());
    assert_eq!(f.vault.calls(), vec![Call::Read(at.clone())]);
    f.storage.unbind(&at).await?;
    assert_eq!(
        refusal(f.storage.read(&Target::unbound(at)).await),
        Some(StorageError::NotFound)
    );
    assert_eq!(f.vault.calls().len(), 1, "no call after unbind");
    assert_eq!(f.calls(), [0, 0, 1]);
    Ok(())
}

// Scenario: "write, delete and rename on a read-only mount are `unsupported`".

#[tokio::test]
async fn write_delete_rename_and_list_on_a_read_only_mount_are_unsupported_before_any_call() -> R {
    let f = fixture().await?;
    for bound in [false, true] {
        if bound {
            f.storage
                .bind(&address("vault", "openai")?, Locator::new(LOCATOR))
                .await?;
        }
        let at = target("vault", "openai")?;
        assert_eq!(
            refusal(f.storage.write(&at, value(b"v")?).await),
            Some(StorageError::Unsupported)
        );
        assert_eq!(
            refusal(f.storage.delete(&at).await),
            Some(StorageError::Unsupported)
        );
        assert_eq!(
            refusal(f.storage.rename(&at, &name("openai-work")?).await),
            Some(StorageError::Unsupported)
        );
        assert_eq!(
            refusal(f.storage.list(&scope("vault")?).await),
            Some(StorageError::Unsupported)
        );
    }
    assert_eq!(f.calls(), [0, 0, 0]);
    Ok(())
}

// Scenario: "SetMount, RemoveNamespace, Bind and Rename give `conflict` in the cases the spec
// names".

#[tokio::test]
async fn set_mount_is_conflict_while_secrets_exist_under_the_current_mount() -> R {
    let f = fixture().await?;
    f.storage
        .write(&target("work", "openai")?, value(b"v")?)
        .await?;
    assert_eq!(
        f.storage
            .set_mount(&key("work")?, BackendRef::default_mount())
            .await,
        Err(StorageError::Conflict)
    );
    f.storage.delete(&target("work", "openai")?).await?;
    f.storage
        .set_mount(&key("work")?, BackendRef::default_mount())
        .await?;
    Ok(())
}

#[tokio::test]
async fn remove_namespace_is_conflict_for_default_and_while_bindings_or_secrets_remain() -> R {
    let f = fixture().await?;
    assert_eq!(
        f.storage.remove_namespace(&key("default")?).await,
        Err(StorageError::Conflict)
    );
    let bound = address("vault", "openai")?;
    f.storage.bind(&bound, Locator::new(LOCATOR)).await?;
    assert_eq!(
        f.storage.remove_namespace(&key("vault")?).await,
        Err(StorageError::Conflict)
    );
    f.storage.unbind(&bound).await?;
    f.storage.remove_namespace(&key("vault")?).await?;

    f.storage
        .write(&target("work", "openai")?, value(b"v")?)
        .await?;
    assert_eq!(
        f.storage.remove_namespace(&key("work")?).await,
        Err(StorageError::Conflict)
    );
    f.storage.delete(&target("work", "openai")?).await?;
    f.storage.remove_namespace(&key("work")?).await?;
    assert_eq!(
        f.storage.remove_namespace(&key("work")?).await,
        Err(StorageError::NotFound)
    );
    Ok(())
}

#[tokio::test]
async fn bind_is_conflict_on_a_bound_address_and_keeps_the_first_locator() -> R {
    let f = fixture().await?;
    f.vault.preload(Locator::new(LOCATOR), value(b"first")?)?;
    let at = address("vault", "openai")?;
    f.storage.bind(&at, Locator::new(LOCATOR)).await?;
    assert_eq!(
        f.storage
            .bind(&at, Locator::new("op://vault/other/field"))
            .await,
        Err(StorageError::Conflict)
    );
    assert_eq!(f.config.binding(&at).await?, Some(Locator::new(LOCATOR)));
    let read = f.storage.read(&Target::unbound(at)).await?;
    assert_eq!(read.value.expose(), b"first");
    Ok(())
}

#[tokio::test]
async fn renaming_a_bound_name_or_onto_a_bound_name_is_conflict_and_no_backend_renames() -> R {
    let f = fixture().await?;
    let from = target("work", "openai")?;
    f.storage.write(&from, value(b"v")?).await?;
    f.storage
        .bind(&from.address, Locator::new("locator-a"))
        .await?;
    assert_eq!(
        f.storage.rename(&from, &name("openai-work")?).await,
        Err(StorageError::Conflict)
    );
    f.storage.unbind(&from.address).await?;
    f.storage
        .bind(&address("work", "openai-work")?, Locator::new("locator-b"))
        .await?;
    assert_eq!(
        f.storage.rename(&from, &name("openai-work")?).await,
        Err(StorageError::Conflict)
    );
    assert!(
        !f.remote
            .calls()
            .iter()
            .any(|call| matches!(call, Call::Rename(..)))
    );
    // The bindings stayed where they were.
    assert_eq!(f.config.binding(&from.address).await?, None);
    assert_eq!(
        f.config.binding(&address("work", "openai-work")?).await?,
        Some(Locator::new("locator-b"))
    );
    Ok(())
}

#[tokio::test]
async fn renaming_onto_a_stored_name_is_the_backend_s_conflict() -> R {
    let f = fixture().await?;
    f.storage
        .write(&target("work", "openai")?, value(b"a")?)
        .await?;
    f.storage
        .write(&target("work", "openai-work")?, value(b"b")?)
        .await?;
    assert_eq!(
        f.storage
            .rename(&target("work", "openai")?, &name("openai-work")?)
            .await,
        Err(StorageError::Conflict)
    );
    Ok(())
}

#[tokio::test]
async fn adding_a_namespace_that_exists_is_conflict() -> R {
    let f = fixture().await?;
    assert_eq!(
        f.storage.add_namespace(key("work")?, None).await,
        Err(StorageError::Conflict)
    );
    assert_eq!(
        f.storage.add_namespace(key("default")?, None).await,
        Err(StorageError::Conflict)
    );
    Ok(())
}

#[tokio::test]
async fn delete_never_removes_a_binding() -> R {
    let f = fixture().await?;
    let at = target("work", "openai")?;
    f.storage.write(&at, value(b"v")?).await?;
    f.storage
        .bind(&at.address, Locator::new("locator-a"))
        .await?;
    f.storage.delete(&at).await?;
    assert_eq!(
        f.config.binding(&at.address).await?,
        Some(Locator::new("locator-a"))
    );
    assert_eq!(
        f.storage.bind(&at.address, Locator::new("locator-b")).await,
        Err(StorageError::Conflict)
    );
    Ok(())
}

// Scenario: "every request reaches exactly one backend".

#[tokio::test]
async fn every_secret_command_reaches_only_its_namespace_s_backend() -> R {
    let f = fixture().await?;
    let at = target("work", "openai")?;
    f.storage.write(&at, value(b"v")?).await?;
    f.storage.read(&at).await?;
    f.storage.list(&scope("work")?).await?;
    f.storage.rename(&at, &name("openai-work")?).await?;
    f.storage.delete(&target("work", "openai-work")?).await?;
    assert_eq!(f.calls(), [0, 5, 0]);

    let local = target("default", "openai")?;
    f.storage.write(&local, value(b"v")?).await?;
    f.storage.read(&local).await?;
    assert_eq!(f.calls(), [2, 5, 0]);
    assert_eq!(
        f.keychain.calls(),
        vec![
            Call::Write(local.address.clone()),
            Call::Read(local.address.clone()),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_fault_or_a_miss_on_the_mounted_backend_never_falls_back() -> R {
    let f = fixture().await?;
    // The same name is held by the default mount; namespace `work` must never reach it.
    f.storage
        .write(&target("default", "openai")?, value(b"v")?)
        .await?;
    let before = f.keychain.calls().len();
    assert_eq!(
        refusal(f.storage.read(&target("work", "openai")?).await),
        Some(StorageError::NotFound)
    );
    f.remote.set_unavailable(true);
    every_secret_command(&f.storage, "work", StorageError::Unavailable).await?;
    assert_eq!(f.keychain.calls().len(), before);
    assert_eq!(f.vault.calls().len(), 0);
    Ok(())
}

#[tokio::test]
async fn set_mount_moves_every_later_request_to_the_new_backend_only() -> R {
    let f = fixture().await?;
    f.storage
        .set_mount(&key("work")?, BackendRef::default_mount())
        .await?;
    let remote_before = f.remote.calls().len();
    f.storage
        .write(&target("work", "openai")?, value(b"v")?)
        .await?;
    f.storage.read(&target("work", "openai")?).await?;
    assert_eq!(f.remote.calls().len(), remote_before);
    assert_eq!(f.keychain.calls().len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_backend_row_for_another_scope_is_dropped_from_a_listing() -> R {
    let config = Arc::new(InMemoryConfig::local());
    let storage =
        FederatedStorage::new(config).with_backend(BackendRef::default_mount(), Arc::new(Leaky))?;
    let rows = storage.list(&Scope::local()).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].address.scope, Scope::local());
    Ok(())
}

/// A backend that lists a row of another namespace beside the one asked for.
struct Leaky;

#[async_trait]
impl SecretStorage for Leaky {
    fn capabilities(&self) -> &[Capability] {
        &Capability::ALL
    }

    async fn read(&self, _: &Target) -> Result<Revealed, StorageError> {
        Err(StorageError::NotFound)
    }

    async fn write(&self, _: &Target, _: SecretValue) -> Result<Written, StorageError> {
        Err(StorageError::Unsupported)
    }

    async fn list(&self, scope: &Scope) -> Result<Vec<SecretMetadata>, StorageError> {
        let mine = Address {
            scope: scope.clone(),
            name: name("openai")?,
        };
        let other = address("elsewhere", "openai")?;
        Ok(vec![
            SecretMetadata {
                address: mine,
                version: None,
            },
            SecretMetadata {
                address: other,
                version: None,
            },
        ])
    }
}

// config-unavailable and the namespace commands' other refusals.

#[tokio::test]
async fn every_namespace_command_is_unavailable_when_the_configuration_store_is() -> R {
    let f = fixture().await?;
    f.config.set_unavailable(true);
    let at = address("work", "openai")?;
    assert_eq!(
        f.storage.add_namespace(key("new")?, None).await,
        Err(StorageError::Unavailable)
    );
    assert_eq!(
        f.storage.remove_namespace(&key("work")?).await,
        Err(StorageError::Unavailable)
    );
    assert_eq!(
        f.storage
            .set_mount(&key("work")?, BackendRef::default_mount())
            .await,
        Err(StorageError::Unavailable)
    );
    assert_eq!(
        f.storage.bind(&at, Locator::new("locator")).await,
        Err(StorageError::Unavailable)
    );
    assert_eq!(f.storage.unbind(&at).await, Err(StorageError::Unavailable));
    assert_eq!(
        f.storage.namespaces().await.err(),
        Some(StorageError::Unavailable)
    );
    // A secret command cannot resolve either, and so calls no backend.
    every_secret_command(&f.storage, "work", StorageError::Unavailable).await?;
    assert_eq!(f.calls(), [0, 0, 0]);
    f.config.set_unavailable(false);
    f.storage.add_namespace(key("new")?, None).await?;
    Ok(())
}

#[tokio::test]
async fn a_mount_on_an_unregistered_backend_is_not_found() -> R {
    let f = fixture().await?;
    let gone = BackendRef {
        kind: BackendKind::Keychain,
        label: label("gone")?,
    };
    assert_eq!(
        f.storage
            .add_namespace(key("new")?, Some(gone.clone()))
            .await,
        Err(StorageError::NotFound)
    );
    assert_eq!(
        f.storage.set_mount(&key("work")?, gone).await,
        Err(StorageError::NotFound)
    );
    assert_eq!(f.config.namespace(&key("new")?).await?, None);
    Ok(())
}

#[tokio::test]
async fn set_mount_and_bind_on_a_missing_namespace_and_unbind_of_an_unbound_name_are_not_found() -> R
{
    let f = fixture().await?;
    assert_eq!(
        f.storage
            .set_mount(&key("missing")?, BackendRef::default_mount())
            .await,
        Err(StorageError::NotFound)
    );
    let at = address("missing", "openai")?;
    assert_eq!(
        f.storage.bind(&at, Locator::new("locator")).await,
        Err(StorageError::NotFound)
    );
    assert_eq!(
        f.storage.unbind(&address("work", "openai")?).await,
        Err(StorageError::NotFound)
    );
    assert_eq!(f.calls(), [0, 0, 0]);
    Ok(())
}

#[tokio::test]
async fn the_namespaces_view_holds_each_namespace_with_its_mount() -> R {
    let f = fixture().await?;
    let namespaces = f.storage.namespaces().await?;
    assert_eq!(
        namespaces,
        vec![
            Namespace {
                key: key("default")?,
                mount: None,
            },
            Namespace {
                key: key("vault")?,
                mount: Some(onepassword_personal()?),
            },
            Namespace {
                key: key("work")?,
                mount: Some(remote_work()?),
            },
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_backend_registered_twice_is_conflict() -> R {
    let storage = FederatedStorage::new(Arc::new(InMemoryConfig::new()))
        .with_backend(BackendRef::default_mount(), Arc::new(Leaky))?;
    assert!(matches!(
        storage.with_backend(BackendRef::default_mount(), Arc::new(Leaky)),
        Err(StorageError::Conflict)
    ));
    Ok(())
}
