//! The namespace configuration store: every namespace with its mount, and every binding.
//!
//! [`NamespaceConfig`] is the seam the specification's `config-unavailable` outcomes stand on: a
//! store that cannot be reached answers [`StorageError::Unavailable`], and mount routing passes
//! that on. [`InMemoryConfig`] is the store in this crate; a file-backed one belongs to the local
//! CLI.
//!
//! A store keeps records and refuses only the collisions it can see on its own: a namespace or a
//! binding that already exists is [`StorageError::Conflict`], one that does not is
//! [`StorageError::NotFound`]. Every other rule (the `default` namespace, a mount on an unknown
//! backend, a namespace still in use) is [`crate::FederatedStorage`]'s.
use std::{
    collections::BTreeMap,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use secrets_core::storage::{Address, BackendRef, Locator, NamespaceKey, ScopeName, StorageError};

/// One namespace and its mount.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Namespace {
    pub key: NamespaceKey,
    /// The backend the namespace is mounted on; `None` is the default mount
    /// ([`BackendRef::default_mount`]).
    pub mount: Option<BackendRef>,
}

impl Namespace {
    /// The one backend this namespace routes to.
    pub fn effective_mount(&self) -> BackendRef {
        self.mount.clone().unwrap_or_else(BackendRef::default_mount)
    }
}

/// Where namespaces, mounts and bindings are kept.
///
/// Every method may answer [`StorageError::Unavailable`] when the store cannot be reached. No
/// method lists bindings: a locator can name a vault item, so only a lookup by address exists.
#[async_trait]
pub trait NamespaceConfig: Send + Sync {
    /// The namespace, if one of this key exists.
    async fn namespace(&self, key: &NamespaceKey) -> Result<Option<Namespace>, StorageError>;

    /// Every namespace, ordered by key.
    async fn namespaces(&self) -> Result<Vec<Namespace>, StorageError>;

    /// Adds the namespace. [`StorageError::Conflict`] if one of its key exists.
    async fn insert_namespace(&self, namespace: Namespace) -> Result<(), StorageError>;

    /// Removes the namespace. [`StorageError::NotFound`] if none of this key exists.
    async fn remove_namespace(&self, key: &NamespaceKey) -> Result<(), StorageError>;

    /// Points the namespace at `mount`. [`StorageError::NotFound`] if none of this key exists.
    async fn set_mount(&self, key: &NamespaceKey, mount: BackendRef) -> Result<(), StorageError>;

    /// The locator bound to the address, if any.
    async fn binding(&self, address: &Address) -> Result<Option<Locator>, StorageError>;

    /// Whether any address in the namespace, of any user, has a binding.
    async fn has_bindings(&self, key: &NamespaceKey) -> Result<bool, StorageError>;

    /// Binds the address to the locator. [`StorageError::Conflict`] if it is already bound.
    async fn insert_binding(&self, address: Address, locator: Locator) -> Result<(), StorageError>;

    /// Removes the address's binding. [`StorageError::NotFound`] if it has none.
    async fn remove_binding(&self, address: &Address) -> Result<(), StorageError>;
}

#[derive(Default)]
struct State {
    namespaces: BTreeMap<NamespaceKey, Option<BackendRef>>,
    bindings: BTreeMap<Address, Locator>,
}

/// A [`NamespaceConfig`] held in memory, gone when it is dropped.
#[derive(Default)]
pub struct InMemoryConfig {
    unavailable: AtomicBool,
    state: Mutex<State>,
}

impl InMemoryConfig {
    /// A store with no namespace at all.
    pub fn new() -> Self {
        Self::default()
    }

    /// Local mode's starting point: namespace `default` in tenant `default`, on the default mount.
    pub fn local() -> Self {
        let store = Self::new();
        if let Ok(mut state) = store.state.lock() {
            state.namespaces.insert(
                NamespaceKey {
                    tenant: ScopeName::default_name(),
                    namespace: ScopeName::default_name(),
                },
                None,
            );
        }
        store
    }

    /// From now on, answer every call [`StorageError::Unavailable`] (or stop doing so), as a store
    /// that cannot be reached would.
    #[cfg(any(test, feature = "testing"))]
    pub fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, StorageError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(StorageError::Unavailable);
        }
        self.state.lock().map_err(|_| StorageError::Unavailable)
    }
}

#[async_trait]
impl NamespaceConfig for InMemoryConfig {
    async fn namespace(&self, key: &NamespaceKey) -> Result<Option<Namespace>, StorageError> {
        Ok(self.lock()?.namespaces.get(key).map(|mount| Namespace {
            key: key.clone(),
            mount: mount.clone(),
        }))
    }

    async fn namespaces(&self) -> Result<Vec<Namespace>, StorageError> {
        Ok(self
            .lock()?
            .namespaces
            .iter()
            .map(|(key, mount)| Namespace {
                key: key.clone(),
                mount: mount.clone(),
            })
            .collect())
    }

    async fn insert_namespace(&self, namespace: Namespace) -> Result<(), StorageError> {
        let mut state = self.lock()?;
        if state.namespaces.contains_key(&namespace.key) {
            return Err(StorageError::Conflict);
        }
        state.namespaces.insert(namespace.key, namespace.mount);
        Ok(())
    }

    async fn remove_namespace(&self, key: &NamespaceKey) -> Result<(), StorageError> {
        self.lock()?
            .namespaces
            .remove(key)
            .map(drop)
            .ok_or(StorageError::NotFound)
    }

    async fn set_mount(&self, key: &NamespaceKey, mount: BackendRef) -> Result<(), StorageError> {
        let mut state = self.lock()?;
        let slot = state
            .namespaces
            .get_mut(key)
            .ok_or(StorageError::NotFound)?;
        *slot = Some(mount);
        Ok(())
    }

    async fn binding(&self, address: &Address) -> Result<Option<Locator>, StorageError> {
        Ok(self.lock()?.bindings.get(address).cloned())
    }

    async fn has_bindings(&self, key: &NamespaceKey) -> Result<bool, StorageError> {
        Ok(self.lock()?.bindings.keys().any(|address| {
            address.scope.tenant == key.tenant && address.scope.namespace == key.namespace
        }))
    }

    async fn insert_binding(&self, address: Address, locator: Locator) -> Result<(), StorageError> {
        let mut state = self.lock()?;
        if state.bindings.contains_key(&address) {
            return Err(StorageError::Conflict);
        }
        state.bindings.insert(address, locator);
        Ok(())
    }

    async fn remove_binding(&self, address: &Address) -> Result<(), StorageError> {
        self.lock()?
            .bindings
            .remove(address)
            .map(drop)
            .ok_or(StorageError::NotFound)
    }
}
