//! Mount routing over secrets.storage backends, one backend per namespace and no fallback
//! (story:mount-federation).
//!
//! [`FederatedStorage`] implements the storage port ([`SecretStorage`]) over backends handed to it
//! as port objects keyed by [`BackendRef`], so it depends on no backend crate. Namespaces, their
//! mounts and bindings live in a [`NamespaceConfig`] store.
//!
//! # Resolution
//!
//! Every secret command resolves its address the same way, as `spec/domains/storage.yaml` states
//! it above the secret commands, and calls no backend until resolution has succeeded:
//!
//! 1. the scope's namespace must exist, or the command is [`StorageError::NotFound`];
//! 2. its mount ([`Namespace::effective_mount`]) names exactly one backend, which must be
//!    registered, or the command is [`StorageError::NotFound`];
//! 3. the backend must offer every capability the command needs, or the command is
//!    [`StorageError::Unsupported`] (a write, delete or rename on a read-only mount);
//! 4. a backend that [requires a binding](SecretStorage::requires_binding) is given the locator
//!    bound to the address, and a name with none is [`StorageError::NotFound`].
//!
//! The backend's answer, refusal or fault, is the command's answer. Nothing falls back to another
//! backend. A locator a caller puts in a [`Target`] is ignored: only a binding sets one.
//!
//! # Bindings
//!
//! Bindings never move. Renaming a bound name, or renaming onto a bound name, is
//! [`StorageError::Conflict`], and [`SecretStorage::delete`] never removes a binding.
//!
//! # What this crate does not decide
//!
//! It authorizes nothing: `denied` is the authorizer's, composed in front of it. Names and values
//! are refused by the port's own types before they reach it.
use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use secrets_core::storage::{
    Address, BackendRef, Capability, Locator, NamespaceKey, Revealed, Scope, ScopeName,
    SecretMetadata, SecretName, SecretStorage, SecretValue, StorageError, Target, Written,
};

pub mod config;
#[cfg(feature = "file-config")]
pub mod file;

pub use config::{InMemoryConfig, Namespace, NamespaceConfig};
#[cfg(feature = "file-config")]
pub use file::FileConfig;

#[cfg(test)]
mod tests;

/// The storage port over one backend per namespace.
pub struct FederatedStorage {
    config: Arc<dyn NamespaceConfig>,
    backends: BTreeMap<BackendRef, Arc<dyn SecretStorage>>,
}

impl FederatedStorage {
    /// Routing over `config` with no backend registered yet.
    pub fn new(config: Arc<dyn NamespaceConfig>) -> Self {
        Self {
            config,
            backends: BTreeMap::new(),
        }
    }

    /// Registers `storage` as the backend `backend` names.
    ///
    /// # Errors
    /// [`StorageError::Conflict`] if a backend is already registered under that reference.
    pub fn with_backend(
        mut self,
        backend: BackendRef,
        storage: Arc<dyn SecretStorage>,
    ) -> Result<Self, StorageError> {
        if self.backends.contains_key(&backend) {
            return Err(StorageError::Conflict);
        }
        self.backends.insert(backend, storage);
        Ok(self)
    }

    /// Every registered backend reference, ordered.
    pub fn backends(&self) -> impl Iterator<Item = &BackendRef> {
        self.backends.keys()
    }

    /// The configuration store routing reads.
    pub fn config(&self) -> &Arc<dyn NamespaceConfig> {
        &self.config
    }

    /// Every namespace with its mount (the `Namespaces` view).
    ///
    /// # Errors
    /// [`StorageError::Unavailable`] if the configuration store cannot be reached.
    pub async fn namespaces(&self) -> Result<Vec<Namespace>, StorageError> {
        self.config.namespaces().await
    }

    /// `AddNamespace`: a new namespace on `mount`, or on the default mount when `None`.
    ///
    /// # Errors
    /// [`StorageError::Conflict`] if the namespace exists; [`StorageError::NotFound`] if the mount
    /// names no registered backend; [`StorageError::Unavailable`] if the store cannot be reached.
    pub async fn add_namespace(
        &self,
        key: NamespaceKey,
        mount: Option<BackendRef>,
    ) -> Result<(), StorageError> {
        if self.config.namespace(&key).await?.is_some() {
            return Err(StorageError::Conflict);
        }
        let namespace = Namespace { key, mount };
        self.registered(&namespace.effective_mount())?;
        self.config.insert_namespace(namespace).await
    }

    /// `RemoveNamespace`.
    ///
    /// # Errors
    /// [`StorageError::Conflict`] for namespace `default`, or while bindings or secrets remain;
    /// [`StorageError::NotFound`] if the namespace does not exist; [`StorageError::Unavailable`] if
    /// the store, or the backend asked whether secrets remain, cannot be reached.
    pub async fn remove_namespace(&self, key: &NamespaceKey) -> Result<(), StorageError> {
        if key.namespace.is_default() {
            return Err(StorageError::Conflict);
        }
        let namespace = self
            .config
            .namespace(key)
            .await?
            .ok_or(StorageError::NotFound)?;
        if self.config.has_bindings(key).await? || self.holds_secrets(&namespace).await? {
            return Err(StorageError::Conflict);
        }
        self.config.remove_namespace(key).await
    }

    /// `SetMount`: the namespace routes to `mount` and to no other backend.
    ///
    /// # Errors
    /// [`StorageError::NotFound`] if the namespace does not exist or `mount` names no registered
    /// backend; [`StorageError::Conflict`] while secrets exist under the current mount;
    /// [`StorageError::Unavailable`] if the store, or the current backend, cannot be reached.
    pub async fn set_mount(
        &self,
        key: &NamespaceKey,
        mount: BackendRef,
    ) -> Result<(), StorageError> {
        let namespace = self
            .config
            .namespace(key)
            .await?
            .ok_or(StorageError::NotFound)?;
        self.registered(&mount)?;
        if self.holds_secrets(&namespace).await? {
            return Err(StorageError::Conflict);
        }
        self.config.set_mount(key, mount).await
    }

    /// `Bind`: the address resolves to `locator` in its namespace's backend.
    ///
    /// # Errors
    /// [`StorageError::NotFound`] if the namespace does not exist; [`StorageError::Conflict`] if
    /// the address is already bound; [`StorageError::Unavailable`] if the store cannot be reached.
    pub async fn bind(&self, address: &Address, locator: Locator) -> Result<(), StorageError> {
        self.config
            .namespace(&namespace_key(&address.scope))
            .await?
            .ok_or(StorageError::NotFound)?;
        self.config.insert_binding(address.clone(), locator).await
    }

    /// `Unbind`.
    ///
    /// # Errors
    /// [`StorageError::NotFound`] if the address has no binding; [`StorageError::Unavailable`] if
    /// the store cannot be reached.
    pub async fn unbind(&self, address: &Address) -> Result<(), StorageError> {
        self.config.remove_binding(address).await
    }

    fn registered(&self, backend: &BackendRef) -> Result<&dyn SecretStorage, StorageError> {
        self.backends
            .get(backend)
            .map(Arc::as_ref)
            .ok_or(StorageError::NotFound)
    }

    /// Steps 1 and 2 of resolution: the one backend the scope's namespace is mounted on.
    async fn mounted(&self, scope: &Scope) -> Result<&dyn SecretStorage, StorageError> {
        let namespace = self
            .config
            .namespace(&namespace_key(scope))
            .await?
            .ok_or(StorageError::NotFound)?;
        self.registered(&namespace.effective_mount())
    }

    /// Steps 1 to 4: the backend, checked for `needs`, and the target it is asked about.
    async fn resolve(
        &self,
        address: &Address,
        needs: &[Capability],
    ) -> Result<(&dyn SecretStorage, Target), StorageError> {
        let backend = self.mounted(&address.scope).await?;
        require(backend, needs)?;
        let locator = if backend.requires_binding() {
            Some(
                self.config
                    .binding(address)
                    .await?
                    .ok_or(StorageError::NotFound)?,
            )
        } else {
            None
        };
        Ok((
            backend,
            Target {
                address: address.clone(),
                locator,
            },
        ))
    }

    /// Whether the namespace's current backend lists any secret for local mode's one user. A
    /// backend that cannot list holds nothing this crate wrote, and an unregistered one is
    /// reached by no command.
    async fn holds_secrets(&self, namespace: &Namespace) -> Result<bool, StorageError> {
        let Some(backend) = self.backends.get(&namespace.effective_mount()) else {
            return Ok(false);
        };
        if !backend.capabilities().contains(&Capability::List) {
            return Ok(false);
        }
        let scope = Scope {
            tenant: namespace.key.tenant.clone(),
            namespace: namespace.key.namespace.clone(),
            user: ScopeName::default_name(),
        };
        Ok(!backend.list(&scope).await?.is_empty())
    }
}

fn namespace_key(scope: &Scope) -> NamespaceKey {
    NamespaceKey {
        tenant: scope.tenant.clone(),
        namespace: scope.namespace.clone(),
    }
}

fn require(backend: &dyn SecretStorage, needs: &[Capability]) -> Result<(), StorageError> {
    let offered = backend.capabilities();
    if needs.iter().all(|need| offered.contains(need)) {
        Ok(())
    } else {
        Err(StorageError::Unsupported)
    }
}

#[async_trait]
impl SecretStorage for FederatedStorage {
    /// Every capability: what a command may do is decided per namespace, by its backend.
    fn capabilities(&self) -> &[Capability] {
        &Capability::ALL
    }

    /// Routing applies bindings itself, so a caller never needs one.
    fn requires_binding(&self) -> bool {
        false
    }

    async fn read(&self, target: &Target) -> Result<Revealed, StorageError> {
        let (backend, target) = self.resolve(&target.address, &[Capability::Read]).await?;
        backend.read(&target).await
    }

    async fn write(&self, target: &Target, value: SecretValue) -> Result<Written, StorageError> {
        let (backend, target) = self.resolve(&target.address, &[Capability::Write]).await?;
        backend.write(&target, value).await
    }

    /// Removes the secret, never its binding.
    async fn delete(&self, target: &Target) -> Result<(), StorageError> {
        let (backend, target) = self.resolve(&target.address, &[Capability::Delete]).await?;
        backend.delete(&target).await
    }

    /// [`StorageError::Conflict`] if either name is bound: bindings never move.
    async fn rename(&self, target: &Target, new_name: &SecretName) -> Result<(), StorageError> {
        let (backend, target) = self
            .resolve(&target.address, &[Capability::Write, Capability::Delete])
            .await?;
        let to = Address {
            scope: target.address.scope.clone(),
            name: new_name.clone(),
        };
        if self.config.binding(&target.address).await?.is_some()
            || self.config.binding(&to).await?.is_some()
        {
            return Err(StorageError::Conflict);
        }
        backend.rename(&target, new_name).await
    }

    /// The backend's rows for exactly `scope`; a row it returns for another scope is dropped.
    async fn list(&self, scope: &Scope) -> Result<Vec<SecretMetadata>, StorageError> {
        let backend = self.mounted(scope).await?;
        require(backend, &[Capability::List])?;
        let mut rows = backend.list(scope).await?;
        rows.retain(|row| &row.address.scope == scope);
        Ok(rows)
    }
}
