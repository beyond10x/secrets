//! The OS keychain as a `secrets.storage` backend (story:keychain-backend).
//!
//! Ported with attribution from `crates/llm-credentials/src/keychain.rs` in
//! `github.com/beyond10x/llm`: the injected [`CredentialStore`], the constructor that never touches
//! the store, the blocking calls run off the async runtime, and the error mapping, where
//! `NoEntry` is not-found and every other backend error is unavailable with its text dropped
//! unformatted.
//!
//! # Store
//!
//! The backend never reads or sets `keyring_core`'s process-wide default store: the embedding
//! chooses one and passes it to [`KeychainBackend::new`]. Tests pass a fresh
//! `keyring_core::mock::Store`. The platform's own store is `native_store`, behind the
//! non-default `native-keychain` feature, which no workspace member enables, so a default build
//! links no platform store.
//!
//! # Layout
//!
//! Every secret is one keychain entry. Its service is the backend's service
//! ([`DEFAULT_SERVICE`] unless [`KeychainBackend::with_service`] names another) and its user is
//! [`entry_user`]: tenant, namespace, user and name joined by `/`. A [`ScopeName`] holds no `/`
//! and a [`SecretName`] may, so the name is last and the first three `/` split the key
//! unambiguously.
//!
//! The entry holds a format byte, a 16-byte version and the value. Every successful write stores a
//! freshly generated version (a UUIDv7), so rewriting the same value still changes it; a rename
//! moves the entry unchanged.
//!
//! # Listing
//!
//! A keychain search is not exact: the mock store matches service and user as unanchored
//! substrings and also returns entries whose secret was deleted. [`SecretStorage::list`]
//! therefore keeps only entries whose service is exactly this backend's and whose decoded scope is
//! exactly the one asked for, and skips every entry that holds no secret.
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use keyring_core::{CredentialStore, Entry};
use secrets_core::storage::{
    Address, BackendKind, Capability, Revealed, Scope, ScopeName, SecretMetadata, SecretName,
    SecretStorage, SecretValue, StorageError, Target, Version, Written,
};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The keychain service every entry of a [`KeychainBackend::new`] backend is stored under.
pub const DEFAULT_SERVICE: &str = "b10x-secrets";

/// The first byte of every stored entry: the layout below.
const FORMAT: u8 = 1;
/// The format byte and the version that precede the value.
const HEADER: usize = 1 + 16;

/// The keychain user an address is stored under: `tenant/namespace/user/name`.
pub fn entry_user(address: &Address) -> String {
    let scope = &address.scope;
    format!(
        "{}/{}/{}/{}",
        scope.tenant, scope.namespace, scope.user, address.name
    )
}

/// The address a keychain user names, if it is one [`entry_user`] could have written.
fn decode_user(user: &str) -> Option<Address> {
    let mut parts = user.splitn(4, '/');
    let tenant = ScopeName::parse(parts.next()?).ok()?;
    let namespace = ScopeName::parse(parts.next()?).ok()?;
    let user = ScopeName::parse(parts.next()?).ok()?;
    let name = SecretName::parse(parts.next()?).ok()?;
    Some(Address {
        scope: Scope {
            tenant,
            namespace,
            user,
        },
        name,
    })
}

/// A keychain error as the port's code. The backend's own error is dropped, never formatted.
fn failure(error: keyring_core::Error) -> StorageError {
    match error {
        keyring_core::Error::NoEntry => StorageError::NotFound,
        other => {
            drop(other); // Discard backend diagnostics without formatting them.
            StorageError::Unavailable
        }
    }
}

/// The stored form of a value under a freshly generated version.
fn seal(value: &SecretValue) -> (Zeroizing<Vec<u8>>, Version) {
    let version = Uuid::now_v7();
    let mut blob = Zeroizing::new(Vec::with_capacity(HEADER + value.len()));
    blob.push(FORMAT);
    blob.extend_from_slice(version.as_bytes());
    blob.extend_from_slice(value.expose());
    (blob, Version::new(version.hyphenated().to_string()))
}

/// The version and value of a stored entry. An entry in another layout is a backend fault.
fn open(blob: &[u8]) -> Result<(Version, &[u8]), StorageError> {
    if blob.len() < HEADER || blob[0] != FORMAT {
        return Err(StorageError::Unavailable);
    }
    let version = Uuid::from_slice(&blob[1..HEADER]).map_err(|_| StorageError::Unavailable)?;
    Ok((
        Version::new(version.hyphenated().to_string()),
        &blob[HEADER..],
    ))
}

/// Whether the entry holds a secret: `Ok(None)` when it holds none.
fn stored(entry: &Entry) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
    match entry.get_secret() {
        Ok(blob) => Ok(Some(Zeroizing::new(blob))),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(other) => Err(failure(other)),
    }
}

/// Named secrets in a keychain, one entry per address.
pub struct KeychainBackend {
    store: Arc<CredentialStore>,
    service: Arc<str>,
    /// Serializes this backend's own writes, deletes and renames, so a check and the change it
    /// guards are not interleaved with another call of the same process.
    changes: Arc<Mutex<()>>,
}

impl KeychainBackend {
    /// A backend over `store` under [`DEFAULT_SERVICE`]. Does not call the store.
    pub fn new(store: Arc<CredentialStore>) -> Self {
        Self::with_service(store, DEFAULT_SERVICE)
    }

    /// A backend over `store` under `service`. Does not call the store. Two backends with
    /// different services share no secret, even over one store.
    pub fn with_service(store: Arc<CredentialStore>, service: impl Into<String>) -> Self {
        Self {
            store,
            service: Arc::from(service.into()),
            changes: Arc::new(Mutex::new(())),
        }
    }

    /// The keychain service this backend's entries are stored under.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Runs one keychain call off the async runtime, as `llm-credentials` does.
    async fn blocking<T: Send + 'static>(
        &self,
        operation: impl FnOnce(Calls) -> Result<T, StorageError> + Send + 'static,
    ) -> Result<T, StorageError> {
        let calls = Calls {
            store: self.store.clone(),
            service: self.service.clone(),
            changes: self.changes.clone(),
        };
        tokio::task::spawn_blocking(move || operation(calls))
            .await
            .map_err(|_| StorageError::Unavailable)?
    }
}

impl fmt::Debug for KeychainBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeychainBackend")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

/// What a blocking call needs, moved onto the blocking thread.
struct Calls {
    store: Arc<CredentialStore>,
    service: Arc<str>,
    changes: Arc<Mutex<()>>,
}

impl Calls {
    fn entry(&self, address: &Address) -> Result<Entry, StorageError> {
        self.store
            .build(&self.service, &entry_user(address), None)
            .map_err(failure)
    }

    fn exclusive(&self) -> Result<std::sync::MutexGuard<'_, ()>, StorageError> {
        self.changes.lock().map_err(|_| StorageError::Unavailable)
    }
}

#[async_trait]
impl SecretStorage for KeychainBackend {
    fn capabilities(&self) -> &[Capability] {
        BackendKind::Keychain.capabilities()
    }

    async fn read(&self, target: &Target) -> Result<Revealed, StorageError> {
        let address = target.address.clone();
        self.blocking(move |calls| {
            let entry = calls.entry(&address)?;
            let blob = Zeroizing::new(entry.get_secret().map_err(failure)?);
            let (version, value) = open(&blob)?;
            Ok(Revealed {
                value: SecretValue::new(value.to_vec())?,
                version: Some(version),
            })
        })
        .await
    }

    async fn write(&self, target: &Target, value: SecretValue) -> Result<Written, StorageError> {
        let address = target.address.clone();
        self.blocking(move |calls| {
            let _changes = calls.exclusive()?;
            let entry = calls.entry(&address)?;
            let existed = stored(&entry)?.is_some();
            let (blob, version) = seal(&value);
            entry.set_secret(&blob).map_err(failure)?;
            Ok(if existed {
                Written::Replaced(Some(version))
            } else {
                Written::Created(Some(version))
            })
        })
        .await
    }

    async fn delete(&self, target: &Target) -> Result<(), StorageError> {
        let address = target.address.clone();
        self.blocking(move |calls| {
            let _changes = calls.exclusive()?;
            calls.entry(&address)?.delete_credential().map_err(failure)
        })
        .await
    }

    async fn rename(&self, target: &Target, new_name: &SecretName) -> Result<(), StorageError> {
        let from = target.address.clone();
        let to = Address {
            scope: from.scope.clone(),
            name: new_name.clone(),
        };
        self.blocking(move |calls| {
            let _changes = calls.exclusive()?;
            let source = calls.entry(&from)?;
            let blob = Zeroizing::new(source.get_secret().map_err(failure)?);
            let destination = calls.entry(&to)?;
            if stored(&destination)?.is_some() {
                return Err(StorageError::Conflict);
            }
            destination.set_secret(&blob).map_err(failure)?;
            if let Err(error) = source.delete_credential() {
                // Undo the copy so the value is not left under both names.
                let _ = destination.delete_credential();
                return Err(failure(error));
            }
            Ok(())
        })
        .await
    }

    async fn list(&self, scope: &Scope) -> Result<Vec<SecretMetadata>, StorageError> {
        let scope = scope.clone();
        self.blocking(move |calls| {
            let spec = HashMap::from([("service", &*calls.service)]);
            let mut listed = Vec::new();
            for entry in calls.store.search(&spec).map_err(failure)? {
                let Some((service, user)) = entry.get_specifiers() else {
                    continue;
                };
                if service != *calls.service {
                    continue;
                }
                let Some(address) = decode_user(&user) else {
                    continue;
                };
                if address.scope != scope {
                    continue;
                }
                let Some(blob) = stored(&entry)? else {
                    continue;
                };
                let (version, _) = open(&blob)?;
                listed.push(SecretMetadata {
                    address,
                    version: Some(version),
                });
            }
            listed.sort();
            Ok(listed)
        })
        .await
    }
}

/// The platform's own credential store, chosen explicitly. Never changes the process default.
///
/// # Errors
/// [`StorageError::Unavailable`] if the store cannot be opened, [`StorageError::Unsupported`] on a
/// platform with no native store. Using the store may require the user to unlock it.
#[cfg(feature = "native-keychain")]
pub fn native_store() -> Result<Arc<CredentialStore>, StorageError> {
    #[cfg(target_os = "linux")]
    {
        zbus_secret_service_keyring_store::Store::new()
            .map(|store| store as Arc<CredentialStore>)
            .map_err(failure)
    }
    #[cfg(target_os = "macos")]
    {
        apple_native_keyring_store::keychain::Store::new()
            .map(|store| store as Arc<CredentialStore>)
            .map_err(failure)
    }
    #[cfg(target_os = "windows")]
    {
        windows_native_keyring_store::Store::new()
            .map(|store| store as Arc<CredentialStore>)
            .map_err(failure)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(StorageError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn address(tenant: &str, namespace: &str, user: &str, name: &str) -> Address {
        Address::parse(tenant, namespace, user, name).unwrap()
    }

    #[test]
    fn the_entry_user_puts_the_name_last_and_decodes_back_exactly() {
        let nested = address("a", "ns", "u", "team/openai");
        assert_eq!(entry_user(&nested), "a/ns/u/team/openai");
        assert_eq!(decode_user("a/ns/u/team/openai"), Some(nested));
        for foreign in [
            "",
            "a",
            "a/ns",
            "a/ns/u",
            "a/ns/u/",
            "A/ns/u/x",
            "a/ns/u/-x",
        ] {
            assert_eq!(decode_user(foreign), None, "{foreign}");
        }
    }

    #[test]
    fn no_entry_is_not_found_and_every_other_error_is_unavailable() {
        assert_eq!(
            failure(keyring_core::Error::NoEntry),
            StorageError::NotFound
        );
        for error in [
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("marker"))),
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("marker"))),
            keyring_core::Error::BadEncoding(b"marker".to_vec()),
            keyring_core::Error::Invalid("marker".into(), "marker".into()),
            keyring_core::Error::NotSupportedByStore("marker".into()),
            keyring_core::Error::NoDefaultStore,
        ] {
            assert_eq!(failure(error), StorageError::Unavailable);
        }
    }

    #[test]
    fn a_sealed_value_opens_to_its_bytes_and_version() {
        let value = SecretValue::new(b"bytes".to_vec()).unwrap();
        let (blob, version) = seal(&value);
        let (opened, bytes) = open(&blob).unwrap();
        assert_eq!((opened, bytes), (version, &b"bytes"[..]));
        assert_eq!(open(b"short"), Err(StorageError::Unavailable));
        let mut other = blob.to_vec();
        other[0] = 0;
        assert_eq!(open(&other), Err(StorageError::Unavailable));
    }
}
