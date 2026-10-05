//! The backends the local commands mount, from the `backends` table of the configuration file.
//!
//! ```toml
//! [backends.keychain.work]          # keychain/default needs no entry
//! service = "b10x-secrets.work"     # optional; this is the default for label `work`
//!
//! [backends.remote.prod]
//! origin = "https://secrets.example"
//! token_env = "B10X_SECRETS_TOKEN"  # or token_file = "/path/to/token", mode 0600
//! ```
//!
//! `keychain/default` is always configured. Every keychain label shares one credential store: the
//! platform's own under feature `native-keychain`, otherwise none, and the keychain then answers
//! `unavailable` and says why. A remote token comes from an environment variable or a protected
//! file, never from the command line or this file. A backend that cannot be built is still
//! mounted, answering `unavailable`, so a command on it says so instead of `not-found`.
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use keyring_core::CredentialStore;
use secrets_core::storage::{
    BackendKind, BackendRef, Capability, Revealed, Scope, ScopeName, SecretMetadata, SecretName,
    SecretStorage, SecretValue, StorageError, Target, Written,
};
use secrets_keychain::{DEFAULT_SERVICE, KeychainBackend};
use secrets_remote::RemoteBackend;
use serde::Deserialize;
use zeroize::Zeroizing;

/// The `backends` table. Every other key of the file is the namespace store's.
#[derive(Default, Deserialize)]
struct File {
    #[serde(default)]
    backends: Table,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    #[serde(default)]
    keychain: BTreeMap<String, KeychainEntry>,
    #[serde(default)]
    remote: BTreeMap<String, RemoteEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeychainEntry {
    service: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteEntry {
    origin: String,
    token_env: Option<String>,
    token_file: Option<PathBuf>,
}

/// Every configured backend, and what the user should know about the ones that cannot be used.
pub struct Backends {
    pub mounted: Vec<(BackendRef, Arc<dyn SecretStorage>)>,
    pub notes: Vec<String>,
    /// Called once the command is done: a test store saves itself to its file.
    pub finish: Option<Box<dyn FnOnce()>>,
}

/// A backend that cannot be reached, with the capabilities of its kind.
struct Unreachable(BackendKind);

#[async_trait]
impl SecretStorage for Unreachable {
    fn capabilities(&self) -> &[Capability] {
        self.0.capabilities()
    }
    async fn read(&self, _: &Target) -> Result<Revealed, StorageError> {
        Err(StorageError::Unavailable)
    }
    async fn write(&self, _: &Target, _: SecretValue) -> Result<Written, StorageError> {
        Err(StorageError::Unavailable)
    }
    async fn delete(&self, _: &Target) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    async fn rename(&self, _: &Target, _: &SecretName) -> Result<(), StorageError> {
        Err(StorageError::Unavailable)
    }
    async fn list(&self, _: &Scope) -> Result<Vec<SecretMetadata>, StorageError> {
        Err(StorageError::Unavailable)
    }
}

fn reference(kind: BackendKind, label: &str) -> Option<BackendRef> {
    Some(BackendRef {
        kind,
        label: ScopeName::parse(label).ok()?,
    })
}

/// The credential store every keychain label uses, or why there is none.
struct Keychain {
    store: Result<Arc<CredentialStore>, String>,
    finish: Option<Box<dyn FnOnce()>>,
}

#[cfg(feature = "test-hooks")]
fn test_keychain() -> Option<Keychain> {
    let path = std::env::var_os("SECRETSCTL_TEST_KEYCHAIN_FILE")?;
    let path = path.to_str()?.to_owned();
    Some(match keyring_core::sample::Store::new_with_backing(&path) {
        Ok(store) => {
            let saved = store.clone();
            Keychain {
                store: Ok(store as Arc<CredentialStore>),
                finish: Some(Box::new(move || {
                    let _ = saved.save();
                })),
            }
        }
        Err(_) => Keychain {
            store: Err("keychain: the test keychain file could not be read".to_owned()),
            finish: None,
        },
    })
}

#[cfg(feature = "native-keychain")]
fn platform_keychain() -> Keychain {
    Keychain {
        store: secrets_keychain::native_store()
            .map_err(|_| "keychain: the OS keychain could not be opened".to_owned()),
        finish: None,
    }
}

#[cfg(not(feature = "native-keychain"))]
fn platform_keychain() -> Keychain {
    Keychain {
        store: Err(
            "keychain: this secretsctl was built without the OS keychain; \
                    rebuild it with `--features native-keychain`"
                .to_owned(),
        ),
        finish: None,
    }
}

fn keychain() -> Keychain {
    #[cfg(feature = "test-hooks")]
    if let Some(keychain) = test_keychain() {
        return keychain;
    }
    platform_keychain()
}

/// A remote token from the source the entry names: exactly one of an environment variable or a
/// file readable by its owner only.
fn token(label: &str, entry: &RemoteEntry) -> Result<Zeroizing<String>, String> {
    match (&entry.token_env, &entry.token_file) {
        (Some(variable), None) => std::env::var(variable)
            .map(Zeroizing::new)
            .map_err(|_| format!("remote/{label}: the token variable `{variable}` is unset")),
        (None, Some(path)) => {
            let bytes = crate::value::read_protected(path, 64 * 1024)
                .map_err(|refusal| format!("remote/{label}: token file: {refusal}"))?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| format!("remote/{label}: the token file is not UTF-8"))?;
            Ok(Zeroizing::new(text.trim().to_owned()))
        }
        _ => Err(format!(
            "remote/{label}: set exactly one of `token_env` and `token_file`"
        )),
    }
}

/// Every backend the configuration file at `path` names, with `keychain/default` always among
/// them.
pub fn load(path: &std::path::Path) -> Backends {
    let mut notes = Vec::new();
    let table = match std::fs::read_to_string(path) {
        Ok(text) => match toml::from_str::<File>(&text) {
            Ok(file) => file.backends,
            Err(_) => {
                notes.push("config: the `backends` table is not valid".to_owned());
                Table::default()
            }
        },
        Err(_) => Table::default(),
    };
    let keychain = keychain();
    let mut mounted: Vec<(BackendRef, Arc<dyn SecretStorage>)> = Vec::new();
    let mut keychain_failed = false;
    let mut services =
        BTreeMap::from([(ScopeName::DEFAULT.to_owned(), DEFAULT_SERVICE.to_owned())]);
    for (label, entry) in table.keychain {
        let service = entry
            .service
            .unwrap_or_else(|| format!("{DEFAULT_SERVICE}.{label}"));
        services.insert(label, service);
    }
    for (label, service) in services {
        let Some(backend) = reference(BackendKind::Keychain, &label) else {
            notes.push("config: a keychain label is not a valid name".to_owned());
            continue;
        };
        let storage: Arc<dyn SecretStorage> = match &keychain.store {
            Ok(store) => Arc::new(KeychainBackend::with_service(store.clone(), service)),
            Err(note) => {
                if !keychain_failed {
                    notes.push(note.clone());
                    keychain_failed = true;
                }
                Arc::new(Unreachable(BackendKind::Keychain))
            }
        };
        mounted.push((backend, storage));
    }
    for (label, entry) in table.remote {
        let Some(backend) = reference(BackendKind::Remote, &label) else {
            notes.push("config: a remote label is not a valid name".to_owned());
            continue;
        };
        let storage: Arc<dyn SecretStorage> = match token(&label, &entry).and_then(|token| {
            secrets_client::Client::new(&entry.origin, token.as_str())
                .map_err(|_| format!("remote/{label}: `origin` is not a URL"))
        }) {
            Ok(client) => Arc::new(RemoteBackend::new(client)),
            Err(note) => {
                notes.push(note);
                Arc::new(Unreachable(BackendKind::Remote))
            }
        };
        mounted.push((backend, storage));
    }
    Backends {
        mounted,
        notes,
        finish: keychain.finish,
    }
}
