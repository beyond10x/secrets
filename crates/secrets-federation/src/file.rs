//! A [`NamespaceConfig`] kept in one TOML file (feature `file-config`).
//!
//! The local CLI keeps its namespaces, mounts and bindings here, in
//! `$XDG_CONFIG_HOME/b10x-secrets/config.toml`. The file holds no secret: a locator names where a
//! value lives, never the value.
//!
//! ```toml
//! [[namespace]]
//! tenant = "default"
//! name = "work"
//! mount = { kind = "keychain", label = "work" }
//!
//! [[binding]]
//! tenant = "default"
//! namespace = "work"
//! user = "default"
//! name = "openai"
//! locator = "op://Work/OpenAI/credential"
//! ```
//!
//! This store reads and writes only the `namespace` and `binding` arrays. Every other key in the
//! file, such as the backend table an embedding configures its backends from, is kept as it was.
//!
//! # Writes
//!
//! Every change is a read-modify-write under an exclusive lock on a sibling `<file>.lock`, and the
//! new file replaces the old one atomically: it is written in full to a fresh file in the same
//! directory, created with mode 0600, synced, and renamed over the old one. A missing directory is
//! created with mode 0700. A reader never sees a partly written file.
//!
//! # Unavailable
//!
//! A file that cannot be read, is not TOML, or holds a record that is not a valid namespace or
//! binding answers every call [`StorageError::Unavailable`], as a store that cannot be reached
//! does. A missing file is local mode's starting point: namespace `default` in tenant `default`, on
//! the default mount. Namespace `default` of tenant `default` always exists, whatever the file says.
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use secrets_core::storage::{
    Address, BackendRef, Locator, NamespaceKey, Scope, ScopeName, SecretName, StorageError,
};
use serde::{Deserialize, Serialize};

use crate::config::{Namespace, NamespaceConfig};

const NAMESPACES: &str = "namespace";
const BINDINGS: &str = "binding";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceRecord {
    tenant: ScopeName,
    name: ScopeName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mount: Option<BackendRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingRecord {
    tenant: ScopeName,
    namespace: ScopeName,
    user: ScopeName,
    name: SecretName,
    locator: Locator,
}

/// What the file says, with every key this store does not own kept aside.
struct Document {
    rest: toml::Table,
    namespaces: BTreeMap<NamespaceKey, Option<BackendRef>>,
    bindings: BTreeMap<Address, Locator>,
}

fn local_default() -> NamespaceKey {
    NamespaceKey {
        tenant: ScopeName::default_name(),
        namespace: ScopeName::default_name(),
    }
}

fn unavailable(error: impl Sized) -> StorageError {
    drop(error); // The store's own diagnostics are not part of a refusal.
    StorageError::Unavailable
}

fn records<T: for<'de> Deserialize<'de>>(
    table: &mut toml::Table,
    key: &str,
) -> Result<Vec<T>, StorageError> {
    match table.remove(key) {
        None => Ok(Vec::new()),
        Some(value) => value.try_into().map_err(unavailable),
    }
}

impl Document {
    fn parse(text: &str) -> Result<Self, StorageError> {
        let mut rest: toml::Table = toml::from_str(text).map_err(unavailable)?;
        let mut namespaces = BTreeMap::new();
        for record in records::<NamespaceRecord>(&mut rest, NAMESPACES)? {
            let key = NamespaceKey {
                tenant: record.tenant,
                namespace: record.name,
            };
            if namespaces.insert(key, record.mount).is_some() {
                return Err(StorageError::Unavailable);
            }
        }
        namespaces.entry(local_default()).or_insert(None);
        let mut bindings = BTreeMap::new();
        for record in records::<BindingRecord>(&mut rest, BINDINGS)? {
            let address = Address {
                scope: Scope {
                    tenant: record.tenant,
                    namespace: record.namespace,
                    user: record.user,
                },
                name: record.name,
            };
            if bindings.insert(address, record.locator).is_some() {
                return Err(StorageError::Unavailable);
            }
        }
        Ok(Self {
            rest,
            namespaces,
            bindings,
        })
    }

    fn render(&self) -> Result<String, StorageError> {
        let mut table = self.rest.clone();
        let namespaces = self
            .namespaces
            .iter()
            .map(|(key, mount)| NamespaceRecord {
                tenant: key.tenant.clone(),
                name: key.namespace.clone(),
                mount: mount.clone(),
            })
            .collect::<Vec<_>>();
        table.insert(
            NAMESPACES.to_owned(),
            toml::Value::try_from(namespaces).map_err(unavailable)?,
        );
        if !self.bindings.is_empty() {
            let bindings = self
                .bindings
                .iter()
                .map(|(address, locator)| BindingRecord {
                    tenant: address.scope.tenant.clone(),
                    namespace: address.scope.namespace.clone(),
                    user: address.scope.user.clone(),
                    name: address.name.clone(),
                    locator: locator.clone(),
                })
                .collect::<Vec<_>>();
            table.insert(
                BINDINGS.to_owned(),
                toml::Value::try_from(bindings).map_err(unavailable)?,
            );
        }
        toml::to_string(&table).map_err(unavailable)
    }
}

/// Namespaces, mounts and bindings in one TOML file.
#[derive(Clone, Debug)]
pub struct FileConfig {
    path: PathBuf,
}

impl FileConfig {
    /// A store over the file at `path`. Touches nothing until it is called.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file this store reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock_path(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        self.path.with_file_name(name)
    }

    fn load(&self) -> Result<Document, StorageError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => Document::parse(&text),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Document::parse(""),
            Err(error) => Err(unavailable(error)),
        }
    }

    /// Loads the file, applies `change` and, when it succeeds, writes the file back atomically, all
    /// under the exclusive lock. A refused change writes nothing.
    fn change<T>(
        &self,
        change: impl FnOnce(&mut Document) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let directory = self.directory();
        create_private_dir(directory).map_err(unavailable)?;
        let lock = private_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_path())
            .map_err(unavailable)?;
        lock.lock().map_err(unavailable)?;
        let mut document = self.load()?;
        let answer = change(&mut document)?;
        let text = document.render()?;
        replace(directory, &self.path, text.as_bytes()).map_err(unavailable)?;
        drop(lock);
        Ok(answer)
    }

    fn directory(&self) -> &Path {
        match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        }
    }
}

fn private_options() -> fs::OpenOptions {
    #[allow(unused_mut)]
    let mut options = fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
}

fn create_private_dir(directory: &Path) -> io::Result<()> {
    #[allow(unused_mut)]
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(directory)
}

/// Writes `bytes` to a fresh mode-0600 file beside `path` and renames it over `path`.
fn replace(directory: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp-{}-{nanos}", std::process::id()));
    let staged = directory.join(name);
    let written = (|| {
        let mut file = private_options()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&staged, path)?;
        #[cfg(unix)]
        fs::File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&staged);
    }
    written
}

#[async_trait]
impl NamespaceConfig for FileConfig {
    async fn namespace(&self, key: &NamespaceKey) -> Result<Option<Namespace>, StorageError> {
        Ok(self.load()?.namespaces.get(key).map(|mount| Namespace {
            key: key.clone(),
            mount: mount.clone(),
        }))
    }

    async fn namespaces(&self) -> Result<Vec<Namespace>, StorageError> {
        Ok(self
            .load()?
            .namespaces
            .into_iter()
            .map(|(key, mount)| Namespace { key, mount })
            .collect())
    }

    async fn insert_namespace(&self, namespace: Namespace) -> Result<(), StorageError> {
        self.change(|document| {
            if document.namespaces.contains_key(&namespace.key) {
                return Err(StorageError::Conflict);
            }
            document.namespaces.insert(namespace.key, namespace.mount);
            Ok(())
        })
    }

    async fn remove_namespace(&self, key: &NamespaceKey) -> Result<(), StorageError> {
        self.change(|document| {
            if key == &local_default() {
                // Always present, so never removed: routing refuses it before asking.
                return Err(StorageError::Conflict);
            }
            document
                .namespaces
                .remove(key)
                .map(drop)
                .ok_or(StorageError::NotFound)
        })
    }

    async fn set_mount(&self, key: &NamespaceKey, mount: BackendRef) -> Result<(), StorageError> {
        self.change(|document| {
            let slot = document
                .namespaces
                .get_mut(key)
                .ok_or(StorageError::NotFound)?;
            *slot = Some(mount);
            Ok(())
        })
    }

    async fn binding(&self, address: &Address) -> Result<Option<Locator>, StorageError> {
        Ok(self.load()?.bindings.get(address).cloned())
    }

    async fn has_bindings(&self, key: &NamespaceKey) -> Result<bool, StorageError> {
        Ok(self.load()?.bindings.keys().any(|address| {
            address.scope.tenant == key.tenant && address.scope.namespace == key.namespace
        }))
    }

    async fn insert_binding(&self, address: Address, locator: Locator) -> Result<(), StorageError> {
        self.change(|document| {
            if document.bindings.contains_key(&address) {
                return Err(StorageError::Conflict);
            }
            document.bindings.insert(address, locator);
            Ok(())
        })
    }

    async fn remove_binding(&self, address: &Address) -> Result<(), StorageError> {
        self.change(|document| {
            document
                .bindings
                .remove(address)
                .map(drop)
                .ok_or(StorageError::NotFound)
        })
    }
}
