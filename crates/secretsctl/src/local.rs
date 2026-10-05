//! The local commands: the storage stack over the configuration file, and what each command
//! prints. Every result is a name, a scope, a backend or a version; no command reads a value back.
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use secrets_core::{
    authorize::{Authorized, Authorizer as _, LocalAuthorizer, Resource},
    storage::{
        Action, Address, AddressError, BackendKind, BackendRef, Locator, MAX_VALUE_BYTES,
        NameError, NamespaceKey, Part, Scope, ScopeName, SecretMetadata, SecretStorage as _,
        SecretValue, StorageError, Target, Written,
    },
};
use secrets_federation::{FederatedStorage, FileConfig, Namespace, NamespaceConfig};
use serde_json::{Value, json};

use crate::{EXIT_USAGE, PutArgs, backends};

const LOCAL: &str = ScopeName::DEFAULT;

/// Why a command did not succeed.
pub enum Failure {
    /// A storage refusal, with the name rule that was broken when it is `invalid-name`.
    Storage {
        error: StorageError,
        detail: Option<(&'static str, NameError)>,
    },
    /// The command line or the input was refused before anything was stored.
    Refused(String),
}

impl From<StorageError> for Failure {
    fn from(error: StorageError) -> Self {
        Self::Storage {
            error,
            detail: None,
        }
    }
}

impl From<AddressError> for Failure {
    fn from(error: AddressError) -> Self {
        let part = match error.part {
            Part::Tenant => "tenant",
            Part::Namespace => "namespace",
            Part::User => "user",
            Part::Name => "name",
            Part::NewName => "new-name",
        };
        Self::Storage {
            error: StorageError::InvalidName,
            detail: Some((part, error.reason)),
        }
    }
}

/// What a successful command prints: JSON under `--json`, text otherwise.
pub struct Report {
    json: Value,
    text: String,
}

type Outcome = Result<Report, Failure>;

struct Stack {
    storage: Authorized<FederatedStorage>,
    notes: Vec<String>,
    finish: Option<Box<dyn FnOnce()>>,
}

/// The local commands over one configuration file.
pub struct Local {
    json: bool,
    stack: Option<Stack>,
    /// What the user is told about a configuration that could not be used, when it could not.
    trouble: Vec<String>,
}

/// `$XDG_CONFIG_HOME/b10x-secrets/config.toml`, or `~/.config/...` when the variable is unset,
/// empty or relative (the XDG base directory rule).
fn config_path() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(directory) if Path::new(&directory).is_absolute() => PathBuf::from(directory),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("b10x-secrets").join("config.toml"))
}

fn scope_text(scope: &Scope) -> String {
    format!("{}/{}/{}", scope.tenant, scope.namespace, scope.user)
}

fn backend_text(backend: &BackendRef) -> String {
    let kind = match backend.kind {
        BackendKind::Keychain => "keychain",
        BackendKind::Onepassword => "onepassword",
        BackendKind::Remote => "remote",
    };
    format!("{kind}/{}", backend.label)
}

fn version_text(version: Option<&secrets_core::storage::Version>) -> &str {
    version.map_or("-", |version| version.as_str())
}

/// A mount as typed: `kind/label`, or a bare kind for label `default`.
fn parse_mount(text: &str) -> Result<BackendRef, Failure> {
    let (kind, label) = text.split_once('/').unwrap_or((text, LOCAL));
    let kind = match kind {
        "keychain" => BackendKind::Keychain,
        "remote" => BackendKind::Remote,
        "onepassword" => BackendKind::Onepassword,
        _ => {
            return Err(Failure::Refused(
                "a mount is `kind/label`, and kind is `keychain` or `remote`".to_owned(),
            ));
        }
    };
    let label = ScopeName::parse(label).map_err(|reason| Failure::Storage {
        error: StorageError::InvalidName,
        detail: Some(("label", reason)),
    })?;
    Ok(BackendRef { kind, label })
}

fn address(namespace: &str, name: &str) -> Result<Address, Failure> {
    Ok(Address::parse(LOCAL, namespace, LOCAL, name)?)
}

fn namespace_key(namespace: &str) -> Result<NamespaceKey, Failure> {
    Ok(NamespaceKey::parse(LOCAL, namespace)?)
}

fn local_scope(namespace: &str) -> Result<Scope, Failure> {
    let namespace = ScopeName::parse(namespace).map_err(|reason| Failure::Storage {
        error: StorageError::InvalidName,
        detail: Some(("namespace", reason)),
    })?;
    Ok(Scope {
        namespace,
        ..Scope::local()
    })
}

fn row(metadata: &SecretMetadata, backend: &BackendRef) -> (Value, String) {
    (
        json!({
            "name": metadata.address.name,
            "scope": metadata.address.scope,
            "backend": backend,
            "version": metadata.version,
        }),
        format!(
            "{}\t{}\t{}\t{}",
            metadata.address.name,
            scope_text(&metadata.address.scope),
            backend_text(backend),
            version_text(metadata.version.as_ref()),
        ),
    )
}

/// Tab-separated lines as aligned columns.
fn columns(lines: &[String]) -> String {
    let cells: Vec<Vec<&str>> = lines
        .iter()
        .map(|line| line.split('\t').collect())
        .collect();
    let width = cells.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..width)
        .map(|column| {
            cells
                .iter()
                .filter_map(|row| row.get(column).map(|cell| cell.len()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    cells
        .iter()
        .map(|row| {
            let mut line = String::new();
            for (column, cell) in row.iter().enumerate() {
                if column + 1 == row.len() {
                    line.push_str(cell);
                } else {
                    line.push_str(&format!("{cell:<width$}  ", width = widths[column]));
                }
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// What a refusal means for the command that got it.
fn meaning(command: &str, error: StorageError) -> &'static str {
    match (command, error) {
        (_, StorageError::Denied) => "the local authorizer refused the scope",
        (_, StorageError::Unavailable) => "a backend or the configuration file could not be used",
        (_, StorageError::InvalidName) => "a name is not valid",
        (_, StorageError::TooLarge) => {
            "the value is larger than the backend accepts (1 MiB at most)"
        }
        (_, StorageError::Unsupported) => "the namespace's backend cannot do this",
        ("namespace add", StorageError::Conflict) => "the namespace exists",
        ("namespace add", StorageError::NotFound) => {
            "the mount names a backend that is not configured"
        }
        ("namespace remove", StorageError::Conflict) => {
            "namespace `default` is never removed, and a namespace holding secrets or bindings is not"
        }
        ("namespace remove", StorageError::NotFound) => "the namespace does not exist",
        ("mount set", StorageError::NotFound) => {
            "the namespace does not exist, or the mount names a backend that is not configured"
        }
        ("mount set", StorageError::Conflict) => "the namespace holds secrets on its current mount",
        ("bind", StorageError::NotFound) => "the namespace does not exist",
        ("bind", StorageError::Conflict) => "the name is already bound; unbind it first",
        ("unbind", StorageError::NotFound) => "the name has no binding",
        ("rename", StorageError::Conflict) => "the new name is taken, or a name is bound",
        ("put" | "list", StorageError::NotFound) => "the namespace does not exist",
        (_, StorageError::NotFound) => {
            "nothing is stored under the name, or the namespace does not exist"
        }
        (_, StorageError::Conflict) => "the command collides with an existing record",
    }
}

fn exit_code(error: StorageError) -> u8 {
    let index = StorageError::ALL
        .iter()
        .position(|candidate| *candidate == error)
        .unwrap_or(0);
    3 + u8::try_from(index).unwrap_or(0)
}

impl Local {
    /// The stack over the configuration file and every backend it configures.
    pub fn open(json: bool) -> Self {
        let Some(path) = config_path() else {
            return Self {
                json,
                stack: None,
                trouble: vec![
                    "config: no configuration directory; set XDG_CONFIG_HOME or HOME".to_owned(),
                ],
            };
        };
        let backends = backends::load(&path);
        let config: Arc<dyn NamespaceConfig> = Arc::new(FileConfig::new(path));
        let mut routing = FederatedStorage::new(config);
        let mut notes = backends.notes;
        for (backend, storage) in backends.mounted {
            routing = match routing.with_backend(backend, storage) {
                Ok(routing) => routing,
                Err(_) => {
                    notes.push("config: a backend is configured twice".to_owned());
                    return Self {
                        json,
                        stack: None,
                        trouble: notes,
                    };
                }
            };
        }
        Self {
            json,
            stack: Some(Stack {
                storage: Authorized::local(routing),
                notes,
                finish: backends.finish,
            }),
            trouble: Vec::new(),
        }
    }

    fn stack(&self) -> Result<&Stack, Failure> {
        self.stack.as_ref().ok_or(Failure::Storage {
            error: StorageError::Unavailable,
            detail: None,
        })
    }

    fn routing(&self) -> Result<&FederatedStorage, Failure> {
        Ok(self.stack()?.storage.inner())
    }

    /// Namespace and binding commands are not port methods, so the authorizer is asked here.
    fn manage(&self, resource: Resource<'_>) -> Result<(), Failure> {
        Ok(LocalAuthorizer.authorize(resource, Action::ManageNamespace)?)
    }

    async fn mount_of(&self, scope: &Scope) -> Result<BackendRef, Failure> {
        let key = NamespaceKey {
            tenant: scope.tenant.clone(),
            namespace: scope.namespace.clone(),
        };
        Ok(self
            .routing()?
            .config()
            .namespace(&key)
            .await?
            .ok_or(StorageError::NotFound)?
            .effective_mount())
    }

    pub async fn put(&self, args: PutArgs) -> Outcome {
        if args.value.is_some() || args.value_flag.is_some() {
            return Err(Failure::Refused(
                "put never takes a value on the command line; pipe it on stdin, type it at the \
                 prompt, or pass --file with a mode-0600 file"
                    .to_owned(),
            ));
        }
        let address = address(&args.namespace.namespace, &args.name)?;
        let stack = self.stack()?;
        let mut bytes = crate::value::read(
            args.file.as_deref(),
            args.raw,
            &format!("Value for {}: ", address.name),
            MAX_VALUE_BYTES,
        )
        .map_err(|refusal| Failure::Refused(refusal.to_string()))?;
        let value = SecretValue::new(std::mem::take(&mut *bytes))?;
        let written = stack
            .storage
            .write(&Target::unbound(address.clone()), value)
            .await?;
        let (outcome, version) = match written {
            Written::Created(version) => ("created", version),
            Written::Replaced(version) => ("replaced", version),
        };
        let backend = self.mount_of(&address.scope).await?;
        Ok(Report {
            json: json!({
                "outcome": outcome,
                "name": address.name,
                "scope": address.scope,
                "backend": backend,
                "version": version,
            }),
            text: format!(
                "{outcome} {} (scope {}, backend {}, version {})",
                address.name,
                scope_text(&address.scope),
                backend_text(&backend),
                version_text(version.as_ref()),
            ),
        })
    }

    pub async fn describe(&self, namespace: &str, name: &str) -> Outcome {
        let address = address(namespace, name)?;
        let rows = self.stack()?.storage.list(&address.scope).await?;
        let metadata = rows
            .iter()
            .find(|row| row.address == address)
            .ok_or(StorageError::NotFound)?;
        let backend = self.mount_of(&address.scope).await?;
        let (json, _) = row(metadata, &backend);
        Ok(Report {
            json,
            text: format!(
                "name     {}\nscope    {}\nbackend  {}\nversion  {}",
                metadata.address.name,
                scope_text(&metadata.address.scope),
                backend_text(&backend),
                version_text(metadata.version.as_ref()),
            ),
        })
    }

    pub async fn list(&self, namespace: &str, all: bool) -> Outcome {
        let scopes = if all {
            self.routing()?
                .namespaces()
                .await?
                .into_iter()
                .filter(|namespace| namespace.key.tenant.as_str() == LOCAL)
                .map(|namespace| Scope {
                    namespace: namespace.key.namespace,
                    ..Scope::local()
                })
                .collect()
        } else {
            vec![local_scope(namespace)?]
        };
        let stack = self.stack()?;
        let mut json = Vec::new();
        let mut lines = vec!["NAME\tSCOPE\tBACKEND\tVERSION".to_owned()];
        for scope in scopes {
            let rows = stack.storage.list(&scope).await?;
            let backend = self.mount_of(&scope).await?;
            for metadata in &rows {
                let (value, line) = row(metadata, &backend);
                json.push(value);
                lines.push(line);
            }
        }
        Ok(Report {
            json: Value::Array(json),
            text: columns(&lines),
        })
    }

    pub async fn delete(&self, namespace: &str, name: &str) -> Outcome {
        let address = address(namespace, name)?;
        self.stack()?
            .storage
            .delete(&Target::unbound(address.clone()))
            .await?;
        Ok(Report {
            json: json!({"outcome": "deleted", "name": address.name, "scope": address.scope}),
            text: format!(
                "deleted {} (scope {})",
                address.name,
                scope_text(&address.scope)
            ),
        })
    }

    pub async fn rename(&self, namespace: &str, name: &str, new_name: &str) -> Outcome {
        let (address, new_name) = Address::parse_rename(LOCAL, namespace, LOCAL, name, new_name)?;
        self.stack()?
            .storage
            .rename(&Target::unbound(address.clone()), &new_name)
            .await?;
        Ok(Report {
            json: json!({
                "outcome": "renamed",
                "name": address.name,
                "new_name": new_name,
                "scope": address.scope,
            }),
            text: format!(
                "renamed {} to {new_name} (scope {})",
                address.name,
                scope_text(&address.scope)
            ),
        })
    }

    pub async fn namespace_add(&self, name: &str, mount: Option<&str>) -> Outcome {
        let key = namespace_key(name)?;
        let mount = mount.map(parse_mount).transpose()?;
        self.manage(Resource::namespace(&key))?;
        self.routing()?
            .add_namespace(key.clone(), mount.clone())
            .await?;
        let backend = mount.clone().unwrap_or_else(BackendRef::default_mount);
        Ok(Report {
            json: json!({"outcome": "added", "namespace": key, "mount": mount, "backend": backend}),
            text: format!(
                "added namespace {} on {}",
                key.namespace,
                backend_text(&backend)
            ),
        })
    }

    pub async fn namespace_list(&self) -> Outcome {
        self.manage(Resource::Namespace { tenant: LOCAL })?;
        let namespaces = self.routing()?.namespaces().await?;
        let mut lines = vec!["NAMESPACE\tTENANT\tBACKEND".to_owned()];
        let json = namespaces
            .iter()
            .map(|Namespace { key, mount }| {
                let backend = mount.clone().unwrap_or_else(BackendRef::default_mount);
                lines.push(format!(
                    "{}\t{}\t{}",
                    key.namespace,
                    key.tenant,
                    backend_text(&backend)
                ));
                json!({"namespace": key, "mount": mount, "backend": backend})
            })
            .collect();
        Ok(Report {
            json: Value::Array(json),
            text: columns(&lines),
        })
    }

    pub async fn namespace_remove(&self, name: &str) -> Outcome {
        let key = namespace_key(name)?;
        self.manage(Resource::namespace(&key))?;
        self.routing()?.remove_namespace(&key).await?;
        Ok(Report {
            json: json!({"outcome": "removed", "namespace": key}),
            text: format!("removed namespace {}", key.namespace),
        })
    }

    pub async fn mount_set(&self, namespace: &str, mount: &str) -> Outcome {
        let key = namespace_key(namespace)?;
        let mount = parse_mount(mount)?;
        self.manage(Resource::namespace(&key))?;
        self.routing()?.set_mount(&key, mount.clone()).await?;
        Ok(Report {
            json: json!({"outcome": "set", "namespace": key, "mount": mount}),
            text: format!(
                "mounted namespace {} on {}",
                key.namespace,
                backend_text(&mount)
            ),
        })
    }

    pub async fn bind(&self, namespace: &str, name: &str, locator: &str) -> Outcome {
        let address = address(namespace, name)?;
        self.manage(Resource::address(&address))?;
        self.routing()?
            .bind(&address, Locator::new(locator))
            .await?;
        Ok(Report {
            json: json!({"outcome": "bound", "name": address.name, "scope": address.scope}),
            text: format!(
                "bound {} (scope {})",
                address.name,
                scope_text(&address.scope)
            ),
        })
    }

    pub async fn unbind(&self, namespace: &str, name: &str) -> Outcome {
        let address = address(namespace, name)?;
        self.manage(Resource::address(&address))?;
        self.routing()?.unbind(&address).await?;
        Ok(Report {
            json: json!({"outcome": "unbound", "name": address.name, "scope": address.scope}),
            text: format!(
                "unbound {} (scope {})",
                address.name,
                scope_text(&address.scope)
            ),
        })
    }

    /// Prints the result, lets a test keychain save itself, and answers the exit code.
    pub fn finish(self, command: &str, outcome: Outcome) -> ExitCode {
        let Self {
            json,
            stack,
            trouble,
        } = self;
        let (notes, finish) = match stack {
            Some(stack) => (stack.notes, stack.finish),
            None => (trouble, None),
        };
        if let Some(finish) = finish {
            finish();
        }
        match outcome {
            Ok(report) => {
                if json {
                    println!("{}", report.json);
                } else {
                    println!("{}", report.text);
                }
                ExitCode::SUCCESS
            }
            Err(Failure::Refused(reason)) => {
                if json {
                    eprintln!("{}", json!({"error": "refused", "message": reason}));
                } else {
                    eprintln!("secretsctl: refused: {reason}");
                }
                ExitCode::from(EXIT_USAGE)
            }
            Err(Failure::Storage { error, detail }) => {
                let notes: &[String] = if error == StorageError::Unavailable {
                    &notes
                } else {
                    &[]
                };
                let message = meaning(command, error);
                if json {
                    eprintln!(
                        "{}",
                        json!({
                            "error": error.code(),
                            "part": detail.map(|(part, _)| part),
                            "reason": detail.map(|(_, reason)| reason.code()),
                            "message": message,
                            "notes": notes,
                        })
                    );
                } else {
                    match detail {
                        Some((part, reason)) => {
                            eprintln!("secretsctl: {error} ({part}: {reason}): {message}");
                        }
                        None => eprintln!("secretsctl: {error}: {message}"),
                    }
                    for note in notes {
                        eprintln!("secretsctl: note: {note}");
                    }
                }
                ExitCode::from(exit_code(error))
            }
        }
    }
}
