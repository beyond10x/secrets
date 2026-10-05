//! `secrets.storage` against `secrets-core`'s storage port (`secrets_core::storage`), in this
//! process.
//!
//! # How an outcome is reached
//!
//! Every command's input goes through the port's own parsing — [`Address::parse`],
//! [`Address::parse_rename`], [`NamespaceKey::parse`], [`ScopeName::parse`] and
//! [`SecretValue::new`] — and the declared branch is read off what the port answered: which part
//! of the input it refused and why. The adapter never decides a branch; it only arranges the input
//! a forced branch is answered on.
//!
//! An input the port accepts is handed to the mounted backends. This module is where mount routing
//! and backends are mounted as their stories land; until one is, nothing is mounted, and the
//! command is answered `unsupported` rather than by a stand-in. Views are unsupported for the same
//! reason: no backend holds a secret and no configuration store holds a namespace.
//!
//! # The authorizer comes first
//!
//! The specification decides `denied` before any name refusal. No authorizer exists yet
//! (story:local-authorizer), so the port's refusals are answered only where the specification's
//! own guards admit the scope — tenant `default` and, for a command that names one, user
//! `default`. Every other scope is the authorizer's to decide and is unsupported.
//!
//! # Forced branches
//!
//! A forced `invalid-name` or `too-large` is made true on top of the input when the port accepts
//! the input as given: a name with one 65-byte segment (a namespace starting with `-` for
//! `AddNamespace`), or a value one byte past 1 MiB. If the port then still accepts it, the port
//! failed to refuse what the arrangement made true, and the command is reported as taking no
//! declared branch.
//!
//! # Errors
//!
//! A refusal is reported by the text the port's error displays, looked up among the wire codes
//! the specification declares. Text that is not exactly one of those codes is no declared error.
use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ess_conformance::target::{TargetError, ViewRow};
use ess_primitives::node::Node;
use secrets_core::storage::{
    Address, AddressError, BackendKind, NameError, NamespaceKey, Part, Scope, ScopeName,
    SecretName, SecretValue, StorageError,
};
use serde_json::Value;

use crate::target::{LibraryContext, LibraryDomain, Observed, unavailable};

pub const DOMAIN: LibraryDomain = LibraryDomain { command, view };

const ACTOR: &str = "secrets.storage.LocalUser";
/// The value bound, restated rather than imported so a change to the port's bound is something
/// this adapter notices instead of follows.
const VALUE_LIMIT: usize = 1024 * 1024;
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
/// Outcomes whose condition the port itself decides, so a forced one is arranged here.
const PORT_REFUSALS: [&str; 2] = ["invalid-name", "too-large"];

type R<T> = Result<T, TargetError>;

/// What the port accepted, ready for a mounted backend.
#[allow(
    dead_code,
    reason = "read by the mounted backends, none of which exists yet"
)]
enum Accepted {
    AddNamespace(NamespaceKey),
    RemoveNamespace(NamespaceKey),
    SetMount(NamespaceKey),
    Bind(Address),
    Unbind(Address),
    Write(Address, SecretValue),
    Read(Address),
    Delete(Address),
    Rename(Address, SecretName),
    ListMetadata(Scope),
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
    context: &mut LibraryContext,
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

fn answer(
    context: &mut LibraryContext,
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
    admitted_scope(command, &input)?;
    let forced = context.forced.clone();
    let mut parsed = parse(command, &input)?;
    if let (Ok(_), Some(outcome)) = (&parsed, forced.as_deref())
        && PORT_REFUSALS.contains(&outcome)
    {
        arrange(command, outcome, &mut input)?;
        parsed = parse(command, &input)?;
        if parsed.is_ok() {
            return Ok(Observed {
                outcome: None,
                error: None,
                events: Vec::new(),
            });
        }
    }
    match parsed {
        Ok(accepted) => mounted(context, command, accepted),
        Err(refusal) => Ok(Observed {
            outcome: branch(command, &refusal).map(ToOwned::to_owned),
            error: declared(refusal.error()),
            events: Vec::new(),
        }),
    }
}

/// The declared error whose wire code is exactly the text the port's error displays.
fn declared(error: StorageError) -> Option<&'static str> {
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

fn text<'a>(input: &'a Value, path: &[&str]) -> R<&'a str> {
    path.iter()
        .try_fold(input, |value, key| value.get(key))
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable("reading the command input", path.join(".")))
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

/// Refuses to answer for a scope the specification's guards do not admit: that answer is the
/// authorizer's (story:local-authorizer), which does not exist yet.
fn admitted_scope(command: &str, input: &Value) -> R<()> {
    let (tenant, user) = scope_fields(command);
    let admitted = text(input, tenant)? == ScopeName::DEFAULT
        && user.map_or(Ok(true), |user| {
            text(input, user).map(|user| user == ScopeName::DEFAULT)
        })?;
    if admitted {
        Ok(())
    } else {
        Err(TargetError::unsupported(
            format!("`{command}` in a scope other than tenant and user `default`"),
            "the local authorizer decides it first, and is story:local-authorizer",
        ))
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

/// A mount's label through the port. An absent optional mount is the default mount; a kind the
/// specification does not declare is not an input this adapter can send.
fn mount(input: &Value, required: bool) -> R<Result<(), Refusal>> {
    let mount = match input.get("mount") {
        None | Some(Value::Null) if !required => return Ok(Ok(())),
        None | Some(Value::Null) => {
            return Err(unavailable("reading the command input", "mount"));
        }
        Some(mount) => mount,
    };
    serde_json::from_value::<BackendKind>(Value::String(text(mount, &["kind"])?.to_owned()))
        .map_err(|error| unavailable("reading the mount kind", error))?;
    Ok(ScopeName::parse(text(mount, &["label"])?)
        .map(drop)
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
            Ok(key) => mount(input, command == "SetMount")?.map(|()| match command {
                "SetMount" => Accepted::SetMount(key),
                _ => Accepted::AddNamespace(key),
            }),
        },
        "RemoveNamespace" => namespace(input)?
            .map(Accepted::RemoveNamespace)
            .map_err(refused),
        "Bind" => address(input)?.map(Accepted::Bind).map_err(refused),
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

/// Makes the forced port refusal's condition true on the input.
fn arrange(command: &str, outcome: &str, input: &mut Value) -> R<()> {
    let (path, value): (&[&str], Value) = match (command, outcome) {
        ("Write", "too-large") => (
            &["value"],
            Value::String(STANDARD.encode(vec![0_u8; VALUE_LIMIT + 1])),
        ),
        ("AddNamespace", "invalid-name") => (
            &["namespace", "namespace"],
            Value::String("-namespace".to_owned()),
        ),
        (_, "invalid-name") => (&["address", "name"], Value::String("a".repeat(65))),
        _ => return Err(unavailable("arranging the forced outcome", outcome)),
    };
    let (last, parents) = path
        .split_last()
        .ok_or_else(|| unavailable("arranging the forced outcome", outcome))?;
    let slot = parents
        .iter()
        .try_fold(&mut *input, |value, key| value.get_mut(key))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| unavailable("arranging the forced outcome", path.join(".")))?;
    slot.insert((*last).to_owned(), value);
    Ok(())
}

/// Hands an accepted command to the backend its namespace is mounted on. Nothing is mounted until
/// mount routing (story:mount-federation) and a backend (story:keychain-backend,
/// story:remote-backend) land; until then the answer is unsupported, never a stand-in's.
fn mounted(_: &mut LibraryContext, command: &str, accepted: Accepted) -> R<Observed> {
    drop(accepted);
    Err(TargetError::unsupported(
        format!("`secrets.storage.{command}` past the port"),
        "no backend is mounted: mount routing is story:mount-federation, backends are \
         story:keychain-backend and story:remote-backend",
    ))
}

fn view(_: &mut LibraryContext, view: &str) -> Option<R<Vec<ViewRow>>> {
    matches!(
        view,
        "secrets.storage.SecretMetadata" | "secrets.storage.Namespaces"
    )
    .then(|| {
        Err(TargetError::unsupported(
            format!("reading `{view}`"),
            "no backend or namespace configuration is mounted (story:mount-federation)",
        ))
    })
}
