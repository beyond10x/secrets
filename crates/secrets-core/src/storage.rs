//! The `secrets.storage` port: named, scoped secrets behind one backend trait, as
//! `spec/domains/storage.yaml` declares them.
//!
//! This module holds the model and the port only. It routes nothing, authorizes nothing and talks
//! to no backend: mount routing, the local authorizer and each backend are their own stories, and
//! each builds on the types here. The service-level [`crate::SecretStore`] is unrelated and
//! unchanged.
//!
//! # What the port decides on its own
//!
//! Two refusals need no backend, so the port answers them before any backend is called:
//!
//! * a name over its bound or outside its grammar is [`StorageError::InvalidName`]
//!   ([`SecretName`], [`ScopeName`], [`Address::parse`]);
//! * a value above [`MAX_VALUE_BYTES`] is [`StorageError::TooLarge`] ([`SecretValue::new`]).
//!
//! # Secret bytes
//!
//! A value exists only as a [`SecretValue`], which has no `Debug`, `Display` or `Serialize`, so it
//! cannot reach a log line, an error or a serialized record by accident. Every other type in this
//! module is metadata.
use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(feature = "testing")]
pub mod testing;

/// The bound on a whole [`SecretName`], in bytes (`name-too-long` in the specification).
pub const MAX_NAME_BYTES: usize = 128;
/// The bound on one `/`-separated segment of a [`SecretName`], and on a whole [`ScopeName`].
pub const MAX_SEGMENT_BYTES: usize = 64;
/// The bound on a secret value, in bytes: 1 MiB.
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;

/// Every refusal of the port: a closed code and nothing else.
///
/// No variant carries a field, so no refusal can repeat a name, a value or a backend's own text.
/// `Display` is exactly the specification's wire code ([`StorageError::code`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StorageError {
    /// Nothing is addressed by the name, or the name resolves to no mount or binding.
    NotFound,
    /// The authorizer refused the action on the resource.
    Denied,
    /// The resolved backend lacks the capability the command needs.
    Unsupported,
    /// The resolved backend, or the namespace configuration store, could not be reached.
    Unavailable,
    /// A name is not a valid [`SecretName`] or [`ScopeName`].
    InvalidName,
    /// The secret value exceeds [`MAX_VALUE_BYTES`].
    TooLarge,
    /// The command collides with an existing record.
    Conflict,
}

impl StorageError {
    /// Every code, in the order the specification declares them.
    pub const ALL: [Self; 7] = [
        Self::NotFound,
        Self::Denied,
        Self::Unsupported,
        Self::Unavailable,
        Self::InvalidName,
        Self::TooLarge,
        Self::Conflict,
    ];

    /// The wire code the specification names (`naming: {wire: ...}`).
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::Denied => "denied",
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
            Self::InvalidName => "invalid-name",
            Self::TooLarge => "too-large",
            Self::Conflict => "conflict",
        }
    }

    /// The code a wire string names, if it names one.
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|error| error.code() == code)
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for StorageError {}

/// Why a name was refused. Every reason is [`StorageError::InvalidName`] to a caller of the port;
/// the reason exists so a caller can tell the length bound (a guard in the specification) from the
/// grammar (an external refusal). None carries any part of the name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NameError {
    /// The whole name is longer than its bound: [`MAX_NAME_BYTES`] for a [`SecretName`],
    /// [`MAX_SEGMENT_BYTES`] for a [`ScopeName`].
    TooLong,
    /// One segment of a [`SecretName`] is longer than [`MAX_SEGMENT_BYTES`].
    SegmentTooLong,
    /// The name is empty, or a [`SecretName`] has an empty segment.
    EmptySegment,
    /// A segment starts with a character outside `[a-z0-9]`.
    BadStart,
    /// A character is outside the name's alphabet.
    BadCharacter,
}

impl NameError {
    /// The closed code of this reason.
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLong => "too-long",
            Self::SegmentTooLong => "segment-too-long",
            Self::EmptySegment => "empty-segment",
            Self::BadStart => "bad-start",
            Self::BadCharacter => "bad-character",
        }
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for NameError {}

impl From<NameError> for StorageError {
    fn from(_: NameError) -> Self {
        Self::InvalidName
    }
}

/// One segment's grammar: `[a-z0-9][a-z0-9._-]*`, at most [`MAX_SEGMENT_BYTES`] bytes. The length
/// of an over-long segment is reported before its characters.
fn segment(segment: &str) -> Result<(), NameError> {
    let mut bytes = segment.bytes();
    let Some(first) = bytes.next() else {
        return Err(NameError::EmptySegment);
    };
    if segment.len() > MAX_SEGMENT_BYTES {
        return Err(NameError::SegmentTooLong);
    }
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(if first == b'.' || first == b'_' || first == b'-' {
            NameError::BadStart
        } else {
            NameError::BadCharacter
        });
    }
    if bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        Ok(())
    } else {
        Err(NameError::BadCharacter)
    }
}

/// A secret's name: `/`-separated segments, each `[a-z0-9][a-z0-9._-]*` and at most
/// [`MAX_SEGMENT_BYTES`] bytes, at most [`MAX_NAME_BYTES`] bytes in total. `openai`,
/// `openai-work` and `team/openai` are names.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretName(String);

impl SecretName {
    /// Checks only the total length, the bound the specification decides by a guard before any
    /// other refusal of a name.
    ///
    /// # Errors
    /// [`NameError::TooLong`] above [`MAX_NAME_BYTES`].
    pub fn check_length(name: &str) -> Result<(), NameError> {
        if name.len() > MAX_NAME_BYTES {
            Err(NameError::TooLong)
        } else {
            Ok(())
        }
    }

    /// # Errors
    /// The first rule the name breaks: the total length, then each segment in order.
    pub fn parse(name: &str) -> Result<Self, NameError> {
        Self::check_length(name)?;
        name.split('/').try_for_each(segment)?;
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretName {
    type Error = NameError;
    fn try_from(name: String) -> Result<Self, NameError> {
        Self::parse(&name)
    }
}

impl From<SecretName> for String {
    fn from(name: SecretName) -> Self {
        name.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A tenant, namespace, user or backend label: one segment of the [`SecretName`] grammar, so at
/// most [`MAX_SEGMENT_BYTES`] bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ScopeName(String);

impl ScopeName {
    /// The tenant, namespace and user of local mode.
    pub const DEFAULT: &'static str = "default";

    /// # Errors
    /// [`NameError::TooLong`] above [`MAX_SEGMENT_BYTES`] (checked first), then the segment
    /// grammar. A `/` is a [`NameError::BadCharacter`].
    pub fn parse(name: &str) -> Result<Self, NameError> {
        if name.len() > MAX_SEGMENT_BYTES {
            return Err(NameError::TooLong);
        }
        segment(name)?;
        Ok(Self(name.to_owned()))
    }

    /// `default`.
    pub fn default_name() -> Self {
        Self(Self::DEFAULT.to_owned())
    }

    pub fn is_default(&self) -> bool {
        self.0 == Self::DEFAULT
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ScopeName {
    type Error = NameError;
    fn try_from(name: String) -> Result<Self, NameError> {
        Self::parse(&name)
    }
}

impl From<ScopeName> for String {
    fn from(name: ScopeName) -> Self {
        name.0
    }
}

impl fmt::Display for ScopeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The scope every secret belongs to, exactly one.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Scope {
    pub tenant: ScopeName,
    pub namespace: ScopeName,
    pub user: ScopeName,
}

impl Scope {
    /// Local mode: tenant, namespace and user `default`.
    pub fn local() -> Self {
        Self {
            tenant: ScopeName::default_name(),
            namespace: ScopeName::default_name(),
            user: ScopeName::default_name(),
        }
    }
}

/// A namespace, unique per tenant.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NamespaceKey {
    pub tenant: ScopeName,
    pub namespace: ScopeName,
}

impl NamespaceKey {
    /// # Errors
    /// The namespace's length first (the `name-too-long` guard of `AddNamespace`), then the
    /// tenant's and the namespace's grammar.
    pub fn parse(tenant: &str, namespace: &str) -> Result<Self, AddressError> {
        if namespace.len() > MAX_SEGMENT_BYTES {
            return Err(AddressError::new(Part::Namespace, NameError::TooLong));
        }
        Ok(Self {
            tenant: ScopeName::parse(tenant).map_err(|e| AddressError::new(Part::Tenant, e))?,
            namespace: ScopeName::parse(namespace)
                .map_err(|e| AddressError::new(Part::Namespace, e))?,
        })
    }
}

/// Which part of an address a refusal concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Part {
    Tenant,
    Namespace,
    User,
    Name,
    /// The name a rename moves to.
    NewName,
}

/// A refused address: which part, and why. To a caller of the port it is
/// [`StorageError::InvalidName`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddressError {
    pub part: Part,
    pub reason: NameError,
}

impl AddressError {
    pub const fn new(part: Part, reason: NameError) -> Self {
        Self { part, reason }
    }
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, f)
    }
}

impl std::error::Error for AddressError {}

impl From<AddressError> for StorageError {
    fn from(_: AddressError) -> Self {
        Self::InvalidName
    }
}

/// A secret's address: its scope and its name. A secret is unique per address.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address {
    pub scope: Scope,
    pub name: SecretName,
}

impl Address {
    /// # Errors
    /// The name's total length first — the specification's `name-too-long` guard, which holds
    /// whatever else is wrong — then the tenant, namespace, user and name grammar, in that order.
    pub fn parse(
        tenant: &str,
        namespace: &str,
        user: &str,
        name: &str,
    ) -> Result<Self, AddressError> {
        SecretName::check_length(name).map_err(|e| AddressError::new(Part::Name, e))?;
        Self::parse_checked(tenant, namespace, user, name)
    }

    /// A rename's address and new name. Both total lengths are decided before either name's
    /// grammar: the specification's `name-too-long` and `new-name-too-long` are guards and every
    /// other name refusal is external.
    ///
    /// # Errors
    /// The first rule broken, as [`Address::parse`] orders them, with the new name's length after
    /// the address name's length and its grammar last.
    pub fn parse_rename(
        tenant: &str,
        namespace: &str,
        user: &str,
        name: &str,
        new_name: &str,
    ) -> Result<(Self, SecretName), AddressError> {
        SecretName::check_length(name).map_err(|e| AddressError::new(Part::Name, e))?;
        SecretName::check_length(new_name).map_err(|e| AddressError::new(Part::NewName, e))?;
        let address = Self::parse_checked(tenant, namespace, user, name)?;
        let new_name =
            SecretName::parse(new_name).map_err(|e| AddressError::new(Part::NewName, e))?;
        Ok((address, new_name))
    }

    fn parse_checked(
        tenant: &str,
        namespace: &str,
        user: &str,
        name: &str,
    ) -> Result<Self, AddressError> {
        let scope = Scope {
            tenant: ScopeName::parse(tenant).map_err(|e| AddressError::new(Part::Tenant, e))?,
            namespace: ScopeName::parse(namespace)
                .map_err(|e| AddressError::new(Part::Namespace, e))?,
            user: ScopeName::parse(user).map_err(|e| AddressError::new(Part::User, e))?,
        };
        let name = SecretName::parse(name).map_err(|e| AddressError::new(Part::Name, e))?;
        Ok(Self { scope, name })
    }
}

/// The kinds of backend a namespace can be mounted on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// The OS keychain, the local default.
    Keychain,
    /// 1Password, read-only.
    Onepassword,
    /// The custody service.
    Remote,
}

impl BackendKind {
    /// What a backend of this kind can do, as the specification's `Backend` invariants state it.
    pub const fn capabilities(self) -> &'static [Capability] {
        match self {
            Self::Onepassword => &[Capability::Read],
            Self::Keychain | Self::Remote => &Capability::ALL,
        }
    }
}

/// A backend instance: its kind and a single-segment label.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BackendRef {
    pub kind: BackendKind,
    pub label: ScopeName,
}

impl BackendRef {
    /// The default mount: kind keychain, label `default`.
    pub fn default_mount() -> Self {
        Self {
            kind: BackendKind::Keychain,
            label: ScopeName::default_name(),
        }
    }
}

/// An operation a backend can offer. One it lacks is refused as [`StorageError::Unsupported`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Read,
    Write,
    Delete,
    List,
}

impl Capability {
    pub const ALL: [Self; 4] = [Self::Read, Self::Write, Self::Delete, Self::List];
}

/// What the authorizer decides for every command, before any backend call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Read,
    Write,
    Delete,
    List,
    ManageNamespace,
}

impl Action {
    pub const ALL: [Self; 5] = [
        Self::Read,
        Self::Write,
        Self::Delete,
        Self::List,
        Self::ManageNamespace,
    ];
}

/// Where a binding points a name in its namespace's backend, such as an `op://` item. Not a
/// secret, and never listed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Locator(String);

impl Locator {
    pub fn new(locator: impl Into<String>) -> Self {
        Self(locator.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An opaque, backend-assigned version. Every successful write changes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Version(String);

impl Version {
    pub fn new(version: impl Into<String>) -> Self {
        Self(version.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Secret bytes, at most [`MAX_VALUE_BYTES`], zeroized on drop.
///
/// It has no `Debug`, `Display` or `Serialize`, so the value cannot be formatted or serialized at
/// all; [`SecretValue::expose`] is the one way to its bytes. Each line below is refused by the
/// compiler:
///
/// ```compile_fail
/// let value = secrets_core::storage::SecretValue::new(b"example".to_vec()).unwrap();
/// let _ = format!("{value:?}"); // no Debug
/// ```
///
/// ```compile_fail
/// let value = secrets_core::storage::SecretValue::new(b"example".to_vec()).unwrap();
/// let _ = format!("{value}"); // no Display
/// ```
///
/// ```compile_fail
/// fn serializable<T: serde::Serialize>(_: &T) {}
/// let value = secrets_core::storage::SecretValue::new(b"example".to_vec()).unwrap();
/// serializable(&value); // no Serialize
/// ```
///
/// The same three lines compile for a metadata type, so the refusals above are about
/// `SecretValue` and nothing else:
///
/// ```
/// fn serializable<T: serde::Serialize>(_: &T) {}
/// let name = secrets_core::storage::SecretName::parse("openai").unwrap();
/// let _ = format!("{name:?}");
/// let _ = format!("{name}");
/// serializable(&name);
/// ```
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// # Errors
    /// [`StorageError::TooLarge`] above [`MAX_VALUE_BYTES`]. Empty and binary values are values.
    pub fn new(value: Vec<u8>) -> Result<Self, StorageError> {
        let value = Zeroizing::new(value);
        if value.len() > MAX_VALUE_BYTES {
            return Err(StorageError::TooLarge);
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What a backend is asked about: the address, and the locator a binding gives the name, if any.
///
/// A caller above mount routing passes no locator; routing fills it from the namespace's binding
/// for a backend that requires one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub address: Address,
    pub locator: Option<Locator>,
}

impl Target {
    /// An address with no binding.
    pub fn unbound(address: Address) -> Self {
        Self {
            address,
            locator: None,
        }
    }
}

/// A value read back, with the version the backend holds it under.
pub struct Revealed {
    pub value: SecretValue,
    pub version: Option<Version>,
}

/// What a successful write did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Written {
    /// No secret was stored at the address.
    Created(Option<Version>),
    /// A secret was stored at the address and now holds the new value.
    Replaced(Option<Version>),
}

/// One listed secret: name, scope and version, never a value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub address: Address,
    pub version: Option<Version>,
}

/// The storage port every backend implements, and mount routing implements over them.
///
/// Every refusal is a [`StorageError`] code. An operation a backend lacks answers
/// [`StorageError::Unsupported`], which is what the provided methods do; a backend overrides the
/// ones its [`SecretStorage::capabilities`] lists. A backend fault is
/// [`StorageError::Unavailable`] and carries none of the backend's own text.
#[async_trait]
pub trait SecretStorage: Send + Sync {
    /// What this backend can do.
    fn capabilities(&self) -> &[Capability];

    /// Whether a name must be bound to a locator before it can be read.
    fn requires_binding(&self) -> bool {
        false
    }

    /// The value at the target, and its version.
    async fn read(&self, target: &Target) -> Result<Revealed, StorageError>;

    /// Stores the value at the target.
    async fn write(&self, target: &Target, value: SecretValue) -> Result<Written, StorageError> {
        let _ = (target, value);
        Err(StorageError::Unsupported)
    }

    /// Removes the secret at the target.
    async fn delete(&self, target: &Target) -> Result<(), StorageError> {
        let _ = target;
        Err(StorageError::Unsupported)
    }

    /// Moves the value at the target to `new_name` in the same scope.
    async fn rename(&self, target: &Target, new_name: &SecretName) -> Result<(), StorageError> {
        let _ = (target, new_name);
        Err(StorageError::Unsupported)
    }

    /// The metadata of every secret in the scope.
    async fn list(&self, scope: &Scope) -> Result<Vec<SecretMetadata>, StorageError> {
        let _ = scope;
        Err(StorageError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repeat(byte: char, count: usize) -> String {
        std::iter::repeat_n(byte, count).collect()
    }

    #[test]
    fn a_name_of_128_bytes_is_a_name_and_129_is_too_long() {
        let at_bound = format!("{}/{}", repeat('a', 64), repeat('b', 63));
        assert_eq!(at_bound.len(), MAX_NAME_BYTES);
        assert!(SecretName::parse(&at_bound).is_ok());
        let over = format!("{}/{}", repeat('a', 64), repeat('b', 64));
        assert_eq!(SecretName::parse(&over), Err(NameError::TooLong));
    }

    #[test]
    fn a_segment_of_64_bytes_is_a_segment_and_65_is_not() {
        assert!(SecretName::parse(&repeat('a', 64)).is_ok());
        assert_eq!(
            SecretName::parse(&repeat('a', 65)),
            Err(NameError::SegmentTooLong)
        );
        assert_eq!(
            SecretName::parse(&format!("team/{}", repeat('a', 65))),
            Err(NameError::SegmentTooLong)
        );
    }

    #[test]
    fn the_total_bound_is_decided_before_the_segment_bound() {
        assert_eq!(
            SecretName::parse(&repeat('a', 129)),
            Err(NameError::TooLong)
        );
    }

    #[test]
    fn the_segment_grammar_is_enforced() {
        for name in ["openai", "openai-work", "team/openai", "a.b_c-d/0"] {
            assert!(SecretName::parse(name).is_ok(), "{name}");
        }
        for (name, reason) in [
            ("", NameError::EmptySegment),
            ("team/", NameError::EmptySegment),
            ("/openai", NameError::EmptySegment),
            ("a//b", NameError::EmptySegment),
            ("-openai", NameError::BadStart),
            ("team/.openai", NameError::BadStart),
            ("OpenAI", NameError::BadCharacter),
            ("open ai", NameError::BadCharacter),
            ("öpen", NameError::BadCharacter),
        ] {
            assert_eq!(SecretName::parse(name), Err(reason), "{name}");
        }
    }

    #[test]
    fn a_scope_name_is_one_segment_of_at_most_64_bytes() {
        assert!(ScopeName::parse(&repeat('a', 64)).is_ok());
        assert_eq!(ScopeName::parse(&repeat('a', 65)), Err(NameError::TooLong));
        assert_eq!(ScopeName::parse("team/a"), Err(NameError::BadCharacter));
        assert_eq!(ScopeName::parse("_a"), Err(NameError::BadStart));
        assert!(ScopeName::parse("default").is_ok_and(|name| name.is_default()));
    }

    #[test]
    fn an_address_reports_the_name_length_before_any_scope_rule() {
        let long = repeat('a', 129);
        assert_eq!(
            Address::parse("default", "-bad", "default", &long),
            Err(AddressError::new(Part::Name, NameError::TooLong))
        );
        assert_eq!(
            Address::parse("default", "-bad", "default", "openai"),
            Err(AddressError::new(Part::Namespace, NameError::BadStart))
        );
        assert_eq!(
            Address::parse("default", "default", "default", &repeat('a', 65)),
            Err(AddressError::new(Part::Name, NameError::SegmentTooLong))
        );
    }

    #[test]
    fn a_rename_decides_both_lengths_before_either_grammar() {
        let structurally_bad = repeat('a', 128);
        assert_eq!(
            Address::parse_rename(
                "default",
                "default",
                "default",
                &structurally_bad,
                &repeat('b', 129)
            ),
            Err(AddressError::new(Part::NewName, NameError::TooLong))
        );
        assert_eq!(
            Address::parse_rename(
                "default",
                "default",
                "default",
                &repeat('a', 129),
                &repeat('b', 129)
            ),
            Err(AddressError::new(Part::Name, NameError::TooLong))
        );
        assert_eq!(
            Address::parse_rename("default", "default", "default", "openai", "-work"),
            Err(AddressError::new(Part::NewName, NameError::BadStart))
        );
    }

    #[test]
    fn a_namespace_key_reports_the_namespace_length_first() {
        assert_eq!(
            NamespaceKey::parse("-bad", &repeat('a', 65)),
            Err(AddressError::new(Part::Namespace, NameError::TooLong))
        );
        assert_eq!(
            NamespaceKey::parse("default", "-bad"),
            Err(AddressError::new(Part::Namespace, NameError::BadStart))
        );
    }

    #[test]
    fn a_value_of_one_mib_is_a_value_and_one_byte_more_is_too_large() {
        assert!(SecretValue::new(vec![0; MAX_VALUE_BYTES]).is_ok());
        assert!(matches!(
            SecretValue::new(vec![0; MAX_VALUE_BYTES + 1]),
            Err(StorageError::TooLarge)
        ));
        assert!(SecretValue::new(Vec::new()).is_ok_and(|value| value.is_empty()));
    }

    #[test]
    fn every_storage_error_is_a_closed_code_with_no_free_text() {
        // No variant carries data: the whole enum fits in one byte.
        assert_eq!(std::mem::size_of::<StorageError>(), 1);
        let declared = [
            "not-found",
            "denied",
            "unsupported",
            "unavailable",
            "invalid-name",
            "too-large",
            "conflict",
        ];
        assert_eq!(StorageError::ALL.len(), declared.len());
        for (error, code) in StorageError::ALL.into_iter().zip(declared) {
            assert_eq!(error.code(), code);
            assert_eq!(error.to_string(), code);
            assert_eq!(format!("{error:#}"), code);
            assert_eq!(StorageError::from_code(code), Some(error));
            // Exhaustive without a wildcard: a new variant does not compile until it is here.
            match error {
                StorageError::NotFound
                | StorageError::Denied
                | StorageError::Unsupported
                | StorageError::Unavailable
                | StorageError::InvalidName
                | StorageError::TooLarge
                | StorageError::Conflict => {}
            }
        }
        assert_eq!(StorageError::from_code("not found"), None);
    }

    #[test]
    fn every_name_refusal_is_invalid_name_and_repeats_no_input() {
        let marker = "leak-marker";
        for reason in [
            NameError::TooLong,
            NameError::SegmentTooLong,
            NameError::EmptySegment,
            NameError::BadStart,
            NameError::BadCharacter,
        ] {
            assert_eq!(StorageError::from(reason), StorageError::InvalidName);
            let error = AddressError::new(Part::Name, reason);
            assert_eq!(StorageError::from(error), StorageError::InvalidName);
            assert!(!format!("{error} {error:?}").contains(marker));
        }
    }

    #[test]
    fn the_capability_table_is_the_specification_s() {
        assert_eq!(BackendKind::Onepassword.capabilities(), &[Capability::Read]);
        assert_eq!(BackendKind::Keychain.capabilities(), &Capability::ALL);
        assert_eq!(BackendKind::Remote.capabilities(), &Capability::ALL);
    }

    #[test]
    fn names_deserialize_only_when_valid() {
        let name: Result<SecretName, _> = serde_json::from_str("\"team/openai\"");
        assert!(name.is_ok());
        let name: Result<SecretName, _> = serde_json::from_str("\"Team\"");
        assert!(name.is_err());
        let action: Result<Action, _> = serde_json::from_str("\"manage-namespace\"");
        assert!(action.is_ok_and(|action| action == Action::ManageNamespace));
    }
}
