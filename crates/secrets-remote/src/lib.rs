//! The custody service as a `secrets.storage` backend (story:remote-backend).
//!
//! [`RemoteBackend`] implements the storage port ([`SecretStorage`]) over the custody service's
//! workload routes, through [`secrets_client::Client`]. It holds no state of its own: every call is
//! one or more requests to the service, authenticated with the client's workload token.
//!
//! # Mapping
//!
//! An [`Address`] maps to the custody reference `{tenant, namespace, key = "<user>/<name>"}`, and
//! the scope's user is the record's `owner_subject` ([`reference`]). A [`ScopeName`] holds no `/`,
//! so the first `/` of a key splits the user from the name unambiguously.
//!
//! The user is part of the key because custody's put upserts on `(tenant, namespace, key)` and
//! overwrites `owner_subject`: with `key = name`, a second user writing the same name would take
//! over the first user's record. Workload reads and listings do not check the owner, so
//! [`SecretStorage::list`] keeps only keys under the scope user's prefix ([`address`]).
//!
//! # Refusals
//!
//! | Client outcome | Storage code |
//! |---|---|
//! | the service cannot be reached, or answers 5xx or an unreadable body | [`StorageError::Unavailable`] |
//! | 404 | [`StorageError::NotFound`] |
//! | 400, 401, 403, 409 or 413 (`Refused`) | [`StorageError::Denied`] |
//!
//! No refusal carries any of the service's response text: a [`StorageError`] has no field.
//!
//! The service refuses a request body over [`SERVICE_BODY_LIMIT`], and a value travels base64
//! encoded, so the backend holds at most [`max_value_bytes`] (about 768 KiB) and answers
//! [`StorageError::TooLarge`] above that without a request. The bound leaves room for the batch a
//! rename sends, so any value this backend accepts can also be renamed.
use std::{collections::BTreeMap, sync::OnceLock};

use async_trait::async_trait;
use secrets_client::{Client, Error as ClientError};
use secrets_core::{
    Disclosure, Mutation, PutSecret, SecretBytes, SecretMetadata as CustodyMetadata, SecretRef,
    SecretState,
    storage::{
        Address, BackendKind, Capability, MAX_SEGMENT_BYTES, Revealed, ScopeName, SecretMetadata,
        SecretName, SecretStorage, SecretValue, StorageError, Target, Version, Written,
    },
};
use uuid::Uuid;

/// The largest request body the custody service accepts, in bytes (`secrets_http::router`'s
/// `RequestBodyLimitLayer`).
pub const SERVICE_BODY_LIMIT: usize = 1024 * 1024;

/// The custody reference an address maps to: `{tenant, namespace, key = "<user>/<name>"}`.
pub fn reference(address: &Address) -> SecretRef {
    SecretRef {
        tenant: address.scope.tenant.as_str().to_owned(),
        namespace: address.scope.namespace.as_str().to_owned(),
        key: format!("{}/{}", address.scope.user, address.name),
    }
}

/// The address a custody reference holds in `scope`, if it holds one: the same tenant and
/// namespace, and a key under the scope user's prefix whose remainder is a [`SecretName`].
pub fn address(scope: &secrets_core::storage::Scope, reference: &SecretRef) -> Option<Address> {
    if reference.tenant != scope.tenant.as_str() || reference.namespace != scope.namespace.as_str()
    {
        return None;
    }
    let (user, name) = reference.key.split_once('/')?;
    if user != scope.user.as_str() {
        return None;
    }
    Some(Address {
        scope: scope.clone(),
        name: SecretName::parse(name).ok()?,
    })
}

/// The largest value, in bytes, whose write and rename both fit [`SERVICE_BODY_LIMIT`].
pub fn max_value_bytes() -> usize {
    static MAX: OnceLock<usize> = OnceLock::new();
    *MAX.get_or_init(|| {
        let room = SERVICE_BODY_LIMIT.saturating_sub(envelope_bytes());
        room / 4 * 3
    })
}

/// The size of the largest request this backend sends with an empty value: a rename's batch with
/// every name at its bound. Base64 adds no escaping and every name is ASCII outside JSON's escapes,
/// so a value of `n` bytes adds exactly `4 * ceil(n / 3)`.
fn envelope_bytes() -> usize {
    let segment = "a".repeat(MAX_SEGMENT_BYTES);
    let name = "a".repeat(secrets_core::storage::MAX_NAME_BYTES);
    let widest = SecretRef {
        tenant: segment.clone(),
        namespace: segment.clone(),
        key: format!("{segment}/{name}"),
    };
    let batch = serde_json::json!({
        "actor": segment,
        "mutations": [
            Mutation::Put { secret: put(widest.clone(), &segment, Vec::new(), Disclosure::WorkloadOnly, BTreeMap::new()) },
            Mutation::Delete { reference: widest },
        ],
    });
    // Unreachable for these types; an unknown size admits no value at all.
    serde_json::to_vec(&batch).map_or(SERVICE_BODY_LIMIT, |body| body.len())
}

fn put(
    reference: SecretRef,
    owner: &str,
    value: Vec<u8>,
    disclosure: Disclosure,
    labels: BTreeMap<String, String>,
) -> PutSecret {
    PutSecret {
        reference,
        owner_subject: owner.to_owned(),
        value: SecretBytes(value),
        disclosure,
        labels,
    }
}

/// A client outcome as the storage code the specification declares. See the module table.
fn refusal(error: ClientError) -> StorageError {
    match error {
        ClientError::Transport | ClientError::Service => StorageError::Unavailable,
        ClientError::NotFound => StorageError::NotFound,
        ClientError::Refused => StorageError::Denied,
    }
}

/// The opaque version of a custody record: its id and its version, so a record deleted and
/// written again does not repeat a version.
fn version(metadata: &CustodyMetadata) -> Version {
    Version::new(format!("{}.{}", metadata.id.simple(), metadata.version))
}

/// The custody service as a storage backend. Kind [`BackendKind::Remote`]: read, write, delete and
/// list, and rename through one prepared batch.
pub struct RemoteBackend {
    client: Client,
}

impl RemoteBackend {
    /// A backend over a client whose token is a workload token of the tenant it serves.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    fn owner(address: &Address) -> &ScopeName {
        &address.scope.user
    }
}

#[async_trait]
impl SecretStorage for RemoteBackend {
    fn capabilities(&self) -> &[Capability] {
        BackendKind::Remote.capabilities()
    }

    async fn read(&self, target: &Target) -> Result<Revealed, StorageError> {
        let reference = reference(&target.address);
        let mut stored = self.client.get(&reference).await.map_err(refusal)?;
        if stored.metadata.reference != reference {
            return Err(StorageError::NotFound);
        }
        let version = version(&stored.metadata);
        let value = SecretValue::new(std::mem::take(&mut stored.value.0))
            .map_err(|_| StorageError::Unavailable)?;
        Ok(Revealed {
            value,
            version: Some(version),
        })
    }

    async fn write(&self, target: &Target, value: SecretValue) -> Result<Written, StorageError> {
        if value.len() > max_value_bytes() {
            return Err(StorageError::TooLarge);
        }
        let input = put(
            reference(&target.address),
            Self::owner(&target.address).as_str(),
            value.expose().to_vec(),
            Disclosure::WorkloadOnly,
            BTreeMap::new(),
        );
        let metadata = self.client.put(&input).await.map_err(refusal)?;
        let written = Some(version(&metadata));
        Ok(if metadata.version == 1 {
            Written::Created(written)
        } else {
            Written::Replaced(written)
        })
    }

    async fn delete(&self, target: &Target) -> Result<(), StorageError> {
        self.client
            .delete(
                &reference(&target.address),
                Self::owner(&target.address).as_str(),
            )
            .await
            .map_err(refusal)
    }

    async fn rename(&self, target: &Target, new_name: &SecretName) -> Result<(), StorageError> {
        let from = reference(&target.address);
        let to = reference(&Address {
            scope: target.address.scope.clone(),
            name: new_name.clone(),
        });
        let mut stored = self.client.get(&from).await.map_err(refusal)?;
        if self.client.exists(&to).await.map_err(refusal)? {
            return Err(StorageError::Conflict);
        }
        let owner = Self::owner(&target.address).as_str();
        let mutations = [
            Mutation::Put {
                secret: put(
                    to,
                    owner,
                    std::mem::take(&mut stored.value.0),
                    stored.metadata.disclosure,
                    std::mem::take(&mut stored.metadata.labels),
                ),
            },
            Mutation::Delete {
                reference: from.clone(),
            },
        ];
        let transaction = Uuid::now_v7();
        self.client
            .prepare(&from.tenant, transaction, owner, &mutations)
            .await
            .map_err(refusal)?;
        if let Err(error) = self.client.commit(&from.tenant, transaction).await {
            // Best effort: an unreachable service lets the batch expire on its own.
            let _ = self.client.abort(&from.tenant, transaction).await;
            return Err(refusal(error));
        }
        Ok(())
    }

    async fn list(
        &self,
        scope: &secrets_core::storage::Scope,
    ) -> Result<Vec<SecretMetadata>, StorageError> {
        let mut listed: Vec<SecretMetadata> = self
            .client
            .references(scope.tenant.as_str(), scope.namespace.as_str())
            .await
            .map_err(refusal)?
            .into_iter()
            .filter(|metadata| metadata.state == SecretState::Active)
            .filter_map(|metadata| {
                Some(SecretMetadata {
                    address: address(scope, &metadata.reference)?,
                    version: Some(version(&metadata)),
                })
            })
            .collect();
        listed.sort();
        Ok(listed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrets_core::storage::Scope;

    fn scope(user: &str) -> Scope {
        Scope {
            tenant: ScopeName::default_name(),
            namespace: ScopeName::default_name(),
            user: ScopeName::parse(user).unwrap_or_else(|_| ScopeName::default_name()),
        }
    }

    #[test]
    fn an_address_maps_to_the_user_prefixed_key_and_back() {
        let Ok(name) = SecretName::parse("team/openai") else {
            panic!("a name");
        };
        let alice = Address {
            scope: scope("alice"),
            name,
        };
        let mapped = reference(&alice);
        assert_eq!(mapped.key, "alice/team/openai");
        assert_eq!(address(&scope("alice"), &mapped), Some(alice));
        assert_eq!(address(&scope("bob"), &mapped), None);
        let unprefixed = SecretRef {
            key: "openai".into(),
            ..mapped
        };
        assert_eq!(address(&scope("alice"), &unprefixed), None);
    }

    #[test]
    fn the_value_bound_leaves_room_for_a_rename_batch() {
        let max = max_value_bytes();
        assert!(max > 700 * 1024 && max < SERVICE_BODY_LIMIT);
        assert!(envelope_bytes() + max.div_ceil(3) * 4 <= SERVICE_BODY_LIMIT);
        assert!(envelope_bytes() + (max + 1).div_ceil(3) * 4 > SERVICE_BODY_LIMIT);
    }

    #[test]
    fn every_client_outcome_maps_to_a_declared_code() {
        assert_eq!(refusal(ClientError::Transport), StorageError::Unavailable);
        assert_eq!(refusal(ClientError::Service), StorageError::Unavailable);
        assert_eq!(refusal(ClientError::NotFound), StorageError::NotFound);
        assert_eq!(refusal(ClientError::Refused), StorageError::Denied);
    }
}
