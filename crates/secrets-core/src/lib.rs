use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretBytes(#[serde(with = "base64_bytes")] pub Vec<u8>);

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for SecretBytes {}

mod base64_bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        STANDARD.decode(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disclosure {
    WorkloadOnly,
    UserRevealable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    pub tenant: String,
    pub namespace: String,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutSecret {
    pub reference: SecretRef,
    pub owner_subject: String,
    pub value: SecretBytes,
    #[serde(default = "workload_only")]
    pub disclosure: Disclosure,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

fn workload_only() -> Disclosure {
    Disclosure::WorkloadOnly
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub id: Uuid,
    pub reference: SecretRef,
    pub owner_subject: String,
    pub disclosure: Disclosure,
    pub state: SecretState,
    pub version: i64,
    pub labels: BTreeMap<String, String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSecret {
    pub metadata: SecretMetadata,
    pub value: SecretBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Mutation {
    Put { secret: PutSecret },
    Delete { reference: SecretRef },
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("storage unavailable")]
    Unavailable,
    #[error("cryptographic operation failed")]
    Crypto,
}

#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn ready(&self) -> Result<(), StoreError>;
    async fn put(&self, input: PutSecret) -> Result<SecretMetadata, StoreError>;
    async fn get(&self, reference: &SecretRef) -> Result<StoredSecret, StoreError>;
    async fn exists(&self, reference: &SecretRef) -> Result<bool, StoreError>;
    async fn delete(&self, reference: &SecretRef, actor: &str) -> Result<(), StoreError>;
    async fn revoke(
        &self,
        reference: &SecretRef,
        actor: &str,
    ) -> Result<SecretMetadata, StoreError>;
    async fn list(
        &self,
        tenant: &str,
        owner: Option<&str>,
    ) -> Result<Vec<SecretMetadata>, StoreError>;
    async fn prepare(
        &self,
        tenant: &str,
        transaction: Uuid,
        mutations: Vec<Mutation>,
        actor: &str,
    ) -> Result<(), StoreError>;
    async fn commit(&self, tenant: &str, transaction: Uuid) -> Result<(), StoreError>;
    async fn abort(&self, tenant: &str, transaction: Uuid) -> Result<(), StoreError>;
}
