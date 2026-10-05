//! Integrity conformance checks of story:refusal-codes against the contract the unit wrote for
//! itself: website/docs/security-model.md ("a person cannot learn whether another owner's secret exists"),
//! website/docs/http-api.md (the code table) and the story's acceptance ("Every refusal the service answers
//! carries a stable machine-readable code").
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt as _;
use secrets_auth::{AuthError, Authority, Principal};
use secrets_core::{
    Disclosure, Mutation, PutSecret, SecretBytes, SecretMetadata, SecretRef, SecretState,
    SecretStore, StoreError, StoredSecret,
};
use secrets_http::AppState;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt as _;
use uuid::Uuid;

const TENANT: &str = "tenant-a";
const CALLER: &str = "subject-a";
const OTHER_OWNER: &str = "subject-b";

fn reference() -> SecretRef {
    SecretRef {
        tenant: TENANT.into(),
        namespace: "ns".into(),
        key: "k".into(),
    }
}

fn metadata(owner: &str) -> SecretMetadata {
    SecretMetadata {
        id: Uuid::nil(),
        reference: reference(),
        owner_subject: owner.into(),
        disclosure: Disclosure::WorkloadOnly,
        state: SecretState::Active,
        version: 1,
        labels: BTreeMap::new(),
        created_at: String::new(),
        updated_at: String::new(),
    }
}

/// Holds at most one secret, at `reference()`, owned by `owner`; `list` honours the owner filter
/// the way the PostgreSQL store does.
struct One {
    owner: Option<&'static str>,
}
#[async_trait]
impl SecretStore for One {
    async fn ready(&self) -> Result<(), StoreError> {
        Ok(())
    }
    async fn put(&self, _: PutSecret) -> Result<SecretMetadata, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn get(&self, _: &SecretRef) -> Result<StoredSecret, StoreError> {
        match self.owner {
            Some(owner) => Ok(StoredSecret {
                metadata: metadata(owner),
                value: SecretBytes(b"v".to_vec()),
            }),
            None => Err(StoreError::NotFound),
        }
    }
    async fn exists(&self, _: &SecretRef) -> Result<bool, StoreError> {
        Ok(self.owner.is_some())
    }
    async fn delete(&self, _: &SecretRef, _: &str) -> Result<(), StoreError> {
        self.owner.map(|_| ()).ok_or(StoreError::NotFound)
    }
    async fn revoke(&self, _: &SecretRef, _: &str) -> Result<SecretMetadata, StoreError> {
        self.owner.map(metadata).ok_or(StoreError::NotFound)
    }
    async fn list(
        &self,
        tenant: &str,
        owner: Option<&str>,
    ) -> Result<Vec<SecretMetadata>, StoreError> {
        Ok(self
            .owner
            .filter(|stored| tenant == TENANT && owner.is_none_or(|o| o == *stored))
            .map(metadata)
            .into_iter()
            .collect())
    }
    async fn prepare(&self, _: &str, _: Uuid, _: Vec<Mutation>, _: &str) -> Result<(), StoreError> {
        Ok(())
    }
    async fn commit(&self, _: &str, _: Uuid) -> Result<(), StoreError> {
        Ok(())
    }
    async fn abort(&self, _: &str, _: Uuid) -> Result<(), StoreError> {
        Ok(())
    }
}

struct Caller;
#[async_trait]
impl Authority for Caller {
    async fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        if token != "t" {
            return Err(AuthError::Unauthorized);
        }
        Ok(Principal {
            subject: CALLER.into(),
            tenant: TENANT.into(),
            actions: ["*".to_owned()].into_iter().collect(),
        })
    }
}

fn router(owner: Option<&'static str>) -> Router {
    secrets_http::router(AppState {
        store: Arc::new(One { owner }),
        user_authority: Arc::new(Caller),
        workload_authority: Arc::new(Caller),
    })
}

async fn send(
    router: Router,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, "Bearer t");
    let body = match body {
        Some(value) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&value).unwrap())
        }
        None => Body::empty(),
    };
    let response = router.oneshot(request.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

const USER_ROUTES: [(&str, &str); 3] = [
    ("POST", "/v1/user/secrets:detail"),
    ("POST", "/v1/user/secrets:revoke"),
    ("DELETE", "/v1/user/secrets"),
];

/// website/docs/security-model.md "Tenant and ownership": a user route answers a secret owned by
/// somebody else exactly as it answers no secret at all, byte for byte, so the new codes open no
/// existence oracle between `not-owned` and `not-found`.
#[tokio::test]
async fn a_user_route_answers_another_owners_secret_exactly_as_no_secret() {
    let mut differs = Vec::new();
    for (method, path) in USER_ROUTES {
        let method: Method = method.parse().unwrap();
        let foreign = send(
            router(Some(OTHER_OWNER)),
            method.clone(),
            path,
            Some(json!(reference())),
        )
        .await;
        let absent = send(router(None), method.clone(), path, Some(json!(reference()))).await;
        if foreign != absent || foreign.0 != StatusCode::NOT_FOUND {
            differs.push(format!(
                "{method} {path}: foreign {} {} / absent {} {}",
                foreign.0,
                String::from_utf8_lossy(&foreign.1),
                absent.0,
                String::from_utf8_lossy(&absent.1)
            ));
        }
    }
    assert!(differs.is_empty(), "existence oracle: {differs:#?}");
}

/// docs/http-api.md: `not-owned` is "on a user route, no secret at the reference is owned by the
/// caller", and `Refusal::NotOwned` is "A user route addresses a secret the caller does not own, or
/// none at all". Every user route that addresses a reference answers that case with that code.
#[tokio::test]
async fn every_user_route_answers_a_secret_the_caller_does_not_own_as_not_owned() {
    let mut wrong = Vec::new();
    for (method, path) in USER_ROUTES {
        let method: Method = method.parse().unwrap();
        let (status, bytes) = send(
            router(Some(OTHER_OWNER)),
            method.clone(),
            path,
            Some(json!(reference())),
        )
        .await;
        let body: Option<Value> = serde_json::from_slice(&bytes).ok();
        if status != StatusCode::NOT_FOUND
            || body != Some(json!({"error": "Not Found", "code": "not-owned"}))
        {
            wrong.push(format!(
                "{method} {path}: {status} {}",
                String::from_utf8_lossy(&bytes)
            ));
        }
    }
    assert!(wrong.is_empty(), "user-route ownership codes: {wrong:#?}");
}

/// Acceptance of story:refusal-codes: "Every refusal the service answers carries a stable
/// machine-readable code beside its reason". A request to a path the router has no route for, or
/// with a method a route does not take, is refused by the router; that refusal has the shape too.
#[tokio::test]
async fn a_refusal_from_the_router_itself_carries_a_code() {
    let mut uncoded = Vec::new();
    for (method, path) in [
        (Method::POST, "/v1/workload/secrets:nope"),
        (Method::GET, "/v1/workload/secrets"),
        (Method::GET, "/v1/user/secrets:detail"),
    ] {
        let (status, bytes) = send(router(None), method.clone(), path, None).await;
        let coded = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|v| v.get("code").and_then(Value::as_str).map(str::to_owned));
        if coded.is_none() {
            uncoded.push(format!(
                "{method} {path}: {status} {:?}",
                String::from_utf8_lossy(&bytes)
            ));
        }
    }
    assert!(uncoded.is_empty(), "refusals without a code: {uncoded:#?}");
}
