//! Authorization and disclosure at the shipped router (`secrets_http::router`), over a store that
//! answers every call successfully. A route that lets a request past its checks therefore answers
//! 2xx, so a refusal here is the router's own and not the store's.
//!
//! The conformance suite reaches `forbidden` only through a principal of another tenant, so it does
//! not tell a route that checks its action from one that checks none, and it reads every view as a
//! principal of the addressed tenant, so it does not tell a view that checks the tenant from one
//! that does not.
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
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tower::ServiceExt as _;
use uuid::Uuid;

const TENANT: &str = "tenant-a";
const OTHER_TENANT: &str = "tenant-b";
const SUBJECT: &str = "subject-a";
const LEAK: &[u8] = b"value-that-must-stay-in-tenant-a";
const TRANSACTION: &str = "0191f5a0-0000-7000-8000-00000000abcd";
const ACTIONS: [&str; 9] = [
    "secret:list",
    "secret:read_metadata",
    "secret:revoke",
    "secret:delete",
    "secret:write",
    "secret:read_value",
    "secret:prepare",
    "secret:commit",
    "secret:abort",
];

fn reference() -> SecretRef {
    SecretRef {
        tenant: TENANT.into(),
        namespace: "ns".into(),
        key: "k".into(),
    }
}

fn metadata() -> SecretMetadata {
    SecretMetadata {
        id: Uuid::nil(),
        reference: reference(),
        owner_subject: SUBJECT.into(),
        disclosure: Disclosure::WorkloadOnly,
        state: SecretState::Active,
        version: 1,
        labels: BTreeMap::new(),
        created_at: String::new(),
        updated_at: String::new(),
    }
}

/// Answers every call as if it succeeded, for any tenant.
struct Yes;
#[async_trait]
impl SecretStore for Yes {
    async fn ready(&self) -> Result<(), StoreError> {
        Ok(())
    }
    async fn put(&self, _: PutSecret) -> Result<SecretMetadata, StoreError> {
        Ok(metadata())
    }
    async fn get(&self, _: &SecretRef) -> Result<StoredSecret, StoreError> {
        Ok(StoredSecret {
            metadata: metadata(),
            value: SecretBytes(LEAK.to_vec()),
        })
    }
    async fn exists(&self, _: &SecretRef) -> Result<bool, StoreError> {
        Ok(true)
    }
    async fn delete(&self, _: &SecretRef, _: &str) -> Result<(), StoreError> {
        Ok(())
    }
    async fn revoke(&self, _: &SecretRef, _: &str) -> Result<SecretMetadata, StoreError> {
        Ok(metadata())
    }
    async fn list(&self, _: &str, _: Option<&str>) -> Result<Vec<SecretMetadata>, StoreError> {
        Ok(vec![metadata()])
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

/// Resolves the bearer token `t` to one fixed principal.
struct One(Principal);
#[async_trait]
impl Authority for One {
    async fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        if token == "t" {
            Ok(self.0.clone())
        } else {
            Err(AuthError::Unauthorized)
        }
    }
}

fn router(tenant: &str, actions: &[&str]) -> Router {
    let principal = Principal {
        subject: SUBJECT.into(),
        tenant: tenant.into(),
        actions: actions.iter().map(|a| (*a).to_owned()).collect(),
    };
    secrets_http::router(AppState {
        store: Arc::new(Yes),
        user_authority: Arc::new(One(principal.clone())),
        workload_authority: Arc::new(One(principal)),
    })
}

struct Route {
    name: &'static str,
    action: &'static str,
    method: Method,
    path: String,
    body: Option<Value>,
}

fn routes() -> Vec<Route> {
    let r = json!(reference());
    let tx = |verb: &str| format!("/v1/workload/tenants/{TENANT}/transactions/{TRANSACTION}{verb}");
    let route = |name, action, method, path: &str, body| Route {
        name,
        action,
        method,
        path: path.to_owned(),
        body,
    };
    vec![
        route(
            "user_list",
            "secret:list",
            Method::GET,
            "/v1/user/secrets",
            None,
        ),
        route(
            "user_detail",
            "secret:read_metadata",
            Method::POST,
            "/v1/user/secrets:detail",
            Some(r.clone()),
        ),
        route(
            "user_revoke",
            "secret:revoke",
            Method::POST,
            "/v1/user/secrets:revoke",
            Some(r.clone()),
        ),
        route(
            "user_delete",
            "secret:delete",
            Method::DELETE,
            "/v1/user/secrets",
            Some(r.clone()),
        ),
        route(
            "workload_put",
            "secret:write",
            Method::PUT,
            "/v1/workload/secrets",
            Some(json!({"reference": r, "owner_subject": SUBJECT, "value": "dg=="})),
        ),
        route(
            "workload_get",
            "secret:read_value",
            Method::POST,
            "/v1/workload/secrets:get",
            Some(r.clone()),
        ),
        route(
            "workload_exists",
            "secret:read_metadata",
            Method::POST,
            "/v1/workload/secrets:exists",
            Some(r.clone()),
        ),
        route(
            "workload_list",
            "secret:list",
            Method::POST,
            "/v1/workload/secrets:list",
            Some(json!({"tenant": TENANT, "namespace": "ns"})),
        ),
        route(
            "workload_delete",
            "secret:delete",
            Method::POST,
            "/v1/workload/secrets:delete",
            Some(json!({"reference": r})),
        ),
        route(
            "workload_prepare",
            "secret:prepare",
            Method::PUT,
            &tx(""),
            Some(json!({"actor": "a", "mutations": [{"op": "delete", "reference": r}]})),
        ),
        route(
            "workload_commit",
            "secret:commit",
            Method::POST,
            &tx("/commit"),
            None,
        ),
        route(
            "workload_abort",
            "secret:abort",
            Method::POST,
            &tx("/abort"),
            None,
        ),
    ]
}

async fn send(
    router: Router,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, "Bearer t");
    let body = match body {
        Some(bytes) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(bytes)
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

async fn call(router: Router, route: &Route) -> (StatusCode, Vec<u8>) {
    let body = route.body.as_ref().map(|b| serde_json::to_vec(b).unwrap());
    send(router, route.method.clone(), &route.path, body).await
}

/// Control: a principal of the addressed tenant holding exactly the route's action gets through, so
/// a 403 in the tests below is the check under test and not a malformed request.
#[tokio::test]
async fn every_route_admits_a_principal_of_its_tenant_holding_only_its_action() {
    let mut refused = Vec::new();
    for route in routes() {
        let (status, _) = call(router(TENANT, &[route.action]), &route).await;
        if !status.is_success() {
            refused.push(format!("{} answered {status}", route.name));
        }
    }
    assert!(
        refused.is_empty(),
        "admitted principal refused: {refused:?}"
    );
}

/// Each route checks its action: a principal of the addressed tenant holding every other action is
/// refused (spec/domains/custody.yaml: `forbidden` — "the grant lacks secret:<action>").
#[tokio::test]
async fn every_route_refuses_a_principal_of_its_tenant_lacking_its_action() {
    let mut admitted = Vec::new();
    for route in routes() {
        let others: Vec<&str> = ACTIONS
            .iter()
            .copied()
            .filter(|a| *a != route.action)
            .collect();
        let (status, _) = call(router(TENANT, &others), &route).await;
        if status != StatusCode::FORBIDDEN {
            admitted.push(format!(
                "{} answered {status} without {}",
                route.name, route.action
            ));
        }
    }
    assert!(
        admitted.is_empty(),
        "route did not check its action: {admitted:?}"
    );
}

/// Each route that addresses a tenant refuses a principal of another tenant holding every action,
/// and discloses nothing of the addressed tenant's secret in doing so.
#[tokio::test]
async fn every_tenant_addressed_route_refuses_a_principal_of_another_tenant() {
    let mut admitted = Vec::new();
    for route in routes().into_iter().filter(|r| r.name != "user_list") {
        let (status, body) = call(router(OTHER_TENANT, &ACTIONS), &route).await;
        let leaked = body.windows(LEAK.len()).any(|w| w == LEAK)
            || String::from_utf8_lossy(&body)
                .contains("dmFsdWUtdGhhdC1tdXN0LXN0YXktaW4tdGVuYW50LWE=");
        if status != StatusCode::FORBIDDEN || leaked {
            admitted.push(format!(
                "{} answered {status} to {OTHER_TENANT} (leaked={leaked})",
                route.name
            ));
        }
    }
    assert!(
        admitted.is_empty(),
        "cross-tenant request admitted: {admitted:?}"
    );
}

/// A value that is not base64 is refused in the router's refusal shape `{"error": <reason>}`
/// (crates/secrets-http/src/lib.rs `ApiError`), not with a decoder message naming a byte of the
/// value and its offset (AGENTS.md: values never belong in errors).
#[tokio::test]
async fn a_malformed_value_is_refused_without_naming_its_bytes() {
    let mut seen = BTreeSet::new();
    for value in ["hunter2!", "c2VjcmV0-dG9rZW4"] {
        let body = json!({"reference": reference(), "owner_subject": SUBJECT, "value": value});
        let (status, bytes) = send(
            router(TENANT, &["secret:write"]),
            Method::PUT,
            "/v1/workload/secrets",
            Some(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let shaped = serde_json::from_slice::<Value>(&bytes).ok()
            == Some(json!({"error": status.canonical_reason()}));
        if !shaped {
            seen.insert(format!("{status} {text}"));
        }
    }
    assert!(
        seen.is_empty(),
        "refusal carried more than the error reason: {seen:?}"
    );
}
