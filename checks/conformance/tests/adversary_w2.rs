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
    Actor, Disclosure, InvalidInput, Mutation, PutSecret, SecretBytes, SecretMetadata, SecretRef,
    SecretState, SecretStore, StoreError, StoredSecret,
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
    async fn put(&self, _: PutSecret, _: &Actor) -> Result<SecretMetadata, StoreError> {
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
    async fn delete(&self, _: &SecretRef, _: &Actor) -> Result<(), StoreError> {
        Ok(())
    }
    async fn revoke(&self, _: &SecretRef, _: &Actor) -> Result<SecretMetadata, StoreError> {
        Ok(metadata())
    }
    async fn list(&self, _: &str, _: Option<&str>) -> Result<Vec<SecretMetadata>, StoreError> {
        Ok(vec![metadata()])
    }
    async fn prepare(&self, _: &str, _: Uuid, _: Vec<Mutation>, _: &str) -> Result<(), StoreError> {
        Ok(())
    }
    async fn commit(&self, _: &str, _: Uuid, _: &str) -> Result<(), StoreError> {
        Ok(())
    }
    async fn abort(&self, _: &str, _: Uuid) -> Result<(), StoreError> {
        Ok(())
    }
}

/// Resolves the bearer token `t` to one fixed principal; `down` finds the authority unavailable.
struct One(Principal);
#[async_trait]
impl Authority for One {
    async fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        if token == "t" {
            Ok(self.0.clone())
        } else if token == "down" {
            Err(AuthError::Unavailable)
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

/// A value that is not base64 is refused in the router's refusal shape
/// `{"error": <reason>, "code": "malformed-body"}` (crates/secrets-http/src/lib.rs `Refusal`), not
/// with a decoder message naming a byte of the value and its offset (AGENTS.md: values never belong
/// in errors).
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
            == Some(json!({"error": status.canonical_reason(), "code": "malformed-body"}));
        if !shaped {
            seen.insert(format!("{status} {text}"));
        }
    }
    assert!(
        seen.is_empty(),
        "refusal carried more than the error reason: {seen:?}"
    );
}

// ---- refusal codes (story:refusal-codes) ------------------------------------------------------
//
// Every refusal is `{"error": <status reason>, "code": <outcome name>}` and nothing else, so a
// client tells two refusals of one status apart from the response alone.

/// The code of a refusal body that is exactly the status reason and a code, or why it is not.
fn code_of(status: StatusCode, bytes: &[u8]) -> Result<String, String> {
    let shown = || format!("{status} {}", String::from_utf8_lossy(bytes));
    let value: Value = serde_json::from_slice(bytes).map_err(|_| shown())?;
    let object = value.as_object().ok_or_else(shown)?;
    if object.len() != 2 || object.get("error") != Some(&json!(status.canonical_reason())) {
        return Err(shown());
    }
    object
        .get("code")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(shown)
}

async fn send_as(
    router: Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
    content_length: bool,
) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(bytes) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            if content_length {
                request = request.header(header::CONTENT_LENGTH, bytes.len());
            }
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

/// The codes the router can emit and the refusal outcomes `spec/domains/custody.yaml` declares for
/// the commands it answers over HTTP are one set: a code no outcome names is unreachable to every
/// reader of the specification, and an outcome no code names cannot be told apart by a client.
/// The two routing refusals (unknown path, wrong method) are outcomes of no command and are
/// checked apart.
#[test]
fn the_router_codes_are_exactly_the_specified_refusal_outcomes() {
    let spec: serde_yaml::Value = serde_yaml::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/domains/custody.yaml"
        ))
        .unwrap(),
    )
    .unwrap();
    let refusals = |outcomes: &serde_yaml::Value| -> Vec<String> {
        outcomes
            .as_sequence()
            .unwrap()
            .iter()
            .filter(|outcome| outcome.get("error").is_some())
            .map(|outcome| outcome["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let mut specified = BTreeSet::new();
    for command in spec["commands"].as_sequence().unwrap() {
        // `secrets rewrap` is an operator command, not a route; its refusal is an exit status.
        if command["name"] == "secrets.custody.RewrapSecrets" {
            continue;
        }
        specified.extend(refusals(&command["outcomes"]));
    }
    for group in spec["outcome_groups"].as_sequence().unwrap() {
        specified.extend(refusals(&group["outcomes"]));
    }
    let routing: BTreeSet<String> = secrets_http::routing_refusal_codes()
        .map(str::to_owned)
        .collect();
    let emitted: BTreeSet<String> = secrets_http::refusal_codes()
        .map(str::to_owned)
        .filter(|code| !routing.contains(code))
        .collect();
    assert_eq!(emitted, specified);
    // A routing refusal is no command's outcome, so no outcome may reuse its code.
    assert!(routing.is_disjoint(&specified), "{routing:?}");
    assert_eq!(routing.len(), 2, "{routing:?}");
}

/// The router's own refusals: an unknown path is `route-not-found` and a method the path does not
/// take is `method-not-allowed`, each in the refusal shape and without echoing the path.
#[tokio::test]
async fn the_routers_own_refusals_are_coded() {
    let cases = [
        (
            Method::POST,
            "/v1/workload/hunter2",
            StatusCode::NOT_FOUND,
            "route-not-found",
        ),
        (
            Method::GET,
            "/hunter2",
            StatusCode::NOT_FOUND,
            "route-not-found",
        ),
        (
            Method::GET,
            "/v1/workload/secrets",
            StatusCode::METHOD_NOT_ALLOWED,
            "method-not-allowed",
        ),
        (
            Method::PATCH,
            &format!("/v1/workload/tenants/{TENANT}/transactions/{TRANSACTION}"),
            StatusCode::METHOD_NOT_ALLOWED,
            "method-not-allowed",
        ),
    ];
    let mut wrong = Vec::new();
    for (method, path, expected_status, expected_code) in cases {
        let (status, bytes) = send(router(TENANT, &ACTIONS), method.clone(), path, None).await;
        let echoed = String::from_utf8_lossy(&bytes).contains("hunter2");
        match code_of(status, &bytes) {
            Ok(code) if status == expected_status && code == expected_code && !echoed => {}
            seen => wrong.push(format!("{method} {path}: {seen:?}")),
        }
    }
    assert!(wrong.is_empty(), "routing refusals: {wrong:#?}");
}

/// Pair 1: both answer 403; the code says which check refused.
#[tokio::test]
async fn a_missing_action_and_a_foreign_tenant_answer_distinct_codes() {
    let mut wrong = Vec::new();
    for route in routes() {
        let others: Vec<&str> = ACTIONS
            .iter()
            .copied()
            .filter(|a| *a != route.action)
            .collect();
        let (status, body) = call(router(TENANT, &others), &route).await;
        match code_of(status, &body) {
            Ok(code) if status == StatusCode::FORBIDDEN && code == "missing-action" => {}
            seen => wrong.push(format!("{} lacking its action: {seen:?}", route.name)),
        }
        if route.name == "user_list" {
            continue;
        }
        let (status, body) = call(router(OTHER_TENANT, &ACTIONS), &route).await;
        match code_of(status, &body) {
            Ok(code) if status == StatusCode::FORBIDDEN && code == "forbidden" => {}
            seen => wrong.push(format!("{} from another tenant: {seen:?}", route.name)),
        }
    }
    assert!(wrong.is_empty(), "403 codes: {wrong:#?}");
}

/// A missing bearer token and one the authority refuses are both `unauthorized`.
#[tokio::test]
async fn a_missing_or_refused_token_is_coded_unauthorized() {
    let mut wrong = Vec::new();
    for route in routes() {
        let body = route.body.as_ref().map(|b| serde_json::to_vec(b).unwrap());
        for token in [None, Some("refused")] {
            let (status, bytes) = send_as(
                router(TENANT, &ACTIONS),
                route.method.clone(),
                &route.path,
                token,
                body.clone(),
                true,
            )
            .await;
            match code_of(status, &bytes) {
                Ok(code) if status == StatusCode::UNAUTHORIZED && code == "unauthorized" => {}
                seen => wrong.push(format!("{} with {token:?}: {seen:?}", route.name)),
            }
        }
    }
    assert!(wrong.is_empty(), "401 codes: {wrong:#?}");
}

/// An authority that cannot be reached is `unavailable`, not `unauthorized`.
#[tokio::test]
async fn an_unreachable_authority_is_coded_unavailable() {
    let mut wrong = Vec::new();
    for route in routes() {
        let body = route.body.as_ref().map(|b| serde_json::to_vec(b).unwrap());
        let (status, bytes) = send_as(
            router(TENANT, &ACTIONS),
            route.method.clone(),
            &route.path,
            Some("down"),
            body,
            true,
        )
        .await;
        match code_of(status, &bytes) {
            Ok(code) if status == StatusCode::SERVICE_UNAVAILABLE && code == "unavailable" => {}
            seen => wrong.push(format!("{}: {seen:?}", route.name)),
        }
    }
    assert!(wrong.is_empty(), "authority-unavailable codes: {wrong:#?}");
}

/// A transaction path segment that is not a UUID is `malformed-path`, and the refusal does not
/// quote the segment back, as axum's own path rejection does.
#[tokio::test]
async fn a_transaction_path_that_is_not_a_uuid_is_coded_malformed_path_without_echoing_it() {
    let mut wrong = Vec::new();
    for route in routes()
        .into_iter()
        .filter(|r| r.path.contains("/transactions/"))
    {
        let path = route.path.replace(TRANSACTION, "hunter2-not-a-uuid");
        let body = route.body.as_ref().map(|b| serde_json::to_vec(b).unwrap());
        let (status, bytes) =
            send(router(TENANT, &ACTIONS), route.method.clone(), &path, body).await;
        let echoed = String::from_utf8_lossy(&bytes).contains("hunter2");
        match code_of(status, &bytes) {
            Ok(code)
                if status == StatusCode::BAD_REQUEST && code == "malformed-path" && !echoed => {}
            seen => wrong.push(format!("{}: {seen:?} echoed={echoed}", route.name)),
        }
    }
    assert!(wrong.is_empty(), "malformed paths: {wrong:#?}");
}

/// A body over 1 MiB is `too-large` in the refusal shape, whether the layer refuses it from its
/// declared length or the extractor from the bytes it read.
#[tokio::test]
async fn a_body_over_the_limit_is_coded_too_large() {
    let mut wrong = Vec::new();
    let mut body = serde_json::to_vec(
        &json!({"reference": reference(), "owner_subject": SUBJECT, "value": "dg=="}),
    )
    .unwrap();
    body.resize(1024 * 1024 + 1, b' ');
    for content_length in [true, false] {
        let (status, bytes) = send_as(
            router(TENANT, &ACTIONS),
            Method::PUT,
            "/v1/workload/secrets",
            Some("t"),
            Some(body.clone()),
            content_length,
        )
        .await;
        match code_of(status, &bytes) {
            Ok(code) if status == StatusCode::PAYLOAD_TOO_LARGE && code == "too-large" => {}
            seen => wrong.push(format!("content-length={content_length}: {seen:?}")),
        }
    }
    assert!(wrong.is_empty(), "413 codes: {wrong:#?}");
}

/// Answers every write with the error `fail` makes, and lists the one secret `SUBJECT` owns so a
/// user route passes its ownership check and reaches the store.
struct Fails(fn() -> StoreError);
#[async_trait]
impl SecretStore for Fails {
    async fn ready(&self) -> Result<(), StoreError> {
        Ok(())
    }
    async fn put(&self, _: PutSecret, _: &Actor) -> Result<SecretMetadata, StoreError> {
        Err((self.0)())
    }
    async fn get(&self, _: &SecretRef) -> Result<StoredSecret, StoreError> {
        Err((self.0)())
    }
    async fn exists(&self, _: &SecretRef) -> Result<bool, StoreError> {
        Err((self.0)())
    }
    async fn delete(&self, _: &SecretRef, _: &Actor) -> Result<(), StoreError> {
        Err((self.0)())
    }
    async fn revoke(&self, _: &SecretRef, _: &Actor) -> Result<SecretMetadata, StoreError> {
        Err((self.0)())
    }
    async fn list(&self, _: &str, _: Option<&str>) -> Result<Vec<SecretMetadata>, StoreError> {
        Ok(vec![metadata()])
    }
    async fn prepare(&self, _: &str, _: Uuid, _: Vec<Mutation>, _: &str) -> Result<(), StoreError> {
        Err((self.0)())
    }
    async fn commit(&self, _: &str, _: Uuid, _: &str) -> Result<(), StoreError> {
        Err((self.0)())
    }
    async fn abort(&self, _: &str, _: Uuid) -> Result<(), StoreError> {
        Err((self.0)())
    }
}

fn failing(fail: fn() -> StoreError) -> Router {
    let principal = Principal {
        subject: SUBJECT.into(),
        tenant: TENANT.into(),
        actions: ACTIONS.iter().map(|a| (*a).to_owned()).collect(),
    };
    secrets_http::router(AppState {
        store: Arc::new(Fails(fail)),
        user_authority: Arc::new(One(principal.clone())),
        workload_authority: Arc::new(One(principal)),
    })
}

/// One store error, the refusal it must answer, and the routes it is sent through (every route
/// that reaches the store when empty).
type StoreCase = (
    fn() -> StoreError,
    StatusCode,
    &'static str,
    &'static [&'static str],
);

/// A store refusal carries the code of the outcome it is, for every `StoreError` the store can
/// return, on every route that reaches the store.
#[tokio::test]
async fn store_refusals_carry_their_outcome_codes() {
    let cases: [StoreCase; 9] = [
        (
            || StoreError::NotFound,
            StatusCode::NOT_FOUND,
            "not-found",
            &[],
        ),
        (
            || StoreError::DeleteTargetMissing,
            StatusCode::NOT_FOUND,
            "delete-target-missing",
            &["workload_commit"],
        ),
        (
            || StoreError::Conflict,
            StatusCode::CONFLICT,
            "duplicate",
            &["workload_prepare"],
        ),
        (
            || StoreError::Invalid(InvalidInput::MalformedReference),
            StatusCode::BAD_REQUEST,
            "malformed-reference",
            &["workload_put", "workload_commit"],
        ),
        (
            || StoreError::Invalid(InvalidInput::InvalidReference),
            StatusCode::BAD_REQUEST,
            "invalid-reference",
            &["workload_put", "workload_commit"],
        ),
        (
            || StoreError::Invalid(InvalidInput::EmptyBatch),
            StatusCode::BAD_REQUEST,
            "empty-batch",
            &["workload_prepare"],
        ),
        (
            || StoreError::Invalid(InvalidInput::CrossTenantBatch),
            StatusCode::BAD_REQUEST,
            "cross-tenant-batch",
            &["workload_prepare"],
        ),
        (
            || StoreError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &[],
        ),
        (
            || StoreError::Crypto,
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &[],
        ),
    ];
    let mut wrong = Vec::new();
    for (fail, expected_status, expected_code, only) in cases {
        for route in routes().into_iter().filter(|r| {
            !matches!(r.name, "user_list" | "user_detail" | "workload_list")
                && (only.is_empty() || only.contains(&r.name))
        }) {
            let (status, bytes) = call(failing(fail), &route).await;
            match code_of(status, &bytes) {
                Ok(code) if status == expected_status && code == expected_code => {}
                seen => wrong.push(format!(
                    "{} expecting {expected_code}: {seen:?}",
                    route.name
                )),
            }
        }
    }
    assert!(wrong.is_empty(), "store refusal codes: {wrong:#?}");
}

/// A user route addressing a secret the caller does not own is `not-owned`, not `not-found`.
#[tokio::test]
async fn a_user_route_on_a_secret_the_caller_does_not_own_is_coded_not_owned() {
    let mut wrong = Vec::new();
    let unowned = json!({"tenant": TENANT, "namespace": "ns", "key": "someone-elses"});
    for route in routes()
        .into_iter()
        .filter(|r| matches!(r.name, "user_detail" | "user_revoke" | "user_delete"))
    {
        let (status, bytes) = send(
            router(TENANT, &ACTIONS),
            route.method.clone(),
            &route.path,
            Some(serde_json::to_vec(&unowned).unwrap()),
        )
        .await;
        match code_of(status, &bytes) {
            Ok(code) if status == StatusCode::NOT_FOUND && code == "not-owned" => {}
            seen => wrong.push(format!("{}: {seen:?}", route.name)),
        }
    }
    assert!(wrong.is_empty(), "not-owned codes: {wrong:#?}");
}
