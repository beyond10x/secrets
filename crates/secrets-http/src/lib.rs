use axum::{
    Json, Router,
    body::Body,
    extract::{FromRequest, FromRequestParts, Path, Request, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    middleware::map_response,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
};
use secrets_auth::{AuthError, Authority, Principal};
use secrets_core::{
    InvalidInput, Mutation, PutSecret, SecretMetadata, SecretRef, SecretStore, StoreError,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
};
use uuid::Uuid;

const COMMIT_TRANSACTION_ROUTE: &str =
    "/v1/workload/tenants/{tenant}/transactions/{transaction}/commit";
const ABORT_TRANSACTION_ROUTE: &str =
    "/v1/workload/tenants/{tenant}/transactions/{transaction}/abort";

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn SecretStore>,
    pub user_authority: Arc<dyn Authority>,
    pub workload_authority: Arc<dyn Authority>,
}

pub fn router(state: AppState) -> Router {
    routes().with_state(state)
}

fn routes() -> Router<AppState> {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/openapi.json", get(openapi))
        .route("/docs", get(docs))
        .route("/v1/user/secrets", get(user_list))
        .route("/v1/user/secrets:detail", post(user_detail))
        .route("/v1/user/secrets:revoke", post(user_revoke))
        .route("/v1/user/secrets", delete(user_delete))
        .route("/v1/workload/secrets", put(workload_put))
        .route("/v1/workload/secrets:get", post(workload_get))
        .route("/v1/workload/secrets:exists", post(workload_exists))
        .route("/v1/workload/secrets:list", post(workload_list))
        .route("/v1/workload/secrets:delete", post(workload_delete))
        .route(
            "/v1/workload/tenants/{tenant}/transactions/{transaction}",
            put(workload_prepare),
        )
        .route(COMMIT_TRANSACTION_ROUTE, post(workload_commit))
        .route(ABORT_TRANSACTION_ROUTE, post(workload_abort))
        .fallback(route_not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(map_response(shape_too_large))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

async fn live() -> StatusCode {
    StatusCode::NO_CONTENT
}
async fn ready(State(state): State<AppState>) -> StatusCode {
    if state.store.ready().await.is_ok() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn metrics() -> &'static str {
    "# HELP secrets_up Process availability.\n# TYPE secrets_up gauge\nsecrets_up 1\n"
}
async fn openapi() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        include_str!("../../../docs/openapi.json"),
    )
        .into_response()
}
async fn docs() -> Html<&'static str> {
    Html(include_str!("../../../docs/index.html"))
}

#[derive(Serialize)]
struct ListResponse {
    secrets: Vec<SecretMetadata>,
}
#[derive(Serialize)]
struct ExistsResponse {
    exists: bool,
}
#[derive(Deserialize)]
struct ScopeRequest {
    tenant: String,
    namespace: String,
}
#[derive(Deserialize)]
struct DeleteRequest {
    reference: SecretRef,
    #[serde(default)]
    actor: Option<String>,
}
#[derive(Deserialize)]
struct PrepareRequest {
    actor: String,
    mutations: Vec<Mutation>,
}

async fn user_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListResponse>, Refusal> {
    let principal = authorize(&headers, &*state.user_authority, "secret:list").await?;
    let secrets = state
        .store
        .list(&principal.tenant, Some(&principal.subject))
        .await?;
    Ok(Json(ListResponse { secrets }))
}
async fn user_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(reference): JsonBody<SecretRef>,
) -> Result<Json<SecretMetadata>, Refusal> {
    let principal = authorize_ref(
        &headers,
        &*state.user_authority,
        "secret:read_metadata",
        &reference,
    )
    .await?;
    let found = state
        .store
        .list(&principal.tenant, Some(&principal.subject))
        .await?
        .into_iter()
        .find(|m| m.reference == reference)
        .ok_or(Refusal::NotOwned)?;
    Ok(Json(found))
}
async fn user_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(reference): JsonBody<SecretRef>,
) -> Result<Json<SecretMetadata>, Refusal> {
    let principal = authorize_ref(
        &headers,
        &*state.user_authority,
        "secret:revoke",
        &reference,
    )
    .await?;
    assert_owner(&state, &principal, &reference).await?;
    Ok(Json(
        state.store.revoke(&reference, &principal.subject).await?,
    ))
}
async fn user_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(reference): JsonBody<SecretRef>,
) -> Result<StatusCode, Refusal> {
    let principal = authorize_ref(
        &headers,
        &*state.user_authority,
        "secret:delete",
        &reference,
    )
    .await?;
    assert_owner(&state, &principal, &reference).await?;
    state.store.delete(&reference, &principal.subject).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn workload_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(input): JsonBody<PutSecret>,
) -> Result<Json<SecretMetadata>, Refusal> {
    let principal = authorize_ref(
        &headers,
        &*state.workload_authority,
        "secret:write",
        &input.reference,
    )
    .await?;
    Ok(Json(
        state
            .store
            .put(PutSecret {
                owner_subject: if input.owner_subject.is_empty() {
                    principal.subject
                } else {
                    input.owner_subject
                },
                ..input
            })
            .await?,
    ))
}
async fn workload_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(reference): JsonBody<SecretRef>,
) -> Result<Json<secrets_core::StoredSecret>, Refusal> {
    authorize_ref(
        &headers,
        &*state.workload_authority,
        "secret:read_value",
        &reference,
    )
    .await?;
    Ok(Json(state.store.get(&reference).await?))
}
async fn workload_exists(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(reference): JsonBody<SecretRef>,
) -> Result<Json<ExistsResponse>, Refusal> {
    authorize_ref(
        &headers,
        &*state.workload_authority,
        "secret:read_metadata",
        &reference,
    )
    .await?;
    Ok(Json(ExistsResponse {
        exists: state.store.exists(&reference).await?,
    }))
}
async fn workload_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(scope): JsonBody<ScopeRequest>,
) -> Result<Json<ListResponse>, Refusal> {
    let principal = authorize(&headers, &*state.workload_authority, "secret:list").await?;
    tenant_match(&principal, &scope.tenant)?;
    let secrets = state
        .store
        .list(&scope.tenant, None)
        .await?
        .into_iter()
        .filter(|metadata| metadata.reference.namespace == scope.namespace)
        .collect();
    Ok(Json(ListResponse { secrets }))
}
async fn workload_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody<DeleteRequest>,
) -> Result<StatusCode, Refusal> {
    let principal = authorize_ref(
        &headers,
        &*state.workload_authority,
        "secret:delete",
        &request.reference,
    )
    .await?;
    state
        .store
        .delete(
            &request.reference,
            request.actor.as_deref().unwrap_or(&principal.subject),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn workload_prepare(
    State(state): State<AppState>,
    headers: HeaderMap,
    PathParams((tenant, transaction)): PathParams<(String, Uuid)>,
    JsonBody(request): JsonBody<PrepareRequest>,
) -> Result<StatusCode, Refusal> {
    let principal = authorize(&headers, &*state.workload_authority, "secret:prepare").await?;
    tenant_match(&principal, &tenant)?;
    state
        .store
        .prepare(&tenant, transaction, request.mutations, &request.actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn workload_commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    PathParams((tenant, transaction)): PathParams<(String, Uuid)>,
) -> Result<StatusCode, Refusal> {
    let principal = authorize(&headers, &*state.workload_authority, "secret:commit").await?;
    tenant_match(&principal, &tenant)?;
    state.store.commit(&tenant, transaction).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn workload_abort(
    State(state): State<AppState>,
    headers: HeaderMap,
    PathParams((tenant, transaction)): PathParams<(String, Uuid)>,
) -> Result<StatusCode, Refusal> {
    let principal = authorize(&headers, &*state.workload_authority, "secret:abort").await?;
    tenant_match(&principal, &tenant)?;
    state.store.abort(&tenant, transaction).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn assert_owner(
    state: &AppState,
    principal: &Principal,
    reference: &SecretRef,
) -> Result<(), Refusal> {
    let found = state
        .store
        .list(&principal.tenant, Some(&principal.subject))
        .await?
        .iter()
        .any(|m| &m.reference == reference);
    if found {
        Ok(())
    } else {
        Err(Refusal::NotOwned)
    }
}
async fn authorize_ref(
    headers: &HeaderMap,
    authority: &dyn Authority,
    action: &str,
    reference: &SecretRef,
) -> Result<Principal, Refusal> {
    let principal = authorize(headers, authority, action).await?;
    tenant_match(&principal, &reference.tenant)?;
    Ok(principal)
}
async fn authorize(
    headers: &HeaderMap,
    authority: &dyn Authority,
    action: &str,
) -> Result<Principal, Refusal> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Refusal::Unauthorized)?;
    let principal = authority.verify(token).await.map_err(Refusal::from)?;
    if !principal.permits(action) {
        return Err(Refusal::MissingAction);
    }
    Ok(principal)
}
fn tenant_match(principal: &Principal, tenant: &str) -> Result<(), Refusal> {
    if principal.tenant == tenant {
        Ok(())
    } else {
        Err(Refusal::Forbidden)
    }
}

/// Declares the closed set of refusals once, so the enum, its status, its code and the list the
/// OpenAPI document and the specification are checked against cannot drift apart.
macro_rules! refusals {
    ($($(#[doc = $doc:literal])* $variant:ident => $status:ident, $code:literal;)*) => {
        /// Every refusal the service answers. The body is `{"error": <status reason>, "code":
        /// <code>}` and nothing else: the reason is the status's canonical phrase and the code is
        /// the name of the outcome it is in `spec/domains/custody.yaml`, so neither carries any
        /// part of the request.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Refusal {
            $($(#[doc = $doc])* $variant,)*
        }
        impl Refusal {
            const ALL: &[Refusal] = &[$(Refusal::$variant,)*];
            fn status(self) -> StatusCode {
                match self {
                    $(Self::$variant => StatusCode::$status,)*
                }
            }
            fn code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code,)*
                }
            }
        }
    };
}

refusals! {
    /// No bearer token, or the authority refused it.
    Unauthorized => UNAUTHORIZED, "unauthorized";
    /// The principal's tenant is not the addressed tenant.
    Forbidden => FORBIDDEN, "forbidden";
    /// The principal lacks the route's action.
    MissingAction => FORBIDDEN, "missing-action";
    /// No record at the address.
    NotFound => NOT_FOUND, "not-found";
    /// A user route addresses a secret the caller does not own, or none at all.
    NotOwned => NOT_FOUND, "not-owned";
    /// A commit's Delete mutation names a reference with no secret.
    DeleteTargetMissing => NOT_FOUND, "delete-target-missing";
    /// A transaction with this id is already prepared in the tenant.
    Duplicate => CONFLICT, "duplicate";
    /// A reference part is empty or contains NUL.
    MalformedReference => BAD_REQUEST, "malformed-reference";
    /// A reference part is longer than 255 bytes.
    InvalidReference => BAD_REQUEST, "invalid-reference";
    /// A prepared batch has no mutation.
    EmptyBatch => BAD_REQUEST, "empty-batch";
    /// A prepared batch names a tenant other than the caller's.
    CrossTenantBatch => BAD_REQUEST, "cross-tenant-batch";
    /// The JSON body does not parse into the route's request type.
    MalformedBody => BAD_REQUEST, "malformed-body";
    /// A path parameter does not parse, such as a transaction id that is not a UUID.
    MalformedPath => BAD_REQUEST, "malformed-path";
    /// The request body is longer than 1 MiB.
    TooLarge => PAYLOAD_TOO_LARGE, "too-large";
    /// Storage, encryption or an authority is unavailable.
    Unavailable => SERVICE_UNAVAILABLE, "unavailable";
    /// No route has this path. A routing refusal, not an outcome of any command.
    RouteNotFound => NOT_FOUND, "route-not-found";
    /// A route has this path but not this method. A routing refusal, not an outcome of any command.
    MethodNotAllowed => METHOD_NOT_ALLOWED, "method-not-allowed";
}

/// Every code a refusal can carry, as it appears on the wire.
pub fn refusal_codes() -> impl Iterator<Item = &'static str> {
    Refusal::ALL.iter().map(|refusal| refusal.code())
}

/// The codes of the refusals the router answers before any route is chosen: an unknown path or a
/// method the path does not take. They are outcomes of no command; every other code is one.
pub fn routing_refusal_codes() -> impl Iterator<Item = &'static str> {
    [Refusal::RouteNotFound, Refusal::MethodNotAllowed]
        .into_iter()
        .map(Refusal::code)
}

async fn route_not_found() -> Refusal {
    Refusal::RouteNotFound
}
async fn method_not_allowed() -> Refusal {
    Refusal::MethodNotAllowed
}

impl From<StoreError> for Refusal {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::NotFound => Self::NotFound,
            StoreError::DeleteTargetMissing => Self::DeleteTargetMissing,
            StoreError::Conflict => Self::Duplicate,
            StoreError::Invalid(InvalidInput::MalformedReference) => Self::MalformedReference,
            StoreError::Invalid(InvalidInput::InvalidReference) => Self::InvalidReference,
            StoreError::Invalid(InvalidInput::EmptyBatch) => Self::EmptyBatch,
            StoreError::Invalid(InvalidInput::CrossTenantBatch) => Self::CrossTenantBatch,
            StoreError::Unavailable | StoreError::Crypto => Self::Unavailable,
        }
    }
}
impl From<AuthError> for Refusal {
    fn from(value: AuthError) -> Self {
        match value {
            AuthError::Unauthorized => Self::Unauthorized,
            AuthError::Unavailable => Self::Unavailable,
        }
    }
}
impl IntoResponse for Refusal {
    fn into_response(self) -> Response<Body> {
        let status = self.status();
        (
            status,
            Json(serde_json::json!({
                "error": status.canonical_reason().unwrap_or("request failed"),
                "code": self.code(),
            })),
        )
            .into_response()
    }
}

/// The body-limit layer answers `413` with its own plain-text body before any handler runs; this
/// gives that answer the refusal shape. Every other response passes through unchanged.
async fn shape_too_large(response: Response) -> Response {
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        Refusal::TooLarge.into_response()
    } else {
        response
    }
}

/// A JSON request body. A body that does not parse into `T` is refused as `malformed-body`, whose
/// response carries only the status reason and code: axum's own rejection text quotes the
/// offending input, and values never belong in errors. A body over the size limit is `too-large`.
struct JsonBody<T>(T);

impl<S: Send + Sync, T: serde::de::DeserializeOwned> FromRequest<S> for JsonBody<T> {
    type Rejection = Refusal;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                Err(Refusal::TooLarge)
            }
            Err(_) => Err(Refusal::MalformedBody),
        }
    }
}

/// Path parameters. A segment that does not parse is refused as `malformed-path`: axum's own
/// rejection text quotes the segment back.
struct PathParams<T>(T);

impl<S: Send + Sync, T: serde::de::DeserializeOwned + Send> FromRequestParts<S> for PathParams<T> {
    type Rejection = Refusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|_| Refusal::MalformedPath)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::{refusal_codes, routes};
    use std::collections::BTreeSet;

    #[test]
    fn production_routes_are_valid_axum_paths() {
        let _ = routes();
    }

    /// Codes are stable kebab-case identifiers, one per refusal.
    #[test]
    fn every_refusal_code_is_distinct_kebab_case() {
        let codes: Vec<&str> = refusal_codes().collect();
        let distinct: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(codes.len(), distinct.len(), "{codes:?}");
        for code in codes {
            let kebab = !code.is_empty()
                && !code.starts_with('-')
                && !code.ends_with('-')
                && !code.contains("--")
                && code.chars().all(|c| c.is_ascii_lowercase() || c == '-');
            assert!(kebab, "{code}");
        }
    }

    /// The OpenAPI document names exactly the codes the router can emit, and every API operation
    /// declares the refusal response.
    #[test]
    fn the_openapi_document_declares_every_refusal_code_on_every_operation() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/openapi.json")).unwrap();
        let schema = &doc["components"]["schemas"]["Error"];
        let declared: BTreeSet<&str> = schema["properties"]["code"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap())
            .collect();
        assert_eq!(declared, refusal_codes().collect::<BTreeSet<_>>());
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"], serde_json::json!(["error", "code"]));
        let mut undeclared = Vec::new();
        for (path, item) in doc["paths"].as_object().unwrap() {
            if !path.starts_with("/v1/") {
                continue;
            }
            for (method, operation) in item.as_object().unwrap() {
                if operation["responses"]["default"]["$ref"] != "#/components/responses/Error" {
                    undeclared.push(format!("{method} {path}"));
                }
            }
        }
        assert!(undeclared.is_empty(), "{undeclared:?}");
    }
}
