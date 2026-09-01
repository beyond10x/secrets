use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
};
use secrets_auth::{AuthError, Authority, Principal};
use secrets_core::{Mutation, PutSecret, SecretMetadata, SecretRef, SecretStore, StoreError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn SecretStore>,
    pub user_authority: Arc<dyn Authority>,
    pub workload_authority: Arc<dyn Authority>,
}

pub fn router(state: AppState) -> Router {
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
        .route(
            "/v1/workload/tenants/{tenant}/transactions/{transaction}:commit",
            post(workload_commit),
        )
        .route(
            "/v1/workload/tenants/{tenant}/transactions/{transaction}:abort",
            post(workload_abort),
        )
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .with_state(state)
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
) -> Result<Json<ListResponse>, ApiError> {
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
    Json(reference): Json<SecretRef>,
) -> Result<Json<SecretMetadata>, ApiError> {
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
        .ok_or(StoreError::NotFound)?;
    Ok(Json(found))
}
async fn user_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(reference): Json<SecretRef>,
) -> Result<Json<SecretMetadata>, ApiError> {
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
    Json(reference): Json<SecretRef>,
) -> Result<StatusCode, ApiError> {
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
    Json(input): Json<PutSecret>,
) -> Result<Json<SecretMetadata>, ApiError> {
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
    Json(reference): Json<SecretRef>,
) -> Result<Json<secrets_core::StoredSecret>, ApiError> {
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
    Json(reference): Json<SecretRef>,
) -> Result<Json<ExistsResponse>, ApiError> {
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
    Json(scope): Json<ScopeRequest>,
) -> Result<Json<ListResponse>, ApiError> {
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
    Json(request): Json<DeleteRequest>,
) -> Result<StatusCode, ApiError> {
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
    Path((tenant, transaction)): Path<(String, Uuid)>,
    Json(request): Json<PrepareRequest>,
) -> Result<StatusCode, ApiError> {
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
    Path((tenant, transaction)): Path<(String, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let principal = authorize(&headers, &*state.workload_authority, "secret:commit").await?;
    tenant_match(&principal, &tenant)?;
    state.store.commit(&tenant, transaction).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn workload_abort(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant, transaction)): Path<(String, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let principal = authorize(&headers, &*state.workload_authority, "secret:abort").await?;
    tenant_match(&principal, &tenant)?;
    state.store.abort(&tenant, transaction).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn assert_owner(
    state: &AppState,
    principal: &Principal,
    reference: &SecretRef,
) -> Result<(), ApiError> {
    let found = state
        .store
        .list(&principal.tenant, Some(&principal.subject))
        .await?
        .iter()
        .any(|m| &m.reference == reference);
    if found {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}
async fn authorize_ref(
    headers: &HeaderMap,
    authority: &dyn Authority,
    action: &str,
    reference: &SecretRef,
) -> Result<Principal, ApiError> {
    let principal = authorize(headers, authority, action).await?;
    tenant_match(&principal, &reference.tenant)?;
    Ok(principal)
}
async fn authorize(
    headers: &HeaderMap,
    authority: &dyn Authority,
    action: &str,
) -> Result<Principal, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let principal = authority.verify(token).await.map_err(ApiError::Auth)?;
    if !principal.permits(action) {
        return Err(ApiError::Forbidden);
    }
    Ok(principal)
}
fn tenant_match(principal: &Principal, tenant: &str) -> Result<(), ApiError> {
    if principal.tenant == tenant {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Invalid,
    Unavailable,
    Auth(AuthError),
}
impl From<StoreError> for ApiError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::NotFound => Self::NotFound,
            StoreError::Conflict => Self::Conflict,
            StoreError::Invalid(_) => Self::Invalid,
            StoreError::Unavailable | StoreError::Crypto => Self::Unavailable,
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response<Body> {
        let status = match self {
            Self::Unauthorized | Self::Auth(AuthError::Unauthorized) => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Unavailable | Self::Auth(AuthError::Unavailable) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        (
            status,
            Json(
                serde_json::json!({"error": status.canonical_reason().unwrap_or("request failed")}),
            ),
        )
            .into_response()
    }
}
