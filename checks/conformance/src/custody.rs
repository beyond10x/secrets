//! `secrets.custody` against the shipped router (`secrets_http::router`) and store
//! (`secrets_postgres::PostgresStore`), in the scenario's own database.
//!
//! # How an outcome is reached
//!
//! Every command goes to the real handler as an HTTP request, and the declared branch is read off
//! what the service answered: the status, the body, and the rows it wrote. The adapter never
//! decides a branch; it only arranges the world the branch is answered in.
//!
//! The retrofit declares most refusals `external:` because their conditions (a missing token, a
//! lost database, a batch that does not open) are not decided by the input. The arrangement is:
//!
//! * **Unforced**, no declared refusal's condition holds: the caller is a principal of the
//!   addressed tenant holding the actor's actions, storage is reachable, the body is within the
//!   limit, and a command that addresses an existing record (revoke, delete, commit, abort, rewrap)
//!   finds one — the adapter stores it through the shipped store first when the scenario has not.
//! * **Forced**, exactly the named condition is made true on top of that: an unregistered token
//!   (`unauthorized`), a principal of another tenant (`forbidden`), the scenario database refusing
//!   connections (`unavailable`), a body padded past 1 MiB with JSON whitespace (`too-large`), a
//!   caller who is not the owner (`not-owned`), a batch already prepared (`duplicate`), and so on.
//!
//! A request carries the scenario's input as given. The one request field that is not input is a
//! prepare's path tenant: the specification models it as the caller's tenant
//! (`PrepareTransaction` in `spec/domains/custody.yaml`), so it is chosen with the caller — the
//! tenant the batch's mutations name, or, when `cross-tenant-batch` is forced, a tenant none of them
//! names.
//!
//! # Events
//!
//! The service publishes nothing (`spec/domains/custody.yaml` header). Each declared event is read
//! from the durable record the command wrote: an `audit_events` row for put, revoke, delete,
//! commit and rewrap, and the prepared row's presence or absence for prepare and abort.
use std::collections::BTreeMap;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ess_conformance::target::{TargetError, ViewRow};
use ess_primitives::{facts::Number, node::Node};
use http_body_util::BodyExt as _;
use secrets_core::{
    Disclosure, Mutation, PutSecret, SecretBytes, SecretMetadata, SecretRef, SecretState,
    SecretStore as _, StoredSecret,
};
use secrets_crypto::Keyring;
use secrets_postgres::PostgresStore;
use serde_json::{Value, json};
use sqlx::Row as _;
use std::sync::Arc;
use tower::ServiceExt as _;
use uuid::Uuid;

use crate::fixture::{Audience, FOREIGN_RING, ROTATED_RING};
use crate::target::{Caller, Context, Domain, Observed, unavailable};

pub const DOMAIN: Domain = Domain { command, view };

// The one action each route authorizes, as `spec/domains/custody.yaml` states it beside each command
// and view. A principal holds exactly that action and no other, so a route that authorizes the
// wrong action is refused rather than let through by a broader grant.
const WRITE: &str = "secret:write";
const REVOKE: &str = "secret:revoke";
const DELETE: &str = "secret:delete";
const PREPARE: &str = "secret:prepare";
const COMMIT: &str = "secret:commit";
const ABORT: &str = "secret:abort";
const LIST: &str = "secret:list";
const READ_METADATA: &str = "secret:read_metadata";
const READ_VALUE: &str = "secret:read_value";
/// Every action a workload or user grant can hold (crates/secrets-http/src/lib.rs, each handler's
/// `authorize`), for the partial grant a forced `missing-action` holds.
const WORKLOAD_ACTIONS: &[&str] = &[
    WRITE,
    READ_VALUE,
    READ_METADATA,
    LIST,
    DELETE,
    PREPARE,
    COMMIT,
    ABORT,
];
const USER_ACTIONS: &[&str] = &[LIST, READ_METADATA, REVOKE, DELETE];
const WORKLOAD_SUBJECT: &str = "system:serviceaccount:fixture:workload";
const FIXTURE_OWNER: &str = "fixture-owner";
const OTHER_SUBJECT: &str = "fixture-other-subject";
const OTHER_TENANT: &str = "fixture-other-tenant";
const CALLER_TENANT: &str = "fixture-caller-tenant";
const UNREGISTERED_TOKEN: &str = "fixture-unregistered-token";
const FIXTURE_NAMESPACE: &str = "fixture";
/// The request body limit, restated rather than imported so a change to the service's bound is
/// something this adapter notices instead of follows.
const BODY_LIMIT: usize = 1024 * 1024;

type R<T> = Result<T, TargetError>;

fn failed(operation: &'static str) -> impl Fn(Box<dyn std::error::Error>) -> TargetError {
    move |error| unavailable(operation, error)
}
fn sql(operation: &'static str) -> impl Fn(sqlx::Error) -> TargetError {
    move |error| unavailable(operation, error)
}
fn json_error(operation: &'static str) -> impl Fn(serde_json::Error) -> TargetError {
    move |error| unavailable(operation, error)
}

fn command(
    context: &mut Context<'_>,
    command: &str,
    input: &BTreeMap<String, Node>,
) -> Option<R<Observed>> {
    let input = match wire(input) {
        Ok(input) => input,
        Err(error) => return Some(Err(error)),
    };
    let surface = match command {
        "secrets.custody.RevokeOwnedSecret" | "secrets.custody.DeleteOwnedSecret" => {
            Surface::Http(Audience::User)
        }
        "secrets.custody.RewrapSecrets" => Surface::Rewrap,
        _ => Surface::Http(Audience::Workload),
    };
    context.caller = match caller(context.actor.as_deref(), surface) {
        Ok(caller) => caller,
        Err(error) => return Some(Err(error)),
    };
    let observed = match command {
        "secrets.custody.PutSecret" => put(context, input),
        "secrets.custody.RevokeOwnedSecret" => revoke(context, &input),
        "secrets.custody.DeleteOwnedSecret" => delete_owned(context, &input),
        "secrets.custody.DeleteSecret" => delete(context, input),
        "secrets.custody.PrepareTransaction" => prepare(context, &input),
        "secrets.custody.CommitTransaction" => commit(context, &input),
        "secrets.custody.AbortTransaction" => abort(context, &input),
        "secrets.custody.RewrapSecrets" => rewrap(context, &input),
        "secrets.custody.ReadSecretValue" => read_value(context, &input),
        "secrets.custody.CheckSecretExists" => check_exists(context, &input),
        "secrets.custody.ListNamespaceSecrets" => list_namespace(context, &input),
        _ => return None,
    };
    Some(match (context.caller, observed) {
        (Caller::Granted, observed) => observed,
        // Sent with a credential the serving surface does not accept: the authority refused it
        // before the command ran, which is the refusal for an actor no grant admits.
        (
            _,
            Ok(Observed {
                response: None,
                error: Some("secrets.custody.Unauthorized" | "secrets.custody.Forbidden"),
                ..
            }),
        ) => Err(TargetError::not_granted(context.actor.clone())),
        (_, observed) => observed,
    })
}

/// Where a command is served: an HTTP route behind one authority, or the `secrets rewrap` binary.
#[derive(Clone, Copy)]
enum Surface {
    Http(Audience),
    Rewrap,
}

/// The credential `actor` holds for `surface`. A user holds an Identity token, a workload a
/// Kubernetes service-account token, and the operator the database URL and keyring file
/// (`crates/secrets-app/src/main.rs`), which no HTTP route accepts.
fn caller(actor: Option<&str>, surface: Surface) -> R<Caller> {
    let held = match actor {
        None => return Ok(Caller::Granted),
        Some("secrets.custody.User") => Some(Audience::User),
        Some("secrets.custody.Workload") => Some(Audience::Workload),
        Some("secrets.custody.Operator") => None,
        Some(other) => {
            return Err(TargetError::unsupported(
                format!("sending a command as `{other}`"),
                "the service knows users, workloads and the operator only",
            ));
        }
    };
    Ok(match (surface, held) {
        (Surface::Http(Audience::User), Some(Audience::User))
        | (Surface::Http(Audience::Workload), Some(Audience::Workload))
        | (Surface::Rewrap, None) => Caller::Granted,
        (Surface::Http(_), None) => Caller::Bearerless,
        (Surface::Http(_), Some(audience)) => Caller::Holding(audience),
        // No route runs a rewrap (crates/secrets-http/src/lib.rs `router`); it needs the database
        // URL and the keyring file, which neither token carries.
        (Surface::Rewrap, Some(_)) => {
            return Err(TargetError::not_granted(actor.map(ToOwned::to_owned)));
        }
    })
}

fn view(context: &mut Context<'_>, view: &str) -> Option<R<Vec<ViewRow>>> {
    Some(match view {
        "secrets.custody.NamespaceSecrets" => namespace_secrets(context),
        "secrets.custody.OwnedSecrets" => owned_secrets(context),
        "secrets.custody.OwnedSecretDetail" => owned_secret_detail(context),
        "secrets.custody.SecretValue" => secret_value(context),
        "secrets.custody.ActiveSecrets" => active_secrets(context),
        _ => return None,
    })
}

// ---- the wire -------------------------------------------------------------------------------

/// The input as the service's JSON: absent optionals omitted, and each `Mutation` union written
/// as serde's internally tagged `{"op": …, <fields>}` rather than ESS's `{"op": …, "value": …}`.
fn wire(input: &BTreeMap<String, Node>) -> R<Value> {
    fn strip(value: Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .filter(|(_, value)| !value.is_null())
                    .map(|(key, value)| (key, strip(value)))
                    .collect(),
            ),
            Value::Array(items) => Value::Array(items.into_iter().map(strip).collect()),
            other => other,
        }
    }
    let mut value = strip(serde_json::to_value(input).map_err(json_error("encoding the input"))?);
    if let Some(Value::Array(mutations)) = value.get_mut("mutations") {
        for mutation in mutations {
            if let Some(Value::Object(fields)) =
                mutation.as_object_mut().and_then(|m| m.remove("value"))
                && let Some(object) = mutation.as_object_mut()
            {
                object.extend(fields);
            }
        }
    }
    Ok(value)
}

fn field<T: serde::de::DeserializeOwned>(input: &Value, name: &str) -> R<T> {
    serde_json::from_value(input.get(name).cloned().unwrap_or(Value::Null))
        .map_err(|error| unavailable("reading the command input", format!("{name}: {error}")))
}

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

impl Reply {
    fn json<T: serde::de::DeserializeOwned>(&self) -> R<T> {
        serde_json::from_slice(&self.body).map_err(json_error("reading the service response"))
    }
}

fn call(
    context: &mut Context<'_>,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
) -> R<Reply> {
    let router = context.scenario.router.clone();
    let token = match context.caller {
        Caller::Bearerless => None,
        Caller::Granted | Caller::Holding(_) => token,
    };
    context.runtime.block_on(async move {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(bytes) => {
                request = request
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, bytes.len());
                Body::from(bytes)
            }
            None => Body::empty(),
        };
        let request = request
            .body(body)
            .map_err(|error| unavailable("building the request", error))?;
        let response = router
            .oneshot(request)
            .await
            .map_err(|error| unavailable("calling the router", error))?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| unavailable("reading the response body", error))?
            .to_bytes()
            .to_vec();
        Ok(Reply { status, body })
    })
}

/// A body for `value`, padded with trailing JSON whitespace past the limit when the scenario forced
/// `too-large`. The padded document still parses to the same value.
fn body(context: &Context<'_>, value: &Value) -> R<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(json_error("encoding the request"))?;
    match context.forced.as_deref() {
        Some("too-large") => bytes.resize(BODY_LIMIT + 1, b' '),
        // The input's own encoding without its closing brace: JSON that does not parse.
        Some("malformed-body") => {
            bytes.pop();
        }
        _ => {}
    }
    Ok(bytes)
}

/// The bearer token for this call: unregistered when `unauthorized` is forced, another tenant's
/// principal when `forbidden` is, a principal of `tenant` holding every other action of its actor
/// when `missing-action` is, and otherwise a principal of `tenant` holding only `action`.
fn token(
    context: &mut Context<'_>,
    audience: Audience,
    subject: &str,
    tenant: &str,
    action: &str,
) -> R<String> {
    let actions = &[action];
    let audience = match context.caller {
        Caller::Holding(held) => held,
        Caller::Granted | Caller::Bearerless => audience,
    };
    match context.forced.as_deref() {
        Some("unauthorized") => Ok(UNREGISTERED_TOKEN.to_owned()),
        Some("missing-action") => {
            let granted = match audience {
                Audience::User => USER_ACTIONS,
                Audience::Workload => WORKLOAD_ACTIONS,
            };
            let others: Vec<&str> = granted
                .iter()
                .copied()
                .filter(|granted| *granted != action)
                .collect();
            context
                .scenario
                .token(audience, subject, tenant, &others)
                .map_err(failed("registering a principal"))
        }
        Some("forbidden") => context
            .scenario
            .token(audience, subject, OTHER_TENANT, actions)
            .map_err(failed("registering a principal")),
        _ => context
            .scenario
            .token(audience, subject, tenant, actions)
            .map_err(failed("registering a principal")),
    }
}

/// Sends the request, with the scenario database refusing connections for its duration when the
/// scenario forced `unavailable` and `storage_down` says that is how this command reaches it.
fn send(
    context: &mut Context<'_>,
    storage_down: bool,
    method: Method,
    path: &str,
    token: &str,
    body: Option<Vec<u8>>,
) -> R<Reply> {
    let down = storage_down && context.forced.as_deref() == Some("unavailable");
    if down {
        context
            .runtime
            .block_on(context.admin.take_down(context.scenario))
            .map_err(failed("taking the scenario database down"))?;
    }
    let reply = call(context, method, path, Some(token), body);
    if down {
        context
            .runtime
            .block_on(context.admin.bring_up(context.scenario))
            .map_err(failed("bringing the scenario database back"))?;
    }
    reply
}

/// A refusal as the service answered it: the declared error its status carries, and the declared
/// outcome its `code` names. Every refusal body is exactly
/// `{"error": <status reason>, "code": <outcome name>}` (crates/secrets-http/src/lib.rs `Refusal`),
/// and the branch is read from that body alone — never from what this adapter sent or forced.
fn refusal(reply: &Reply) -> R<Option<(&'static str, String)>> {
    let error = match reply.status {
        StatusCode::BAD_REQUEST => "secrets.custody.InvalidInput",
        StatusCode::UNAUTHORIZED => "secrets.custody.Unauthorized",
        StatusCode::FORBIDDEN => "secrets.custody.Forbidden",
        StatusCode::NOT_FOUND => "secrets.custody.NotFound",
        StatusCode::CONFLICT => "secrets.custody.Conflict",
        StatusCode::SERVICE_UNAVAILABLE => "secrets.custody.Unavailable",
        StatusCode::PAYLOAD_TOO_LARGE => "secrets.custody.PayloadTooLarge",
        _ => return Ok(None),
    };
    let shaped = reply.json::<Value>().ok().and_then(|body| {
        let object = body.as_object()?;
        let reason = object.get("error")?.as_str()?;
        let code = object.get("code")?.as_str()?;
        (object.len() == 2 && Some(reason) == reply.status.canonical_reason())
            .then(|| code.to_owned())
    });
    let Some(code) = shaped else {
        return Err(unavailable(
            "reading a refusal",
            format!(
                "status {} did not carry exactly {{\"error\": {:?}, \"code\": <code>}}: {}",
                reply.status,
                reply.status.canonical_reason().unwrap_or_default(),
                String::from_utf8_lossy(&reply.body)
            ),
        ));
    };
    Ok(Some((error, code)))
}

/// The declared branch a refusal took: the outcome its code names, carrying the error its status
/// is. A status that is no declared refusal is an undeclared branch.
fn refused(reply: &Reply) -> R<Observed> {
    Ok(match refusal(reply)? {
        Some((error, code)) => Observed {
            response: None,
            outcome: Some(code),
            error: Some(error),
            events: Vec::new(),
        },
        None => Observed {
            response: None,
            outcome: None,
            error: None,
            events: Vec::new(),
        },
    })
}

// ---- durable records ------------------------------------------------------------------------

struct Audit {
    tenant: String,
    secret: Option<Uuid>,
    actor: String,
    action: String,
}

fn audit_mark(context: &Context<'_>) -> R<i64> {
    context.runtime.block_on(async {
        sqlx::query_scalar::<_, i64>("SELECT coalesce(max(sequence), 0) FROM audit_events")
            .fetch_one(&context.scenario.observer)
            .await
            .map_err(sql("reading the audit position"))
    })
}

fn audit_since(context: &Context<'_>, mark: i64) -> R<Vec<Audit>> {
    context.runtime.block_on(async {
        let rows = sqlx::query(
            "SELECT tenant, secret_id, actor, action FROM audit_events WHERE sequence > $1 ORDER BY sequence",
        )
        .bind(mark)
        .fetch_all(&context.scenario.observer)
        .await
        .map_err(sql("reading audit records"))?;
        rows.iter()
            .map(|row| {
                Ok(Audit {
                    tenant: row.try_get("tenant")?,
                    secret: row.try_get("secret_id")?,
                    actor: row.try_get("actor")?,
                    action: row.try_get("action")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(sql("reading audit records"))
    })
}

/// The id and owner of the secret stored at `reference`, if one is.
fn stored(context: &Context<'_>, reference: &SecretRef) -> R<Option<(Uuid, String)>> {
    context.runtime.block_on(async {
        let row = sqlx::query(
            "SELECT id, owner_subject FROM secrets WHERE tenant=$1 AND namespace=$2 AND secret_key=$3",
        )
        .bind(&reference.tenant)
        .bind(&reference.namespace)
        .bind(&reference.key)
        .fetch_optional(&context.scenario.observer)
        .await
        .map_err(sql("reading a stored secret"))?;
        row.map(|row| Ok((row.try_get("id")?, row.try_get("owner_subject")?)))
            .transpose()
            .map_err(sql("reading a stored secret"))
    })
}

fn prepared(context: &Context<'_>, tenant: &str, transaction: Uuid) -> R<bool> {
    context.runtime.block_on(async {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM prepared_transactions WHERE tenant=$1 AND id=$2)",
        )
        .bind(tenant)
        .bind(transaction)
        .fetch_one(&context.scenario.observer)
        .await
        .map_err(sql("reading a prepared batch"))
    })
}

fn cannot_arrange(what: &str) -> TargetError {
    TargetError::unavailable("arranging the forced outcome", what)
}

fn fixture_put(reference: SecretRef, owner: &str) -> PutSecret {
    PutSecret {
        reference,
        owner_subject: owner.to_owned(),
        value: SecretBytes(b"fixture".to_vec()),
        disclosure: Disclosure::WorkloadOnly,
        labels: BTreeMap::new(),
    }
}

/// Stores a secret at `reference` through the shipped store, returning its owner.
fn arrange_secret(context: &mut Context<'_>, reference: &SecretRef) -> R<String> {
    if let Some((_, owner)) = stored(context, reference)? {
        return Ok(owner);
    }
    let store = context.scenario.store.clone();
    context
        .runtime
        .block_on(store.put(fixture_put(reference.clone(), FIXTURE_OWNER)))
        .map_err(|error| unavailable("arranging a stored secret", error))?;
    context.scenario.owners.insert(FIXTURE_OWNER.to_owned());
    Ok(FIXTURE_OWNER.to_owned())
}

fn arrange_batch(
    context: &Context<'_>,
    tenant: &str,
    transaction: Uuid,
    mutations: Vec<Mutation>,
) -> R<()> {
    context
        .runtime
        .block_on(
            context
                .scenario
                .store
                .prepare(tenant, transaction, mutations, "fixture-actor"),
        )
        .map_err(|error| unavailable("arranging a prepared batch", error))
}

fn in_tenant(tenant: &str, key: &str) -> SecretRef {
    SecretRef {
        tenant: tenant.to_owned(),
        namespace: FIXTURE_NAMESPACE.to_owned(),
        key: key.to_owned(),
    }
}

fn touch(context: &mut Context<'_>, reference: &SecretRef) {
    context.scenario.references.insert((
        reference.tenant.clone(),
        reference.namespace.clone(),
        reference.key.clone(),
    ));
}

// ---- nodes ----------------------------------------------------------------------------------

fn text(value: impl Into<String>) -> Node {
    Node::Text(value.into())
}
fn reference_node(reference: &SecretRef) -> Node {
    Node::Map(BTreeMap::from([
        ("tenant".to_owned(), text(&reference.tenant)),
        ("namespace".to_owned(), text(&reference.namespace)),
        ("key".to_owned(), text(&reference.key)),
    ]))
}
fn metadata_row(metadata: &SecretMetadata) -> R<ViewRow> {
    let disclosure = serde_json::to_value(metadata.disclosure)
        .map_err(json_error("encoding a disclosure"))?
        .as_str()
        .map(text)
        .ok_or_else(|| unavailable("encoding a disclosure", "not a string"))?;
    Ok(BTreeMap::from([
        ("id".to_owned(), text(metadata.id.to_string())),
        ("reference".to_owned(), reference_node(&metadata.reference)),
        ("owner_subject".to_owned(), text(&metadata.owner_subject)),
        ("disclosure".to_owned(), disclosure),
        (
            "state".to_owned(),
            text(match metadata.state {
                SecretState::Active => "Active",
                SecretState::Revoked => "Revoked",
            }),
        ),
        (
            "version".to_owned(),
            Node::Number(Number::from(metadata.version)),
        ),
        (
            "labels".to_owned(),
            Node::Map(
                metadata
                    .labels
                    .iter()
                    .map(|(key, value)| (key.clone(), text(value)))
                    .collect(),
            ),
        ),
        ("created_at".to_owned(), text(&metadata.created_at)),
        ("updated_at".to_owned(), text(&metadata.updated_at)),
    ]))
}

// ---- commands -------------------------------------------------------------------------------

// PUT /v1/workload/secrets (crates/secrets-http/src/lib.rs `workload_put`).
fn put(context: &mut Context<'_>, input: Value) -> R<Observed> {
    let reference: SecretRef = field(&input, "reference")?;
    touch(context, &reference);
    if let Some(owner) = input.get("owner_subject").and_then(Value::as_str)
        && !owner.is_empty()
    {
        context.scenario.owners.insert(owner.to_owned());
    }
    if context.forced.as_deref() == Some("created") && stored(context, &reference)?.is_some() {
        return Err(cannot_arrange(
            "a secret is already stored at the reference",
        ));
    }
    let token = token(
        context,
        Audience::Workload,
        WORKLOAD_SUBJECT,
        &reference.tenant,
        WRITE,
    )?;
    let body = body(context, &input)?;
    let mark = audit_mark(context)?;
    let reply = send(
        context,
        true,
        Method::PUT,
        "/v1/workload/secrets",
        &token,
        Some(body),
    )?;
    if reply.status != StatusCode::OK {
        return refused(&reply);
    }
    let metadata: SecretMetadata = reply.json()?;
    context
        .scenario
        .owners
        .insert(metadata.owner_subject.clone());
    let events = audit_since(context, mark)?
        .into_iter()
        .filter(|row| row.action == "put" && row.secret == Some(metadata.id))
        .map(|_| {
            (
                "secrets.custody.SecretPut",
                BTreeMap::from([
                    ("reference".to_owned(), reference_node(&metadata.reference)),
                    ("owner_subject".to_owned(), text(&metadata.owner_subject)),
                ]),
            )
        })
        .collect();
    Ok(Observed {
        response: None,
        outcome: Some(
            if metadata.version == 1 {
                "created"
            } else {
                "replaced"
            }
            .to_owned(),
        ),
        error: None,
        events,
    })
}

/// The caller of a user route: the stored owner, or another subject when `not-owned` is forced.
/// A secret is stored first when the scenario has none at the reference.
fn owner_caller(context: &mut Context<'_>, reference: &SecretRef) -> R<String> {
    let owner = arrange_secret(context, reference)?;
    context.scenario.owners.insert(owner.clone());
    Ok(if context.forced.as_deref() == Some("not-owned") {
        OTHER_SUBJECT.to_owned()
    } else {
        owner
    })
}

// POST /v1/user/secrets:revoke (crates/secrets-http/src/lib.rs `user_revoke`).
fn revoke(context: &mut Context<'_>, input: &Value) -> R<Observed> {
    let reference: SecretRef = field(input, "reference")?;
    touch(context, &reference);
    let caller = owner_caller(context, &reference)?;
    let token = token(context, Audience::User, &caller, &reference.tenant, REVOKE)?;
    let body = body(context, &json!(reference))?;
    let mark = audit_mark(context)?;
    let reply = send(
        context,
        true,
        Method::POST,
        "/v1/user/secrets:revoke",
        &token,
        Some(body),
    )?;
    if reply.status != StatusCode::OK {
        return refused(&reply);
    }
    let metadata: SecretMetadata = reply.json()?;
    let events = audit_since(context, mark)?
        .into_iter()
        .filter(|row| row.action == "revoke" && row.secret == Some(metadata.id))
        .map(|_| {
            (
                "secrets.custody.SecretRevoked",
                BTreeMap::from([("reference".to_owned(), reference_node(&metadata.reference))]),
            )
        })
        .collect();
    Ok(Observed {
        response: None,
        outcome: Some("revoked".to_owned()),
        error: None,
        events,
    })
}

/// A `SecretDeleted` for each `delete` record naming the secret that was stored at `reference`.
fn deleted(
    context: &Context<'_>,
    mark: i64,
    before: Option<Uuid>,
    reference: &SecretRef,
) -> R<Observed> {
    let events = audit_since(context, mark)?
        .into_iter()
        .filter(|row| row.action == "delete" && row.secret.is_some() && row.secret == before)
        .map(|_| {
            (
                "secrets.custody.SecretDeleted",
                BTreeMap::from([("reference".to_owned(), reference_node(reference))]),
            )
        })
        .collect();
    Ok(Observed {
        response: None,
        outcome: Some("deleted".to_owned()),
        error: None,
        events,
    })
}

// DELETE /v1/user/secrets (crates/secrets-http/src/lib.rs `user_delete`).
fn delete_owned(context: &mut Context<'_>, input: &Value) -> R<Observed> {
    let reference: SecretRef = field(input, "reference")?;
    touch(context, &reference);
    let caller = owner_caller(context, &reference)?;
    let token = token(context, Audience::User, &caller, &reference.tenant, DELETE)?;
    let body = body(context, &json!(reference))?;
    let before = stored(context, &reference)?.map(|(id, _)| id);
    let mark = audit_mark(context)?;
    let reply = send(
        context,
        true,
        Method::DELETE,
        "/v1/user/secrets",
        &token,
        Some(body),
    )?;
    if reply.status != StatusCode::NO_CONTENT {
        return refused(&reply);
    }
    deleted(context, mark, before, &reference)
}

// POST /v1/workload/secrets:delete (crates/secrets-http/src/lib.rs `workload_delete`).
fn delete(context: &mut Context<'_>, input: Value) -> R<Observed> {
    let reference: SecretRef = field(&input, "reference")?;
    touch(context, &reference);
    if context.forced.as_deref() == Some("not-found") {
        if stored(context, &reference)?.is_some() {
            return Err(cannot_arrange("a secret is stored at the reference"));
        }
    } else {
        arrange_secret(context, &reference)?;
    }
    let token = token(
        context,
        Audience::Workload,
        WORKLOAD_SUBJECT,
        &reference.tenant,
        DELETE,
    )?;
    let body = body(context, &input)?;
    let before = stored(context, &reference)?.map(|(id, _)| id);
    let mark = audit_mark(context)?;
    let reply = send(
        context,
        true,
        Method::POST,
        "/v1/workload/secrets:delete",
        &token,
        Some(body),
    )?;
    if reply.status != StatusCode::NO_CONTENT {
        return refused(&reply);
    }
    deleted(context, mark, before, &reference)
}

fn transaction_input(input: &Value) -> R<(String, Uuid)> {
    Ok((field(input, "tenant")?, field(input, "transaction")?))
}

/// The route of a transaction; its id segment is not a UUID when the scenario forced
/// `malformed-path`.
fn transaction_path(context: &Context<'_>, tenant: &str, transaction: Uuid, verb: &str) -> String {
    let segment = if context.forced.as_deref() == Some("malformed-path") {
        "not-a-transaction".to_owned()
    } else {
        transaction.to_string()
    };
    format!("/v1/workload/tenants/{tenant}/transactions/{segment}{verb}")
}

fn transaction_payload(tenant: &str, transaction: Uuid) -> BTreeMap<String, Node> {
    BTreeMap::from([
        ("tenant".to_owned(), text(tenant)),
        ("transaction".to_owned(), text(transaction.to_string())),
    ])
}

// PUT /v1/workload/tenants/{tenant}/transactions/{transaction}
// (crates/secrets-http/src/lib.rs `workload_prepare`). The path tenant is the caller's, which the
// specification leaves outside the input: the tenant the batch names, or, when
// `cross-tenant-batch` is forced, one it does not name.
fn prepare(context: &mut Context<'_>, input: &Value) -> R<Observed> {
    let transaction: Uuid = field(input, "transaction")?;
    let actor: Value = field(input, "actor")?;
    let batch: Value = field(input, "mutations")?;
    let mutations: Vec<Mutation> = field(input, "mutations")?;
    let named: std::collections::BTreeSet<String> = mutations
        .iter()
        .map(|mutation| match mutation {
            Mutation::Put { secret } => secret.reference.tenant.clone(),
            Mutation::Delete { reference } => reference.tenant.clone(),
        })
        .collect();
    let tenant = if context.forced.as_deref() == Some("cross-tenant-batch") {
        let mut tenant = CALLER_TENANT.to_owned();
        while named.contains(&tenant) {
            tenant.push_str("-other");
        }
        tenant
    } else {
        match named.len() {
            0 => CALLER_TENANT.to_owned(),
            1 => named.iter().next().cloned().unwrap_or_default(),
            _ => {
                return Err(cannot_arrange(
                    "the batch names more than one tenant, so no caller's tenant holds all of it",
                ));
            }
        }
    };
    for mutation in &mutations {
        if let Mutation::Put { secret } = mutation {
            touch(context, &secret.reference);
            context.scenario.owners.insert(secret.owner_subject.clone());
        }
    }
    // A batch an earlier step of the scenario prepared already makes the condition true.
    if context.forced.as_deref() == Some("duplicate") && !prepared(context, &tenant, transaction)? {
        arrange_batch(context, &tenant, transaction, mutations.clone())?;
    }
    let token = token(
        context,
        Audience::Workload,
        WORKLOAD_SUBJECT,
        &tenant,
        PREPARE,
    )?;
    let body = body(context, &json!({"actor": actor, "mutations": batch}))?;
    let path = transaction_path(context, &tenant, transaction, "");
    let reply = send(context, true, Method::PUT, &path, &token, Some(body))?;
    if reply.status != StatusCode::NO_CONTENT {
        return refused(&reply);
    }
    if !prepared(context, &tenant, transaction)? {
        return Err(unavailable(
            "observing a prepared batch",
            "the service answered 204 and holds no batch",
        ));
    }
    Ok(Observed {
        response: None,
        outcome: Some("prepared".to_owned()),
        error: None,
        events: vec![(
            "secrets.custody.TransactionPrepared",
            transaction_payload(&tenant, transaction),
        )],
    })
}

// POST .../transactions/{transaction}/commit (crates/secrets-http/src/lib.rs `workload_commit`).
fn commit(context: &mut Context<'_>, input: &Value) -> R<Observed> {
    let (tenant, transaction) = transaction_input(input)?;
    let exists = prepared(context, &tenant, transaction)?;
    let forced = context.forced.clone();
    let arranged = match forced.as_deref() {
        Some("not-found") => None,
        Some("delete-target-missing") => Some(vec![Mutation::Delete {
            reference: in_tenant(&tenant, "missing"),
        }]),
        Some("malformed-reference") => Some(vec![Mutation::Put {
            secret: fixture_put(in_tenant(&tenant, ""), FIXTURE_OWNER),
        }]),
        Some("invalid-reference") => Some(vec![Mutation::Put {
            secret: fixture_put(in_tenant(&tenant, &"k".repeat(256)), FIXTURE_OWNER),
        }]),
        _ if exists => None,
        _ => Some(vec![Mutation::Put {
            secret: fixture_put(in_tenant(&tenant, "committed"), FIXTURE_OWNER),
        }]),
    };
    if exists
        && matches!(
            forced.as_deref(),
            Some(
                "not-found" | "delete-target-missing" | "malformed-reference" | "invalid-reference"
            )
        )
    {
        return Err(cannot_arrange("a batch is already prepared under this id"));
    }
    if let Some(batch) = arranged {
        arrange_batch(context, &tenant, transaction, batch)?;
    }
    if forced.as_deref() == Some("unavailable") {
        // The batch no longer opens under the actor it was sealed for.
        context.runtime.block_on(async {
            sqlx::query("UPDATE prepared_transactions SET actor = actor || '-altered' WHERE tenant=$1 AND id=$2")
                .bind(&tenant)
                .bind(transaction)
                .execute(&context.scenario.observer)
                .await
                .map_err(sql("altering a prepared batch"))
        })?;
    }
    let token = token(
        context,
        Audience::Workload,
        WORKLOAD_SUBJECT,
        &tenant,
        COMMIT,
    )?;
    let mark = audit_mark(context)?;
    let path = transaction_path(context, &tenant, transaction, "/commit");
    let reply = send(context, false, Method::POST, &path, &token, None)?;
    if reply.status != StatusCode::NO_CONTENT {
        let observed = refused(&reply)?;
        // A refused commit rolls back and leaves the batch prepared; an absent or expired batch is
        // gone (crates/secrets-postgres/src/lib.rs `commit`). The code is checked against that
        // record, not replaced by it.
        let held = prepared(context, &tenant, transaction)?;
        let gone = observed.outcome.as_deref() == Some("not-found");
        if reply.status == StatusCode::NOT_FOUND && held == gone {
            return Err(unavailable(
                "observing a refused commit",
                format!(
                    "the service coded {:?} and the batch is {}",
                    observed.outcome,
                    if held { "still prepared" } else { "gone" }
                ),
            ));
        }
        return Ok(observed);
    }
    let events = audit_since(context, mark)?
        .into_iter()
        .filter(|row| row.action == "commit_batch" && row.secret.is_none() && row.tenant == tenant)
        .map(|_| {
            (
                "secrets.custody.TransactionCommitted",
                transaction_payload(&tenant, transaction),
            )
        })
        .collect();
    Ok(Observed {
        response: None,
        outcome: Some("committed".to_owned()),
        error: None,
        events,
    })
}

// POST .../transactions/{transaction}/abort (crates/secrets-http/src/lib.rs `workload_abort`).
fn abort(context: &mut Context<'_>, input: &Value) -> R<Observed> {
    let (tenant, transaction) = transaction_input(input)?;
    let exists = prepared(context, &tenant, transaction)?;
    if context.forced.as_deref() == Some("not-found") {
        if exists {
            return Err(cannot_arrange("a batch is already prepared under this id"));
        }
    } else if !exists {
        arrange_batch(
            context,
            &tenant,
            transaction,
            vec![Mutation::Delete {
                reference: in_tenant(&tenant, "aborted"),
            }],
        )?;
    }
    let token = token(
        context,
        Audience::Workload,
        WORKLOAD_SUBJECT,
        &tenant,
        ABORT,
    )?;
    let path = transaction_path(context, &tenant, transaction, "/abort");
    let reply = send(context, true, Method::POST, &path, &token, None)?;
    if reply.status != StatusCode::NO_CONTENT {
        return refused(&reply);
    }
    if prepared(context, &tenant, transaction)? {
        return Err(unavailable(
            "observing an aborted batch",
            "the service answered 204 and still holds the batch",
        ));
    }
    Ok(Observed {
        response: None,
        outcome: Some("aborted".to_owned()),
        error: None,
        events: vec![(
            "secrets.custody.TransactionAborted",
            transaction_payload(&tenant, transaction),
        )],
    })
}

// `secrets rewrap --actor <actor>` (crates/secrets-app/src/main.rs:68-73), which opens the store with
// the operator's keyring, calls `PostgresStore::rewrap_all` and prints the count it returns.
fn rewrap(context: &mut Context<'_>, input: &Value) -> R<Observed> {
    let actor: String = field(input, "actor")?;
    let forced = context.forced.clone();
    // `rewrapped` and `failed` are about stored state: a version under the service's
    // active key, which the rotated ring no longer makes active and the foreign ring cannot open.
    if matches!(forced.as_deref(), Some("rewrapped" | "failed")) {
        arrange_secret(context, &in_tenant("fixture-rewrap", "rewrap"))?;
    }
    let ring = if forced.as_deref() == Some("failed") {
        FOREIGN_RING
    } else {
        ROTATED_RING
    };
    let url = context.scenario.url.clone();
    let mark = audit_mark(context)?;
    let result = context.runtime.block_on(async {
        let keyring =
            Keyring::from_json(ring).map_err(|error| unavailable("reading a keyring", error))?;
        let store = PostgresStore::connect(&url, Arc::new(keyring))
            .await
            .map_err(|error| unavailable("opening the operator's store", error))?;
        Ok::<_, TargetError>(store.rewrap_all(&actor).await)
    })?;
    let Ok(count) = result else {
        return Ok(Observed {
            response: None,
            outcome: Some("failed".to_owned()),
            error: Some("secrets.custody.Unavailable"),
            events: Vec::new(),
        });
    };
    let rewraps: Vec<Audit> = audit_since(context, mark)?
        .into_iter()
        .filter(|row| row.action == "rewrap")
        .collect();
    if count == 0 {
        // `rewrapped 0 version(s)`: the printed count is the only record (spec NothingRewrapped).
        let events = if rewraps.is_empty() {
            vec![(
                "secrets.custody.NothingRewrapped",
                BTreeMap::from([("actor".to_owned(), text(actor))]),
            )]
        } else {
            Vec::new()
        };
        return Ok(Observed {
            response: None,
            outcome: Some("nothing-to-rewrap".to_owned()),
            error: None,
            events,
        });
    }
    Ok(Observed {
        response: None,
        outcome: Some("rewrapped".to_owned()),
        error: None,
        events: rewraps
            .into_iter()
            .map(|row| {
                (
                    "secrets.custody.SecretsRewrapped",
                    BTreeMap::from([("actor".to_owned(), text(row.actor))]),
                )
            })
            .collect(),
    })
}

// POST /v1/workload/secrets:get (crates/secrets-http/src/lib.rs `workload_get`) as a command. A
// refusal must carry only its reason (`refusal`), so a refused read leaks no byte of the value.
fn read_value(context: &mut Context<'_>, input: &Value) -> R<Observed> {
    let reference: SecretRef = field(input, "reference")?;
    touch(context, &reference);
    if context.forced.as_deref() == Some("not-found") {
        if stored(context, &reference)?.is_some() {
            return Err(cannot_arrange("a secret is stored at the reference"));
        }
    } else {
        arrange_secret(context, &reference)?;
    }
    let token = token(
        context,
        Audience::Workload,
        WORKLOAD_SUBJECT,
        &reference.tenant,
        READ_VALUE,
    )?;
    let body = body(context, &json!(reference))?;
    let reply = send(
        context,
        true,
        Method::POST,
        "/v1/workload/secrets:get",
        &token,
        Some(body),
    )?;
    if reply.status != StatusCode::OK {
        return refused(&reply);
    }
    let stored: StoredSecret = reply.json()?;
    Ok(Observed {
        response: None,
        outcome: Some("read".to_owned()),
        error: None,
        events: vec![(
            "secrets.custody.SecretValueRead",
            BTreeMap::from([(
                "reference".to_owned(),
                reference_node(&stored.metadata.reference),
            )]),
        )],
    })
}

// POST /v1/workload/secrets:exists (crates/secrets-http/src/lib.rs `workload_exists`) as a command.
// A secret is stored first, so a refused check has something it could have disclosed.
fn check_exists(context: &mut Context<'_>, input: &Value) -> R<Observed> {
    let reference: SecretRef = field(input, "reference")?;
    touch(context, &reference);
    arrange_secret(context, &reference)?;
    let token = token(
        context,
        Audience::Workload,
        WORKLOAD_SUBJECT,
        &reference.tenant,
        READ_METADATA,
    )?;
    let body = body(context, &json!(reference))?;
    let reply = send(
        context,
        true,
        Method::POST,
        "/v1/workload/secrets:exists",
        &token,
        Some(body),
    )?;
    if reply.status != StatusCode::OK {
        return refused(&reply);
    }
    reply.json::<Exists>()?;
    Ok(Observed {
        response: None,
        outcome: Some("checked".to_owned()),
        error: None,
        events: vec![(
            "secrets.custody.SecretExistenceChecked",
            BTreeMap::from([("reference".to_owned(), reference_node(&reference))]),
        )],
    })
}

// POST /v1/workload/secrets:list (crates/secrets-http/src/lib.rs `workload_list`) as a command. A
// secret is stored in the namespace first, so a refused listing has something it could disclose.
fn list_namespace(context: &mut Context<'_>, input: &Value) -> R<Observed> {
    let tenant: String = field(input, "tenant")?;
    let namespace: String = field(input, "namespace")?;
    let reference = SecretRef {
        tenant: tenant.clone(),
        namespace: namespace.clone(),
        key: "listed".to_owned(),
    };
    touch(context, &reference);
    arrange_secret(context, &reference)?;
    let token = token(context, Audience::Workload, WORKLOAD_SUBJECT, &tenant, LIST)?;
    let body = body(context, &input.clone())?;
    let reply = send(
        context,
        true,
        Method::POST,
        "/v1/workload/secrets:list",
        &token,
        Some(body),
    )?;
    if reply.status != StatusCode::OK {
        return refused(&reply);
    }
    reply.json::<Listing>()?;
    Ok(Observed {
        response: None,
        outcome: Some("listed".to_owned()),
        error: None,
        events: vec![(
            "secrets.custody.NamespaceSecretsListed",
            BTreeMap::from([
                ("tenant".to_owned(), text(tenant)),
                ("namespace".to_owned(), text(namespace)),
            ]),
        )],
    })
}

// ---- views ----------------------------------------------------------------------------------
//
// No custody view declares a parameter, and the service reads every one over a scope: a tenant
// and namespace, a caller, or a reference. Each view is read through its handler over every scope
// the scenario's commands touched.

fn references(context: &Context<'_>) -> Vec<SecretRef> {
    context
        .scenario
        .references
        .iter()
        .map(|(tenant, namespace, key)| SecretRef {
            tenant: tenant.clone(),
            namespace: namespace.clone(),
            key: key.clone(),
        })
        .collect()
}

fn read(
    context: &mut Context<'_>,
    method: Method,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> R<Reply> {
    let body = body
        .map(|value| serde_json::to_vec(&value).map_err(json_error("encoding a read")))
        .transpose()?;
    call(context, method, path, Some(token), body)
}

fn answered(reply: &Reply, what: &str) -> R<()> {
    if reply.status == StatusCode::OK {
        Ok(())
    } else {
        Err(unavailable(
            "reading a view",
            format!("{what} answered {}", reply.status),
        ))
    }
}

#[derive(serde::Deserialize)]
struct Listing {
    secrets: Vec<SecretMetadata>,
}

// POST /v1/workload/secrets:list per touched (tenant, namespace).
fn namespace_secrets(context: &mut Context<'_>) -> R<Vec<ViewRow>> {
    let scopes: std::collections::BTreeSet<(String, String)> = references(context)
        .into_iter()
        .map(|reference| (reference.tenant, reference.namespace))
        .collect();
    let mut rows = Vec::new();
    for (tenant, namespace) in scopes {
        let token = context
            .scenario
            .token(Audience::Workload, WORKLOAD_SUBJECT, &tenant, &[LIST])
            .map_err(failed("registering a principal"))?;
        let reply = read(
            context,
            Method::POST,
            "/v1/workload/secrets:list",
            &token,
            Some(json!({"tenant": tenant, "namespace": namespace})),
        )?;
        answered(&reply, "secrets:list")?;
        for metadata in reply.json::<Listing>()?.secrets {
            rows.push(metadata_row(&metadata)?);
        }
    }
    Ok(rows)
}

fn callers(context: &Context<'_>) -> Vec<(String, String)> {
    let tenants: std::collections::BTreeSet<String> = context
        .scenario
        .references
        .iter()
        .map(|(tenant, _, _)| tenant.clone())
        .collect();
    tenants
        .iter()
        .flat_map(|tenant| {
            context
                .scenario
                .owners
                .iter()
                .map(move |owner| (tenant.clone(), owner.clone()))
        })
        .collect()
}

// GET /v1/user/secrets per touched tenant and owner.
fn owned_secrets(context: &mut Context<'_>) -> R<Vec<ViewRow>> {
    let mut rows = Vec::new();
    for (tenant, owner) in callers(context) {
        let token = context
            .scenario
            .token(Audience::User, &owner, &tenant, &[LIST])
            .map_err(failed("registering a principal"))?;
        let reply = read(context, Method::GET, "/v1/user/secrets", &token, None)?;
        answered(&reply, "user secrets")?;
        for metadata in reply.json::<Listing>()?.secrets {
            rows.push(metadata_row(&metadata)?);
        }
    }
    Ok(rows)
}

// POST /v1/user/secrets:detail per touched reference and owner; not-found is no row.
fn owned_secret_detail(context: &mut Context<'_>) -> R<Vec<ViewRow>> {
    let mut rows = Vec::new();
    for reference in references(context) {
        let owners: Vec<String> = context.scenario.owners.iter().cloned().collect();
        for owner in owners {
            let token = context
                .scenario
                .token(Audience::User, &owner, &reference.tenant, &[READ_METADATA])
                .map_err(failed("registering a principal"))?;
            let reply = read(
                context,
                Method::POST,
                "/v1/user/secrets:detail",
                &token,
                Some(json!(reference)),
            )?;
            if reply.status == StatusCode::NOT_FOUND {
                continue;
            }
            answered(&reply, "secrets:detail")?;
            rows.push(metadata_row(&reply.json()?)?);
        }
    }
    Ok(rows)
}

// POST /v1/workload/secrets:get per touched reference; not-found is no row.
fn secret_value(context: &mut Context<'_>) -> R<Vec<ViewRow>> {
    let mut rows = Vec::new();
    for reference in references(context) {
        let token = context
            .scenario
            .token(
                Audience::Workload,
                WORKLOAD_SUBJECT,
                &reference.tenant,
                &[READ_VALUE],
            )
            .map_err(failed("registering a principal"))?;
        let reply = read(
            context,
            Method::POST,
            "/v1/workload/secrets:get",
            &token,
            Some(json!(reference)),
        )?;
        if reply.status == StatusCode::NOT_FOUND {
            continue;
        }
        answered(&reply, "secrets:get")?;
        let stored: StoredSecret = reply.json()?;
        rows.push(BTreeMap::from([
            (
                "reference".to_owned(),
                reference_node(&stored.metadata.reference),
            ),
            (
                "version".to_owned(),
                Node::Number(Number::from(stored.metadata.version)),
            ),
            ("value".to_owned(), text(STANDARD.encode(&stored.value.0))),
        ]));
    }
    Ok(rows)
}

#[derive(serde::Deserialize)]
struct Exists {
    exists: bool,
}

// POST /v1/workload/secrets:exists per touched reference.
fn active_secrets(context: &mut Context<'_>) -> R<Vec<ViewRow>> {
    let mut rows = Vec::new();
    for reference in references(context) {
        let token = context
            .scenario
            .token(
                Audience::Workload,
                WORKLOAD_SUBJECT,
                &reference.tenant,
                &[READ_METADATA],
            )
            .map_err(failed("registering a principal"))?;
        let reply = read(
            context,
            Method::POST,
            "/v1/workload/secrets:exists",
            &token,
            Some(json!(reference)),
        )?;
        answered(&reply, "secrets:exists")?;
        if reply.json::<Exists>()?.exists {
            rows.push(BTreeMap::from([(
                "reference".to_owned(),
                reference_node(&reference),
            )]));
        }
    }
    Ok(rows)
}
