---
title: HTTP API
description: Every route of the Secrets API with its action, request body, success response and error codes.
sidebar_position: 5
---

# HTTP API

The machine-readable contract is [OpenAPI 3.1](openapi.json), also served by a running instance at
`/openapi.json`. This page adds what the document leaves implicit: the action each route requires,
the bodies of the routes it does not describe, and the error codes.

## Conventions

- JSON in, JSON out. Request bodies are limited to 1 MiB.
- Values are base64 (standard alphabet) strings in the `value` field.
- A reference is `{"tenant": "...", "namespace": "...", "key": "..."}`. Each part must be
  1 to 255 bytes and contain no NUL byte.
- Every response carries an `x-request-id` header; one is generated when the request has none.
- Authentication and actions are described in [Authentication](authentication.md).

## Errors

Every refusal has the body `{"error": "<reason phrase>", "code": "<code>"}` and nothing else. The
reason phrase is the status's, and the code says which refusal it is, so two refusals with the
same status are told apart by the code. Neither ever contains any part of the request. The codes
are stable; the OpenAPI document lists them in `#/components/schemas/Error`.

| Status | Code | Meaning |
|---|---|---|
| `400` | `malformed-body` | the body is not JSON of the route's request shape |
| `400` | `malformed-path` | the `{transaction}` path segment is not a UUID |
| `400` | `malformed-reference` | a reference part is empty or contains a NUL byte |
| `400` | `invalid-reference` | a reference part is longer than 255 bytes (and none is empty or NUL-bearing) |
| `400` | `empty-batch` | a prepared batch has no mutation |
| `400` | `cross-tenant-batch` | a prepared batch names a tenant other than the caller's |
| `401` | `unauthorized` | no bearer token, or the authority did not accept it |
| `403` | `missing-action` | the principal lacks the route's action |
| `403` | `forbidden` | the principal's tenant differs from the request's |
| `404` | `not-found` | no such secret or transaction, or a revoked secret on a workload read |
| `404` | `not-owned` | on a user route, no secret at the reference is owned by the caller |
| `404` | `delete-target-missing` | a commit's delete mutation names a reference with no secret |
| `404` | `route-not-found` | no route has this path |
| `405` | `method-not-allowed` | the path exists but does not take this method |
| `409` | `duplicate` | a transaction with this ID is already prepared in the tenant |
| `413` | `too-large` | the request body is longer than 1 MiB |
| `503` | `unavailable` | the database, the keyring or an authority is unavailable, or decryption failed |

`missing-action` is checked before `forbidden`, and a body or path that does not parse is refused
before the token is checked. `not-owned` does not say whether a secret exists at the reference: a
secret owned by someone else and no secret at all get the same answer, byte for byte.

## Metadata

Metadata never contains a value:

```json
{
  "id": "0199...",
  "reference": {"tenant": "tenant-a", "namespace": "connectors", "key": "conn-123"},
  "owner_subject": "user-42",
  "disclosure": "workload_only",
  "state": "active",
  "version": 3,
  "labels": {"provider": "example"},
  "created_at": "2026-09-01 10:00:00.000000+00",
  "updated_at": "2026-09-01 10:05:00.000000+00"
}
```

`created_at` and `updated_at` are PostgreSQL `timestamptz` values rendered as text.

## User routes

For people. Metadata, revocation and deletion only; no route returns a value.

| Route | Action | Body | Success |
|---|---|---|---|
| `GET /v1/user/secrets` | `secret:list` | none | `200` `{"secrets": [Metadata]}`, the caller's own secrets in its tenant, including revoked ones |
| `POST /v1/user/secrets:detail` | `secret:read_metadata` | reference | `200` Metadata |
| `POST /v1/user/secrets:revoke` | `secret:revoke` | reference | `200` Metadata with `state: revoked` |
| `DELETE /v1/user/secrets` | `secret:delete` | reference | `204` |

## Workload routes

For service accounts acting inside their granted tenant.

| Route | Action | Body | Success |
|---|---|---|---|
| `PUT /v1/workload/secrets` | `secret:write` | PutSecret | `200` Metadata of the new version |
| `POST /v1/workload/secrets:get` | `secret:read_value` | reference | `200` `{"metadata": Metadata, "value": "<base64>"}` |
| `POST /v1/workload/secrets:exists` | `secret:read_metadata` | reference | `200` `{"exists": bool}`, `true` only for an active secret |
| `POST /v1/workload/secrets:list` | `secret:list` | `{"tenant", "namespace"}` | `200` `{"secrets": [Metadata]}` for that namespace, every owner and state |
| `POST /v1/workload/secrets:delete` | `secret:delete` | `{"reference", "actor"?}` | `204` |

A PutSecret body:

```json
{
  "reference": {"tenant": "tenant-a", "namespace": "connectors", "key": "conn-123"},
  "owner_subject": "user-42",
  "value": "c2VjcmV0LWJ5dGVz",
  "disclosure": "workload_only",
  "labels": {"provider": "example"}
}
```

`disclosure` defaults to `workload_only` and `labels` to `{}`. An empty `owner_subject` is replaced
by the calling workload's subject. Writing an existing reference adds a version and replaces its
owner, disclosure and labels; writing a revoked reference makes it active again. `get` returns the
current version of an active secret and `404` for a revoked one.

## Prepared batches

A workload can stage several puts and deletes in one tenant and apply them atomically.

| Route | Action | Body | Success |
|---|---|---|---|
| `PUT /v1/workload/tenants/{tenant}/transactions/{transaction}` | `secret:prepare` | `{"actor", "mutations"}` | `204` |
| `POST /v1/workload/tenants/{tenant}/transactions/{transaction}/commit` | `secret:commit` | none | `204` |
| `POST /v1/workload/tenants/{tenant}/transactions/{transaction}/abort` | `secret:abort` | none | `204` |

`{transaction}` is a UUID chosen by the caller. Mutations are tagged by `op`:

```json
{
  "actor": "system:serviceaccount:connectors:connectors",
  "mutations": [
    {"op": "put", "secret": {"reference": {"tenant": "tenant-a", "namespace": "connectors", "key": "new"}, "owner_subject": "user-42", "value": "bmV3"}},
    {"op": "delete", "reference": {"tenant": "tenant-a", "namespace": "connectors", "key": "old"}}
  ]
}
```

Prepare refuses an empty batch or a mutation in another tenant (`400`) and a transaction ID
already prepared in the tenant (`409`). Nothing is visible until commit, which applies every
mutation in one PostgreSQL transaction: if any mutation fails, none is applied and the batch stays
prepared. Commit or abort of an unknown ID is `404`. A batch expires 600 seconds after it is
prepared, and committing or aborting it afterwards is `404`.

## Service routes

No authentication.

| Route | Success |
|---|---|
| `GET /health/live` | `204` |
| `GET /health/ready` | `204` when the database answers, else `503` |
| `GET /metrics` | Prometheus text |
| `GET /openapi.json` | this contract |
| `GET /docs` | a short HTML reference page |

## Differences from the OpenAPI document

The OpenAPI document at version 0.4.0 does not declare the request bodies of
`secrets:list`, `secrets:delete` and the prepare route, or the `/metrics`,
`/openapi.json` and `/docs` routes. This page describes what the service does for them.
