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

| Status | Meaning |
|---|---|
| `400` | invalid input, for example an invalid reference, an empty batch or a cross-tenant batch |
| `401` | no bearer token, or the authority did not accept it |
| `403` | the principal lacks the action, or its tenant differs from the request's |
| `404` | no such secret or transaction, a revoked secret on a workload read, or a secret the user does not own |
| `409` | a transaction with this ID is already prepared in the tenant |
| `503` | the database, the keyring or an authority is unavailable, or decryption failed |

Error bodies are `{"error": "<reason phrase>"}`. Bodies the JSON extractor rejects get a
plain-text message from the framework instead.

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

The OpenAPI document at version 0.3.0 does not declare the request bodies of
`secrets:list`, `secrets:delete` and the prepare route, any error responses, or the `/metrics`,
`/openapi.json` and `/docs` routes. This page describes what the service does for them.
