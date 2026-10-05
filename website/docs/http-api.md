---
title: HTTP API
sidebar_position: 5
description: Every route of the Secrets API with its action, body, success response and refusal codes.
---

# HTTP API

The machine-readable contract is
[`docs/openapi.json`](https://github.com/beyond10x/secrets/blob/main/docs/openapi.json)
(OpenAPI 3.1), also served by a running instance at `/openapi.json`. This page adds the action per
route, the bodies the document leaves out, and the refusal codes.

## Conventions

- JSON in and out; request bodies at most 1 MiB.
- Values are standard base64 strings in `value`.
- A reference is `{"tenant", "namespace", "key"}`; each part is 1 to 255 bytes with no NUL byte.
- Every response carries `x-request-id`, generated when the request has none.
- Actions and authorities: [Authentication](./authentication.md).

## Errors

Every refusal is exactly `{"error": "<reason phrase>", "code": "<code>"}`. The code tells two
refusals with one status apart, and neither field repeats the request.

| Status | Code | Meaning |
|---|---|---|
| `400` | `malformed-body` | the body is not JSON of the route's shape |
| `400` | `malformed-path` | `{transaction}` is not a UUID |
| `400` | `malformed-reference` | a reference part is empty or holds a NUL byte |
| `400` | `invalid-reference` | a reference part is longer than 255 bytes |
| `400` | `empty-batch` | a prepared batch has no mutation |
| `400` | `cross-tenant-batch` | a batch names a tenant other than the caller's |
| `401` | `unauthorized` | no bearer token, or the authority rejected it |
| `403` | `missing-action` | the principal lacks the route's action |
| `403` | `forbidden` | the principal's tenant differs from the request's |
| `404` | `not-found` | no such secret or transaction, or a revoked secret on a workload read |
| `404` | `not-owned` | on a user route, the caller owns no secret at the reference |
| `404` | `delete-target-missing` | a commit's delete names a reference with no secret |
| `404` | `route-not-found` | no route has this path |
| `405` | `method-not-allowed` | the path does not take this method |
| `409` | `duplicate` | this transaction ID is already prepared in the tenant |
| `413` | `too-large` | the body is longer than 1 MiB |
| `503` | `unavailable` | the database, keyring or an authority is unavailable, or decryption failed |

A body or path that does not parse is refused before the token is checked. `not-owned` answers
the same bytes whether someone else owns the secret or none exists.

## Metadata

Metadata never contains a value. `created_at` and `updated_at` are PostgreSQL `timestamptz` text.

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

## User routes

| Route | Action | Body | Success |
|---|---|---|---|
| `GET /v1/user/secrets` | `secret:list` | none | `200` `{"secrets": [Metadata]}`: the caller's own, revoked included |
| `POST /v1/user/secrets:detail` | `secret:read_metadata` | reference | `200` Metadata |
| `POST /v1/user/secrets:revoke` | `secret:revoke` | reference | `200` Metadata, `state: revoked` |
| `DELETE /v1/user/secrets` | `secret:delete` | reference | `204` |

## Workload routes

| Route | Action | Body | Success |
|---|---|---|---|
| `PUT /v1/workload/secrets` | `secret:write` | PutSecret | `200` Metadata of the new version |
| `POST /v1/workload/secrets:get` | `secret:read_value` | reference | `200` `{"metadata", "value"}` |
| `POST /v1/workload/secrets:exists` | `secret:read_metadata` | reference | `200` `{"exists"}`, `true` only when active |
| `POST /v1/workload/secrets:list` | `secret:list` | `{"tenant", "namespace"}` | `200` `{"secrets": [Metadata]}`, every owner and state |
| `POST /v1/workload/secrets:delete` | `secret:delete` | `{"reference", "actor"?}` | `204` |

```json
{
  "reference": {"tenant": "tenant-a", "namespace": "connectors", "key": "conn-123"},
  "owner_subject": "user-42",
  "value": "c2VjcmV0LWJ5dGVz",
  "disclosure": "workload_only",
  "labels": {"provider": "example"}
}
```

`disclosure` defaults to `workload_only` and `labels` to `{}`; an empty `owner_subject` becomes the
calling workload's subject. Writing an existing reference adds a version and replaces owner,
disclosure and labels; writing a revoked one makes it active.

## Prepared batches

A workload stages puts and deletes in its tenant and applies them atomically.

| Route | Action | Body | Success |
|---|---|---|---|
| `PUT /v1/workload/tenants/{tenant}/transactions/{transaction}` | `secret:prepare` | `{"actor", "mutations"}` | `204` |
| `POST .../transactions/{transaction}/commit` | `secret:commit` | none | `204` |
| `POST .../transactions/{transaction}/abort` | `secret:abort` | none | `204` |

```json
{
  "actor": "system:serviceaccount:connectors:connectors",
  "mutations": [
    {"op": "put", "secret": {"reference": {"tenant": "tenant-a", "namespace": "connectors", "key": "new"}, "owner_subject": "user-42", "value": "bmV3"}},
    {"op": "delete", "reference": {"tenant": "tenant-a", "namespace": "connectors", "key": "old"}}
  ]
}
```

`{transaction}` is a caller-chosen UUID. Nothing is visible until commit, which applies every
mutation in one transaction or none of them, leaving the batch prepared. A batch expires 600
seconds after prepare; commit or abort after that, or of an unknown ID, is `404`.

## Service routes

No authentication: `GET /health/live` (`204`), `GET /health/ready` (`204`, or `503` when the
database does not answer), `GET /metrics` (Prometheus text), `GET /openapi.json`, `GET /docs`.

The OpenAPI document at 0.4.1 does not declare the bodies of `secrets:list`, `secrets:delete` and
prepare, or the `/metrics`, `/openapi.json` and `/docs` routes; this page describes them.
