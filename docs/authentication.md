---
title: Authentication
description: How workloads and people authenticate, how tenant and actions are established, and the action each route requires.
sidebar_position: 4
---

# Authentication

Every API route except the probes, metrics and documentation requires
`Authorization: Bearer <token>`. Two authorities verify tokens, one per route family:

| Routes | Authority | Token |
|---|---|---|
| `/v1/workload/...` | Kubernetes `TokenReview` plus a local grant file | a projected service-account token |
| `/v1/user/...` | an Identity service | a user access token for the configured audience |

Either authority produces a principal: a **subject**, one **tenant** and a set of **actions**.
The route then requires its action and, where the request names a tenant, that the tenant matches.

## Workloads

A workload presents a projected Kubernetes service-account token whose audience is the value of
`--workload-audience` (`SECRETS_WORKLOAD_AUDIENCE`). For each request, Secrets:

1. Sends a `TokenReview` to the cluster API server, authenticating with its own service-account
   token and trusting the in-cluster CA, and asks for that exact audience.
2. Requires `authenticated: true` and the audience in the review's result.
3. Takes the reviewed username (for a service account,
   `system:serviceaccount:<namespace>:<name>`) as the subject.
4. Looks the subject up in the grant file. No grant means `401`.

The grant file (`--workload-grants-file`) is a JSON array read once at startup:

```json
[
  {
    "subject": "system:serviceaccount:connectors:connectors",
    "tenant": "tenant-a",
    "actions": ["secret:write", "secret:read_value", "secret:read_metadata", "secret:list", "secret:delete"]
  }
]
```

The first entry whose `subject` matches wins, so a subject acts in exactly one tenant. The action
`*` grants every action.

Secrets' own service account needs permission to create `tokenreviews` in the
`authentication.k8s.io` API group. A composition chart provides that, together with the
workload's token projection.

When a workload request is refused or the authority is unavailable, the service logs a warning with
a `stage` field and no token or subject: `reviewer_token_read`, `token_review_request`,
`token_review_status`, `token_review_decode`, `token_review_missing_status`,
`token_review_refused`, `token_review_missing_subject` or `workload_grant_missing`.

## People

A user request carries an access token issued by Identity. For each request Secrets calls
`GET <identity-origin>/v1/access-authority` with the same bearer token and an `x-b10x-audience`
header set to `--identity-audience`. It then requires:

- a `2xx` answer with `sub`, `aud`, `tenant_id` and `scope`;
- `aud` equal to the configured audience, and non-empty `sub` and `tenant_id`.

`sub` becomes the subject, `tenant_id` the tenant, and the whitespace-separated `scope` the
actions. Identity answering `401` or `403` becomes `401`; any other failure becomes `503`.
Identity knows nothing about secrets; the scope strings mean something only inside Secrets.

## Actions

| Action | Routes |
|---|---|
| `secret:list` | `GET /v1/user/secrets`, `POST /v1/workload/secrets:list` |
| `secret:read_metadata` | `POST /v1/user/secrets:detail`, `POST /v1/workload/secrets:exists` |
| `secret:revoke` | `POST /v1/user/secrets:revoke` |
| `secret:delete` | `DELETE /v1/user/secrets`, `POST /v1/workload/secrets:delete` |
| `secret:write` | `PUT /v1/workload/secrets` |
| `secret:read_value` | `POST /v1/workload/secrets:get` |
| `secret:prepare` | `PUT /v1/workload/tenants/{tenant}/transactions/{transaction}` |
| `secret:commit` | `POST .../transactions/{transaction}/commit` |
| `secret:abort` | `POST .../transactions/{transaction}/abort` |

A token the authority does not accept is `401`. A valid principal without the action, or with a
different tenant than the request names, is `403`. User routes then act only on secrets the
principal owns and answer `404` otherwise.
