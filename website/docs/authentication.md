---
title: Authentication
sidebar_position: 4
description: How workloads and people authenticate, how tenant and actions are established, and the action each route requires.
---

# Authentication

Every API route except the probes, metrics and documentation requires
`Authorization: Bearer <token>`. One authority per route family:

| Routes | Authority | Token |
|---|---|---|
| `/v1/workload/...` | Kubernetes `TokenReview` plus a grant file | a projected service-account token |
| `/v1/user/...` | Identity | a user access token for the configured audience |

Either one yields a principal: a **subject**, one **tenant** and a set of **actions**.

## Workloads

The token's audience must be `--workload-audience`. For each request Secrets:

1. sends a `TokenReview` for that exact audience to the cluster API server;
2. requires `authenticated: true` and the audience in the result;
3. takes the reviewed username, `system:serviceaccount:<namespace>:<name>`, as the subject;
4. looks the subject up in the grant file, and answers `401` without a grant.

```json
[
  {
    "subject": "system:serviceaccount:connectors:connectors",
    "tenant": "tenant-a",
    "actions": ["secret:write", "secret:read_value", "secret:read_metadata", "secret:list", "secret:delete"]
  }
]
```

The grant file is read once at startup. The first matching entry wins, so a subject acts in one
tenant; `*` grants every action. Secrets' own service account needs `create` on `tokenreviews` in
`authentication.k8s.io`.

A refused or failed workload request logs a `stage` and no token or subject:
`reviewer_token_read`, `token_review_request`, `token_review_status`, `token_review_decode`,
`token_review_missing_status`, `token_review_refused`, `token_review_missing_subject`,
`workload_grant_missing`.

## People

Secrets calls `GET <identity-origin>/v1/access-authority` with the caller's bearer token and
`x-b10x-audience: <identity-audience>`, and requires a `2xx` answer whose `aud` equals the
audience and whose `sub` and `tenant_id` are not empty. `sub` is the subject, `tenant_id` the
tenant, and the space-separated `scope` the actions. Identity answering `401` or `403` becomes
`401`; any other failure becomes `503`.

## Actions

| Action | Routes |
|---|---|
| `secret:list` | `GET /v1/user/secrets`, `POST /v1/workload/secrets:list` |
| `secret:read_metadata` | `POST /v1/user/secrets:detail`, `POST /v1/workload/secrets:exists` |
| `secret:revoke` | `POST /v1/user/secrets:revoke` |
| `secret:delete` | `DELETE /v1/user/secrets`, `POST /v1/workload/secrets:delete` |
| `secret:write` | `PUT /v1/workload/secrets` |
| `secret:read_value` | `POST /v1/workload/secrets:get` |
| `secret:prepare` | `PUT .../tenants/{tenant}/transactions/{transaction}` |
| `secret:commit` | `POST .../transactions/{transaction}/commit` |
| `secret:abort` | `POST .../transactions/{transaction}/abort` |

A token the authority rejects is `401` (`unauthorized`). A principal without the route's action is
`403` (`missing-action`), checked before the tenant; a principal of another tenant is `403`
(`forbidden`).
