---
slug: /
title: Overview
sidebar_label: Overview
sidebar_position: 1
description: What Secrets is, what it owns, and where it stops.
---

# Secrets

Secrets is an encrypted, tenant-scoped custody service for credentials that belong to people and
to the workloads acting for them. A workload hands Secrets a value; Secrets encrypts it in the
application, stores only ciphertext in PostgreSQL, and gives it back only to a workload that is
authorized for that exact tenant and action. The person who owns the value can see its metadata,
revoke it or delete it. No user route returns a stored value.

```text
workload ──PUT value──▶ Secrets ──ciphertext──▶ PostgreSQL
   │                       │
   └──read value◀──────────┤  only with secret:read_value in that tenant
                           │
person ──list / revoke / delete──▶ metadata only
```

## Why it exists

Services that call external providers for a user end up holding that user's tokens and keys.
Kept in each service's own database, those bytes spread plaintext, key material and ad-hoc access
rules across the platform. Secrets gives them one place with one set of rules: encrypted before
storage, bound to a tenant, granted per action, and recorded in an audit row.

## What it owns

Encrypted value versions, their metadata and owner, disclosure, local revocation, deletion,
workload grants, prepared mutation batches and a value-free audit trail.

## What it does not own

- **Provider logic.** OAuth exchange, refresh and upstream token revocation stay in the
  integrating service.
- **Identity.** Identity verifies people and issues an audience Secrets checks; it knows nothing
  about secrets.
- **Deployment.** This repository publishes source and an OCI image, and no Helm chart. The
  composing product's chart owns PostgreSQL, the keyring Secret, token projection, RBAC and
  network policy.

## Request path

1. The HTTP boundary accepts a JSON body of at most 1 MiB and a bearer token.
2. The route's authority verifies audience, subject, tenant and action before storage is called.
3. The store locks the secret's row and allocates the next version number.
4. The crypto layer seals the value under a fresh data key, with the full reference as associated
   data.
5. One PostgreSQL transaction writes the ciphertext, the wrapped key, the metadata and an audit
   event.

## Where to go next

| You want to | Read |
|---|---|
| build it and migrate a database | [Getting started](./getting-started.md) |
| know what is protected and how | [Security model](./security-model.md) |
| call it from a workload | [HTTP API](./http-api.md), [Rust client](./rust-client.md) |
| run it | [Operations](./operations.md) |
| see what ships and what does not | [Status](./status.mdx) |
| read the specification | [ESS specification](./reference/ess/index.mdx) |
