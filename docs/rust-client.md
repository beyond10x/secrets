---
title: Rust client
description: Use the secrets-client crate from a Rust workload to store, read, list, delete and batch secrets.
sidebar_position: 6
---

# Rust client

`secrets-client` is the official Rust client for the workload routes. It is a thin wrapper over the
[HTTP API](http-api.md) and uses the types from `secrets-core`. It does not cover the user routes.

## Add the dependency

The crates live in this repository; depend on a release tag:

```toml
[dependencies]
secrets-client = { git = "https://github.com/beyond10x/secrets", tag = "v0.4.0" }
secrets-core = { git = "https://github.com/beyond10x/secrets", tag = "v0.4.0" }
```

## Use it

```rust
use secrets_client::Client;
use secrets_core::{Disclosure, PutSecret, SecretBytes, SecretRef};
use std::collections::BTreeMap;

async fn example(token: String) -> Result<(), secrets_client::Error> {
    let client = Client::new("http://secrets.platform.svc:8080/", token)?;
    let reference = SecretRef {
        tenant: "tenant-a".into(),
        namespace: "connectors".into(),
        key: "conn-123".into(),
    };
    client
        .put(&PutSecret {
            reference: reference.clone(),
            owner_subject: "user-42".into(),
            value: SecretBytes(b"credential-bytes".to_vec()),
            disclosure: Disclosure::WorkloadOnly,
            labels: BTreeMap::new(),
        })
        .await?;
    let stored = client.get(&reference).await?;
    assert_eq!(stored.metadata.version, 1);
    let _names = client.references("tenant-a", "connectors").await?;
    client.delete(&reference, "connector-cleanup").await?;
    Ok(())
}
```

`token` is the workload's projected service-account token. The client keeps the token it was
created with; build a new client after the projected token is refreshed.

## Methods

| Method | Route |
|---|---|
| `put(&PutSecret) -> SecretMetadata` | `PUT /v1/workload/secrets` |
| `get(&SecretRef) -> StoredSecret` | `POST /v1/workload/secrets:get` |
| `exists(&SecretRef) -> bool` | `POST /v1/workload/secrets:exists` |
| `references(tenant, namespace) -> Vec<SecretMetadata>` | `POST /v1/workload/secrets:list` |
| `delete(&SecretRef, actor)` | `POST /v1/workload/secrets:delete` |
| `prepare(tenant, transaction, actor, &[Mutation])` | `PUT .../transactions/{transaction}` |
| `commit(tenant, transaction)` | `POST .../transactions/{transaction}/commit` |
| `abort(tenant, transaction)` | `POST .../transactions/{transaction}/abort` |

All methods are `async` and return `Result<_, secrets_client::Error>`.

## Errors

| Variant | Cause |
|---|---|
| `NotFound` | `404` |
| `Refused` | any other `4xx`, including `401`, `403`, `400` and `409` |
| `Service` | a `5xx`, or a response body that could not be decoded |
| `Transport` | an invalid origin or a failed connection |

Errors carry no response body, so they never echo a value.

## Notes

- Route paths are joined onto the origin as relative URLs. If the origin has a path, end it with
  `/`, or its last segment is replaced.
- `StoredSecret.value` is a `SecretBytes`, which zeroes its buffer when dropped.
- `delete` and `prepare` send the `actor` you pass, and the service records it in the audit log
  as given; see [Known limitations](limitations.md#audit-actors-can-be-caller-chosen).
