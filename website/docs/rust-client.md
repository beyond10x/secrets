---
title: Rust client
sidebar_position: 6
description: Call Secrets from a Rust workload with the secrets-client crate.
---

# Rust client

`secrets-client` wraps the workload routes of the [HTTP API](./http-api.md) with the types from
`secrets-core`. It does not cover the user routes.

```toml
[dependencies]
secrets-client = { git = "https://github.com/beyond10x/secrets", tag = "v0.5.0" }
secrets-core = { git = "https://github.com/beyond10x/secrets", tag = "v0.5.0" }
```

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
    client.delete(&reference, "connector-cleanup").await?;
    Ok(())
}
```

`token` is the workload's projected service-account token. The client keeps the token it was built
with; build a new one after the token is refreshed.

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

Every method is `async` and returns `Result<_, secrets_client::Error>`:

| Variant | Cause |
|---|---|
| `NotFound` | `404` |
| `Refused` | any other `4xx` |
| `Service` | a `5xx`, or a body that does not decode |
| `Transport` | an invalid origin or a failed connection |

Errors carry no response body. Paths are joined onto the origin as relative URLs, so an origin with
a path must end in `/`. `StoredSecret.value` zeroes its buffer when dropped. The `actor` passed to
`delete` and `prepare` is recorded in the audit log as given.
